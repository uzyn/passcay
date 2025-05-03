//! WebAuthn Registration (attestation-less)
//!
//! Functions for verifying WebAuthn passkey registration responses
//! with support for ES256 and RS256 keys and flexible security options.

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const passcay = @import("root.zig");
const cbor = @import("zbor");

const types = passcay.types;
const util = passcay.util;

/// Use the common WebAuthnError type from types module
pub const RegistrationError = types.WebAuthnError;

/// Verification expectations for WebAuthn registration
///
/// Controls which security checks are performed during verification.
/// Set fields to null to skip verification for that parameter.
///
/// Example usage:
/// ```
/// // Full security (all checks enabled)
/// const strict_expectations = RegVerifyExpectations{
///     .challenge = challenge_from_session,
///     .origin = "https://example.com",
///     .rp_id = "example.com",
///     .require_user_verification = true,
/// };
/// ```
pub const RegVerifyExpectations = struct {
    /// Expected challenge that was sent to the client
    /// The challenge is a random string generated during the registration ceremony
    challenge: []const u8,

    /// Expected origin (e.g. "https://example.com"), null to skip verification
    /// The origin is the full URL origin of the site where the registration is happening
    origin: ?[]const u8,

    /// Expected RP ID (e.g. "example.com"), null to skip verification
    /// The RP ID is usually the domain name of the website
    rp_id: ?[]const u8,

    /// Whether to require user verification (UV flag)
    /// User verification means the user was authenticated to the authenticator
    require_user_verification: bool,

    /// Whether to require user presence (UP flag)
    /// User presence means the user physically interacted with the authenticator
    require_user_presence: bool = true,
};

/// Registration verification input data
///
/// Contains the raw client data needed to verify a WebAuthn registration response.
///
/// Example usage:
/// ```
/// const input = RegVerifyInput{
///     .attestation_object = attestation_object_from_client,
///     .client_data_json = client_data_json_from_client,
/// };
/// ```
pub const RegVerifyInput = struct {
    /// Base64URL encoded attestation object
    /// This contains the authenticator data, RP ID hash, flags, and credential data
    attestation_object: []const u8,

    /// Base64URL encoded client data JSON
    /// This contains the challenge, type, and origin information from the client
    client_data_json: []const u8,
};

/// Result of a successful registration verification
pub const RegVerifyResult = struct {
    /// Credential ID (base64url encoded) to be stored
    credential_id: []const u8,
    /// Public key (base64url encoded) to be stored
    public_key: []const u8,
    /// Initial signature counter value to be stored
    sign_count: u32,
    /// Authenticator AAGUID (base64url encoded), identifies the authenticator model
    aaguid: []const u8,
    /// Attestation format (e.g., "none", "packed", "fido-u2f")
    fmt: []const u8,
    /// Flags from the authenticator data
    flags: u8,

    /// Free all allocated memory in this result
    pub fn deinit(self: *const RegVerifyResult, allocator: mem.Allocator) void {
        allocator.free(self.credential_id);
        allocator.free(self.public_key);
        allocator.free(self.aaguid);
        allocator.free(self.fmt);
    }
};

const CoseKeyType = types.CoseKeyType;
const CoseCurve = types.CoseCurve;
const CoseAlgorithm = types.CoseAlg;
const CoseKeyLabel = types.CoseKey;

fn sha256(allocator: mem.Allocator, data: []const u8) ![]const u8 {
    var hash: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    passcay.crypto.sha256(data, &hash, .{});
    return try allocator.dupe(u8, &hash);
}

/// Verify a WebAuthn registration response
///
/// Verifies a registration response with customizable security checks.
/// Always requires "webauthn.create" type.
/// Returns credential data to store if verification succeeds.
pub fn verify(allocator: mem.Allocator, input: RegVerifyInput, expectations: RegVerifyExpectations) !RegVerifyResult {
    const client_data = try passcay.util.parseClientDataJson(allocator, input.client_data_json);
    defer client_data.deinit(allocator);

    if (!mem.eql(u8, client_data.type, "webauthn.create")) {
        return error.InvalidClientDataType;
    }

    if (!mem.eql(u8, client_data.challenge, expectations.challenge)) {
        return error.ChallengeMismatch;
    }

    if (expectations.origin) |expected_origin| {
        if (!mem.eql(u8, client_data.origin, expected_origin)) {
            return error.OriginMismatch;
        }
    }

    const attestation = try passcay.cbor.parseAttestationObject(allocator, input.attestation_object);
    defer attestation.deinit(allocator);

    const auth_data = try passcay.cbor.parseAuthenticatorData(allocator, attestation.auth_data);
    defer auth_data.deinit(allocator);

    if (expectations.rp_id) |expected_rp_id| {
        const calculated_rp_id_hash = try sha256(allocator, expected_rp_id);
        defer allocator.free(calculated_rp_id_hash);

        if (!mem.eql(u8, auth_data.rp_id_hash, calculated_rp_id_hash)) {
            return error.InvalidRpIdHash;
        }
    }

    if (expectations.require_user_presence) {
        if ((auth_data.flags & 0x01) == 0) {
            return error.MissingUserPresenceFlag;
        }
    }

    if (expectations.require_user_verification) {
        if ((auth_data.flags & 0x04) == 0) {
            return error.MissingUserVerificationFlag;
        }
    }

    const credential_id = auth_data.credential_id orelse return error.MissingCredentialId;
    const credential_public_key = auth_data.credential_public_key orelse return error.MissingCredentialPublicKey;

    const key_params = try passcay.cbor.parseCoseKey(allocator, credential_public_key);
    defer key_params.deinit(allocator);

    var cose_alg: passcay.crypto.CoseAlg = undefined;

    switch (key_params.key_type) {
        .EC2 => {
            if (key_params.curve != .P256) {
                return error.InvalidCoseKey;
            }
            if (key_params.x == null or key_params.y == null) {
                return error.InvalidCoseKey;
            }
            cose_alg = .ES256;
        },
        .RSA => {
            if (key_params.n == null or key_params.e == null) {
                return error.InvalidCoseKey;
            }
            cose_alg = .RS256;
        },
        else => return error.UnsupportedKeyType,
    }

    const credential_id_base64 = try passcay.util.encodeBase64Url(allocator, credential_id);
    errdefer allocator.free(credential_id_base64);

    const public_key_base64 = try passcay.util.encodeBase64Url(allocator, credential_public_key);
    errdefer allocator.free(public_key_base64);

    const aaguid_base64 = try passcay.util.encodeBase64Url(allocator, auth_data.aaguid orelse return error.MissingAAGUID);
    errdefer allocator.free(aaguid_base64);

    const fmt_copy = try allocator.dupe(u8, attestation.fmt);
    errdefer allocator.free(fmt_copy);

    const result = RegVerifyResult{
        .credential_id = credential_id_base64,
        .public_key = public_key_base64,
        .sign_count = auth_data.sign_count,
        .aaguid = aaguid_base64,
        .fmt = fmt_copy,
        .flags = auth_data.flags,
    };
    return result;
}

test "verify client data type mismatch" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a client data JSON with the wrong type (using "webauthn.get" instead of "webauthn.create")
    const client_data_json = "{\"type\":\"webauthn.get\",\"challenge\":\"test_challenge\",\"origin\":\"https://example.com\"}";
    const attestation_obj = try allocator.alloc(u8, 256);
    defer allocator.free(attestation_obj);
    std.crypto.random.bytes(attestation_obj);

    const attestation_obj_b64 = try passcay.util.encodeBase64Url(allocator, attestation_obj);
    defer allocator.free(attestation_obj_b64);

    const input = RegVerifyInput{
        .attestation_object = attestation_obj_b64,
        .client_data_json = client_data_json,
    };

    const expectations = RegVerifyExpectations{
        .challenge = "test_challenge",
        .origin = "https://example.com",
        .rp_id = "example.com",
        .require_user_verification = true,
    };

    try testing.expectError(error.InvalidClientDataType, verify(allocator, input, expectations));
}

test "verify challenge mismatch" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const client_data_json = "{\"type\":\"webauthn.create\",\"challenge\":\"test_challenge\",\"origin\":\"https://example.com\"}";
    const attestation_obj = try allocator.alloc(u8, 256);
    defer allocator.free(attestation_obj);
    std.crypto.random.bytes(attestation_obj);

    const attestation_obj_b64 = try passcay.util.encodeBase64Url(allocator, attestation_obj);
    defer allocator.free(attestation_obj_b64);

    const input = RegVerifyInput{
        .attestation_object = attestation_obj_b64,
        .client_data_json = client_data_json,
    };

    const expectations = RegVerifyExpectations{
        .challenge = "wrong_challenge", // Different from the one in client data
        .origin = "https://example.com",
        .rp_id = "example.com",
        .require_user_verification = true,
    };

    try testing.expectError(error.ChallengeMismatch, verify(allocator, input, expectations));
}

test "verify origin mismatch" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const client_data_json = "{\"type\":\"webauthn.create\",\"challenge\":\"test_challenge\",\"origin\":\"https://example.com\"}";
    const attestation_obj = try allocator.alloc(u8, 256);
    defer allocator.free(attestation_obj);
    std.crypto.random.bytes(attestation_obj);

    const attestation_obj_b64 = try passcay.util.encodeBase64Url(allocator, attestation_obj);
    defer allocator.free(attestation_obj_b64);

    const input = RegVerifyInput{
        .attestation_object = attestation_obj_b64,
        .client_data_json = client_data_json,
    };

    const expectations = RegVerifyExpectations{
        .challenge = "test_challenge",
        .origin = "https://wrong.com", // Different from the one in client data
        .rp_id = "example.com",
        .require_user_verification = true,
    };

    try testing.expectError(error.OriginMismatch, verify(allocator, input, expectations));
}

test "verify skipping user presence verification" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a valid client data JSON
    const client_data_json = "{\"type\":\"webauthn.create\",\"challenge\":\"test_challenge\",\"origin\":\"https://example.com\"}";

    // Create authenticator data with user verification (UV=1) but NO user presence (UP=0) flags
    var auth_data = [_]u8{0} ** 100; // Make it large enough

    // Add RP ID hash (32 bytes)
    var rp_id_hash: [32]u8 = undefined;
    passcay.crypto.sha256("example.com", &rp_id_hash, .{});
    @memcpy(auth_data[0..32], &rp_id_hash);

    // Set flags: User Verification (0x04) but NO User Presence (0x01)
    auth_data[32] = 0x04;

    // Sign count (4 bytes)
    auth_data[33] = 0;
    auth_data[34] = 0;
    auth_data[35] = 0;
    auth_data[36] = 1;

    // Add attested credential data flag (0x40)
    auth_data[32] |= 0x40;

    // Add a mock AAGUID (16 bytes)
    for (37..53) |i| {
        auth_data[i] = @truncate(i);
    }

    // Add credential ID length (2 bytes) - 16 bytes
    auth_data[53] = 0;
    auth_data[54] = 16;

    // Add credential ID (16 bytes)
    for (55..71) |i| {
        auth_data[i] = @truncate(i);
    }

    // Add a simple COSE key (using minimal valid structure)
    var key_pos: usize = 71;

    // Map with 5 entries
    auth_data[key_pos] = 0xA5;
    key_pos += 1;

    // 1 (kty): 2 (EC2)
    auth_data[key_pos] = 0x01;
    key_pos += 1;
    auth_data[key_pos] = 0x02;
    key_pos += 1;

    // 3 (alg): -7 (ES256)
    auth_data[key_pos] = 0x03;
    key_pos += 1;
    auth_data[key_pos] = 0x26; // -7 as CBOR negative int
    key_pos += 1;

    // -1 (crv): 1 (P-256)
    auth_data[key_pos] = 0x20; // -1 as CBOR negative int
    key_pos += 1;
    auth_data[key_pos] = 0x01;
    key_pos += 1;

    // -2 (x): bytes [1, 2, 3, 4]
    auth_data[key_pos] = 0x21; // -2 as CBOR negative int
    key_pos += 1;
    auth_data[key_pos] = 0x44; // Byte string of length 4
    key_pos += 1;
    auth_data[key_pos] = 1;
    key_pos += 1;
    auth_data[key_pos] = 2;
    key_pos += 1;
    auth_data[key_pos] = 3;
    key_pos += 1;
    auth_data[key_pos] = 4;
    key_pos += 1;

    // -3 (y): bytes [5, 6, 7, 8]
    auth_data[key_pos] = 0x22; // -3 as CBOR negative int
    key_pos += 1;
    auth_data[key_pos] = 0x44; // Byte string of length 4
    key_pos += 1;
    auth_data[key_pos] = 5;
    key_pos += 1;
    auth_data[key_pos] = 6;
    key_pos += 1;
    auth_data[key_pos] = 7;
    key_pos += 1;
    auth_data[key_pos] = 8;
    key_pos += 1;

    // Create attestation object
    var attestation_obj = std.ArrayList(u8).init(allocator);
    defer attestation_obj.deinit();

    // Map with 3 entries
    try attestation_obj.append(0xA3);

    // "fmt": "none"
    try attestation_obj.append(0x63); // Text string of length 3
    try attestation_obj.appendSlice("fmt");
    try attestation_obj.append(0x64); // Text string of length 4
    try attestation_obj.appendSlice("none");

    // "attStmt": {} (empty map)
    try attestation_obj.append(0x67); // Text string of length 7
    try attestation_obj.appendSlice("attStmt");
    try attestation_obj.append(0xA0); // Empty map

    // "authData": the authenticator data we created
    try attestation_obj.append(0x68); // Text string of length 8
    try attestation_obj.appendSlice("authData");

    // Encode authenticator data as byte string
    if (key_pos <= 255) {
        try attestation_obj.append(0x58); // Byte string with 1-byte length
        try attestation_obj.append(@intCast(key_pos)); // Length of auth_data as u8
    } else {
        try attestation_obj.append(0x59); // Byte string with 2-byte length
        try attestation_obj.append(@intCast((key_pos >> 8) & 0xFF)); // High byte
        try attestation_obj.append(@intCast(key_pos & 0xFF)); // Low byte
    }
    try attestation_obj.appendSlice(auth_data[0..key_pos]);

    // Base64 encode the attestation object
    const attestation_obj_b64 = try util.encodeBase64Url(allocator, attestation_obj.items);
    defer allocator.free(attestation_obj_b64);

    // Test 1: require_user_presence = true (default) should fail with MissingUserPresenceFlag
    {
        const input = RegVerifyInput{
            .attestation_object = attestation_obj_b64,
            .client_data_json = client_data_json,
        };

        const expectations = RegVerifyExpectations{
            .challenge = "test_challenge",
            .origin = "https://example.com",
            .rp_id = "example.com",
            .require_user_verification = true,
            // require_user_presence defaults to true
        };

        const result = verify(allocator, input, expectations);
        try testing.expectError(error.MissingUserPresenceFlag, result);
    }

    // Test 2: require_user_presence = false should proceed to later verification steps
    {
        const input = RegVerifyInput{
            .attestation_object = attestation_obj_b64,
            .client_data_json = client_data_json,
        };

        const expectations = RegVerifyExpectations{
            .challenge = "test_challenge",
            .origin = "https://example.com",
            .rp_id = "example.com",
            .require_user_verification = true,
            .require_user_presence = false, // Skip user presence check
        };

        // It might still fail for other reasons (since we're using a simplified test setup)
        // But it should NOT fail with MissingUserPresenceFlag
        const result = verify(allocator, input, expectations);
        if (result) |success| {
            // Clean up if verification unexpectedly succeeds
            success.deinit(allocator);
        } else |err| {
            try testing.expect(err != error.MissingUserPresenceFlag);
        }
    }
}
