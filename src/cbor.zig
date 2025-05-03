//! CBOR parsing utilities for WebAuthn
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const zbor = @import("zbor");

const types = @import("types.zig");
const util = @import("util.zig");

/// Parse a WebAuthn attestation object from base64url-encoded CBOR data
pub fn parseAttestationObject(allocator: Allocator, attestation_object_b64: []const u8) !AttestationObject {
    var arena = std.heap.ArenaAllocator.init(allocator);
    const temp_allocator = arena.allocator();

    const attestation_bytes = try util.decodeBase64Url(temp_allocator, attestation_object_b64);

    const data_item = try zbor.DataItem.new(attestation_bytes);

    if (data_item.getType() != .Map) {
        return error.InvalidAttestationFormat;
    }

    const map = data_item.map().?;

    var fmt: ?[]const u8 = null;
    var auth_data: ?[]const u8 = null;
    var att_stmt: ?zbor.DataItem = null;

    var map_iter = map;
    while (map_iter.next()) |pair| {
        if (pair.key.getType() == .TextString) {
            const key_str = pair.key.string().?;

            if (mem.eql(u8, key_str, "fmt")) {
                if (pair.value.getType() != .TextString) {
                    return error.InvalidAttestationFormat;
                }
                fmt = pair.value.string().?;
            } else if (mem.eql(u8, key_str, "authData")) {
                if (pair.value.getType() != .ByteString) {
                    return error.InvalidAttestationFormat;
                }
                auth_data = pair.value.string().?;
            } else if (mem.eql(u8, key_str, "attStmt")) {
                att_stmt = pair.value;
            }
        }
    }

    if (fmt == null or auth_data == null) {
        arena.deinit();
        std.debug.print("Invalid attestation format. fmt={any}, auth_data={any}, att_stmt={any}\n", .{ fmt != null, auth_data != null, att_stmt != null });
        return error.InvalidAttestationFormat;
    }

    const fmt_copy = try allocator.dupe(u8, fmt.?);
    errdefer allocator.free(fmt_copy);

    const auth_data_copy = try allocator.dupe(u8, auth_data.?);
    errdefer allocator.free(auth_data_copy);

    var raw_att_stmt: []const u8 = undefined;
    if (att_stmt != null) {
        if (att_stmt.?.getType() == .Map) {
            raw_att_stmt = try allocator.dupe(u8, &[_]u8{});
        } else if (att_stmt.?.getType() == .ByteString) {
            raw_att_stmt = try allocator.dupe(u8, att_stmt.?.string().?);
        } else {
            raw_att_stmt = try allocator.dupe(u8, &[_]u8{});
        }
    } else {
        raw_att_stmt = try allocator.dupe(u8, &[_]u8{});
    }
    errdefer allocator.free(raw_att_stmt);

    arena.deinit();

    return AttestationObject{
        .fmt = fmt_copy,
        .auth_data = auth_data_copy,
        .att_stmt = raw_att_stmt,
    };
}

/// Parsed attestation object containing required WebAuthn components
pub const AttestationObject = struct {
    fmt: []const u8,
    auth_data: []const u8,
    att_stmt: []const u8,

    pub fn deinit(self: *const AttestationObject, allocator: Allocator) void {
        allocator.free(self.fmt);
        allocator.free(self.auth_data);
        allocator.free(self.att_stmt);
    }
};

/// Parse authenticator data and extract credential information
pub fn parseAuthenticatorData(allocator: Allocator, auth_data: []const u8) !AuthenticatorDataFull {
    if (auth_data.len < 37) {
        return error.MissingAuthData;
    }

    const rp_id_hash = auth_data[0..32];
    const flags = auth_data[32];
    const sign_count = @as(u32, auth_data[33]) << 24 |
        @as(u32, auth_data[34]) << 16 |
        @as(u32, auth_data[35]) << 8 |
        @as(u32, auth_data[36]);

    const rp_id_hash_copy = try allocator.dupe(u8, rp_id_hash);
    errdefer allocator.free(rp_id_hash_copy);

    var result = AuthenticatorDataFull{
        .rp_id_hash = rp_id_hash_copy,
        .flags = flags,
        .sign_count = sign_count,
        .aaguid = null,
        .credential_id = null,
        .credential_public_key = null,
    };

    // Skipping the first bytes:
    //  - 32 bytes: rpIdHash
    //  - 1 byte: flags
    //  - 4 bytes: signCount
    var pos: usize = 37;

    if ((flags & 0x40) != 0) {
        if (pos + 16 + 2 <= auth_data.len) {
            // Extract AAGUID (16 bytes)
            const aaguid = auth_data[pos .. pos + 16];
            result.aaguid = try allocator.dupe(u8, aaguid);
            errdefer if (result.aaguid != null) allocator.free(result.aaguid.?);
            pos += 16;

            // Get credential ID length
            const id_len = @as(u16, auth_data[pos]) << 8 | @as(u16, auth_data[pos + 1]);
            pos += 2;

            if (pos + id_len <= auth_data.len) {
                // Extract credential ID
                const credential_id = auth_data[pos .. pos + id_len];
                result.credential_id = try allocator.dupe(u8, credential_id);
                errdefer if (result.credential_id != null) allocator.free(result.credential_id.?);
                pos += id_len;

                // The credential public key follows and is a CBOR-encoded structure
                if (pos < auth_data.len) {
                    const credential_public_key = auth_data[pos..auth_data.len];
                    result.credential_public_key = try allocator.dupe(u8, credential_public_key);
                    errdefer if (result.credential_public_key != null) allocator.free(result.credential_public_key.?);
                }
            }
        }
    }

    return result;
}

/// Parse authenticator data from base64url-encoded string
pub fn parseB64AuthenticatorData(allocator: Allocator, auth_data_b64: []const u8) !AuthenticatorDataFull {
    const auth_data_bytes = try util.decodeBase64Url(allocator, auth_data_b64);
    defer allocator.free(auth_data_bytes);

    return parseAuthenticatorData(allocator, auth_data_bytes);
}

/// Comprehensive parsed authenticator data with all possible WebAuthn components
pub const AuthenticatorDataFull = struct {
    rp_id_hash: []const u8,
    flags: u8,
    sign_count: u32,
    aaguid: ?[]const u8,
    credential_id: ?[]const u8,
    credential_public_key: ?[]const u8,

    pub fn deinit(self: *const AuthenticatorDataFull, allocator: Allocator) void {
        allocator.free(self.rp_id_hash);
        if (self.aaguid != null) allocator.free(self.aaguid.?);
        if (self.credential_id != null) allocator.free(self.credential_id.?);
        if (self.credential_public_key != null) allocator.free(self.credential_public_key.?);
    }
};

/// Extract and parse a COSE key from CBOR-encoded data
pub fn parseCoseKey(allocator: Allocator, key_cbor: []const u8) !CoseKeyParameters {
    const data_item = try zbor.DataItem.new(key_cbor);

    if (data_item.getType() != .Map) {
        return error.InvalidCoseKey;
    }

    const map = data_item.map().?;

    var key_type: ?types.CoseKeyType = null;
    var algorithm: ?types.CoseAlg = null;
    var curve: ?types.CoseCurve = null;
    var x: ?[]const u8 = null;
    var y: ?[]const u8 = null;
    var n: ?[]const u8 = null;
    var e: ?[]const u8 = null;

    var map_iter = map;
    while (map_iter.next()) |pair| {
        if (pair.key.getType() == .Int) {
            const key_int = pair.key.int().?;

            switch (key_int) {
                1 => { // kty (key type)
                    if (pair.value.getType() != .Int) continue;
                    const kty_int = pair.value.int().?;
                    key_type = @enumFromInt(@as(i32, @intCast(kty_int)));
                },
                3 => { // alg (algorithm)
                    if (pair.value.getType() != .Int) continue;
                    const alg_int = pair.value.int().?;
                    // We only support ES256 and RS256
                    const alg_val = @as(i32, @intCast(alg_int));
                    if (alg_val == -7 or alg_val == -257) {
                        algorithm = @enumFromInt(alg_val);
                    }
                },
                -1 => { // crv (curve) or n (RSA modulus) depending on key type
                    if (key_type) |kt| {
                        if (kt == .EC2 or kt == .OKP) {
                            if (pair.value.getType() == .Int) {
                                const crv_int = pair.value.int().?;
                                curve = @enumFromInt(@as(i32, @intCast(crv_int)));
                            }
                        } else if (kt == .RSA) {
                            if (pair.value.getType() == .ByteString) {
                                const n_bytes = pair.value.string().?;
                                n = try allocator.dupe(u8, n_bytes);
                            }
                        }
                    }
                },
                -2 => { // x (EC2/OKP) or e (RSA exponent) depending on key type
                    if (key_type) |kt| {
                        if (kt == .EC2 or kt == .OKP) {
                            if (pair.value.getType() == .ByteString) {
                                const x_bytes = pair.value.string().?;
                                x = try allocator.dupe(u8, x_bytes);
                            }
                        } else if (kt == .RSA) {
                            if (pair.value.getType() == .ByteString) {
                                const e_bytes = pair.value.string().?;
                                e = try allocator.dupe(u8, e_bytes);
                            }
                        }
                    }
                },
                -3 => { // y (EC2)
                    if (key_type) |kt| {
                        if (kt == .EC2) {
                            if (pair.value.getType() == .ByteString) {
                                const y_bytes = pair.value.string().?;
                                y = try allocator.dupe(u8, y_bytes);
                            }
                        }
                    }
                },
                else => {}, // Ignore other keys
            }
        }
    }

    // Verify we have the required key type
    if (key_type == null) {
        // Free any allocated memory
        if (x) |x_val| allocator.free(x_val);
        if (y) |y_val| allocator.free(y_val);
        if (n) |n_val| allocator.free(n_val);
        if (e) |e_val| allocator.free(e_val);

        return error.InvalidCoseKey;
    }

    return CoseKeyParameters{
        .key_type = key_type.?,
        .algorithm = algorithm,
        .curve = curve,
        .x = x,
        .y = y,
        .n = n,
        .e = e,
    };
}

/// Extracted parameters from a COSE key
pub const CoseKeyParameters = struct {
    /// Key type (EC2, RSA, OKP)
    key_type: types.CoseKeyType,

    /// Algorithm (-7 for ES256, -257 for RS256)
    algorithm: ?types.CoseAlg,

    /// Curve (for EC2/OKP keys)
    curve: ?types.CoseCurve,

    /// X coordinate (for EC2/OKP keys)
    x: ?[]const u8,

    /// Y coordinate (for EC2 keys)
    y: ?[]const u8,

    /// RSA modulus (for RSA keys)
    n: ?[]const u8,

    /// RSA exponent (for RSA keys)
    e: ?[]const u8,

    /// Free all allocated memory in this struct
    pub fn deinit(self: *const CoseKeyParameters, allocator: Allocator) void {
        if (self.x) |x_val| allocator.free(x_val);
        if (self.y) |y_val| allocator.free(y_val);
        if (self.n) |n_val| allocator.free(n_val);
        if (self.e) |e_val| allocator.free(e_val);
    }
};

/// Extract COSE algorithm from key parameters
pub fn extractCoseAlgorithm(key_params: CoseKeyParameters) !types.CoseAlg {
    if (key_params.algorithm) |alg| {
        return alg;
    }

    switch (key_params.key_type) {
        .EC2 => {
            if (key_params.curve) |curve| {
                if (curve == .P256) {
                    return .ES256;
                }
            }
        },
        .RSA => {
            return .RS256;
        },
        else => {},
    }

    return error.UnsupportedAlgorithm;
}

/// Extract P-256 key coordinates for ES256
pub fn extractP256Coordinates(key_params: CoseKeyParameters) !struct { x: []const u8, y: []const u8 } {
    if (key_params.key_type != .EC2) {
        return error.InvalidKeyType;
    }

    if (key_params.curve) |curve| {
        if (curve != .P256) {
            return error.UnsupportedCurve;
        }
    } else {
        return error.MissingCurve;
    }

    const x = key_params.x orelse return error.MissingCoordinate;
    const y = key_params.y orelse return error.MissingCoordinate;

    return .{ .x = x, .y = y };
}

/// Extract RSA key parameters for RS256
pub fn extractRSAParameters(key_params: CoseKeyParameters) !struct { n: []const u8, e: []const u8 } {
    if (key_params.key_type != .RSA) {
        return error.InvalidKeyType;
    }

    const n = key_params.n orelse return error.MissingParameter;
    const e = key_params.e orelse return error.MissingParameter;

    return .{ .n = n, .e = e };
}

/// CBOR-encode a map with fmt, attStmt, and authData fields in canonical order
pub fn encodeAttestationObject(
    allocator: Allocator,
    fmt: []const u8,
    auth_data: []const u8,
    att_stmt: []const u8,
) ![]const u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try buffer.append(0xA3); // Map, 3 pairs

    try buffer.append(0x63); // Text string, length 3
    try buffer.appendSlice("fmt");
    try buffer.append(0x60 + @as(u8, @intCast(fmt.len))); // Text string with inline length
    try buffer.appendSlice(fmt);

    try buffer.append(0x67); // Text string, length 7
    try buffer.appendSlice("attStmt");

    if (att_stmt.len > 0) {
        try buffer.appendSlice(att_stmt);
    } else {
        try buffer.append(0xA0); // Empty map
    }

    try buffer.append(0x68); // Text string, length 8
    try buffer.appendSlice("authData");

    if (auth_data.len <= 23) {
        try buffer.append(0x40 + @as(u8, @intCast(auth_data.len)));
    } else if (auth_data.len <= 255) {
        try buffer.append(0x58); // Bytestring with 1-byte length
        try buffer.append(@as(u8, @intCast(auth_data.len)));
    } else if (auth_data.len <= 65535) {
        try buffer.append(0x59); // Bytestring with 2-byte length
        try buffer.append(@as(u8, @intCast(auth_data.len >> 8)));
        try buffer.append(@as(u8, @intCast(auth_data.len & 0xFF)));
    } else {
        try buffer.append(0x5A); // Bytestring with 4-byte length
        try buffer.append(@as(u8, @intCast(auth_data.len >> 24)));
        try buffer.append(@as(u8, @intCast((auth_data.len >> 16) & 0xFF)));
        try buffer.append(@as(u8, @intCast((auth_data.len >> 8) & 0xFF)));
        try buffer.append(@as(u8, @intCast(auth_data.len & 0xFF)));
    }
    try buffer.appendSlice(auth_data);

    return buffer.toOwnedSlice();
}

/// Parse authenticator data for authentication (simplified version)
pub fn parseAuthData(_: Allocator, auth_data: []const u8) !AuthData {
    if (auth_data.len < 37) {
        return error.Short;
    }

    var result = AuthData{
        .rp_id_hash = undefined,
        .flags = auth_data[32],
        .sign_count = @as(u32, auth_data[33]) << 24 |
            @as(u32, auth_data[34]) << 16 |
            @as(u32, auth_data[35]) << 8 |
            @as(u32, auth_data[36]),
    };

    @memcpy(&result.rp_id_hash, auth_data[0..32]);

    return result;
}

/// Simplified authenticator data structure
pub const AuthData = struct {
    rp_id_hash: [32]u8,
    flags: u8,
    sign_count: u32,
    pub fn deinit(_: *const AuthData, _: Allocator) void {
        // Nothing to deallocate
    }
};

test "parseAttestationObject basic functionality" {
    const testing = std.testing;
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    try buffer.append(0xA3);

    // "fmt": "none"
    try buffer.append(0x63); // Text string of length 3
    try buffer.appendSlice("fmt");
    try buffer.append(0x64); // Text string of length 4
    try buffer.appendSlice("none");

    // "attStmt": {} (empty map)
    try buffer.append(0x67); // Text string of length 7
    try buffer.appendSlice("attStmt");
    try buffer.append(0xA0); // Empty map

    // "authData": byte string with 37 bytes of zeros
    try buffer.append(0x68); // Text string of length 8
    try buffer.appendSlice("authData");
    try buffer.append(0x58); // Byte string with 1-byte length
    try buffer.append(37); // Length 37
    try buffer.appendSlice(&[_]u8{0} ** 37);

    const b64_encoded = try util.encodeBase64Url(testing.allocator, buffer.items);
    defer testing.allocator.free(b64_encoded);

    const result = try parseAttestationObject(testing.allocator, b64_encoded);
    defer result.deinit(testing.allocator);

    try testing.expectEqualStrings("none", result.fmt);
    try testing.expectEqual(@as(usize, 37), result.auth_data.len);
}

test "parseCoseKey with EC2/P-256 key" {
    const testing = std.testing;

    // Create a COSE key for EC2/P-256
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    // Map with 5 entries
    try buffer.append(0xA5);

    // 1 (kty): 2 (EC2)
    try buffer.append(0x01);
    try buffer.append(0x02);

    // 3 (alg): -7 (ES256)
    try buffer.append(0x03);
    try buffer.append(0x26); // -7 as CBOR negative int

    // -1 (crv): 1 (P-256)
    try buffer.append(0x20); // -1 as CBOR negative int
    try buffer.append(0x01);

    // -2 (x): bytes [1, 2, 3, 4]
    try buffer.append(0x21); // -2 as CBOR negative int
    try buffer.append(0x44); // Byte string of length 4
    try buffer.appendSlice(&[_]u8{ 1, 2, 3, 4 });

    // -3 (y): bytes [5, 6, 7, 8]
    try buffer.append(0x22); // -3 as CBOR negative int
    try buffer.append(0x44); // Byte string of length 4
    try buffer.appendSlice(&[_]u8{ 5, 6, 7, 8 });

    // Parse the key
    const key_params = try parseCoseKey(testing.allocator, buffer.items);
    defer key_params.deinit(testing.allocator);

    // Verify the parsed result
    try testing.expectEqual(types.CoseKeyType.EC2, key_params.key_type);
    try testing.expectEqual(types.CoseAlg.ES256, key_params.algorithm.?);
    try testing.expectEqual(types.CoseCurve.P256, key_params.curve.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, key_params.x.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 5, 6, 7, 8 }, key_params.y.?);
}

test "parseAuthData basic functionality" {
    const testing = std.testing;

    var auth_data = [_]u8{0} ** 37;
    std.crypto.random.bytes(auth_data[0..32]); // RP ID hash
    auth_data[32] = 0x01;

    auth_data[33] = 0;
    auth_data[34] = 0;
    auth_data[35] = 0;
    auth_data[36] = 42;

    const result = try parseAuthData(testing.allocator, &auth_data);
    defer result.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, auth_data[0..32], &result.rp_id_hash);
    try testing.expectEqual(@as(u8, 0x01), result.flags);
    try testing.expectEqual(@as(u32, 42), result.sign_count);
}

test "extractCoseAlgorithm ES256" {
    const testing = std.testing;

    const key_params = CoseKeyParameters{
        .key_type = .EC2,
        .algorithm = .ES256,
        .curve = .P256,
        .x = null,
        .y = null,
        .n = null,
        .e = null,
    };

    const alg = try extractCoseAlgorithm(key_params);
    try testing.expectEqual(types.CoseAlg.ES256, alg);
}

test "extractCoseAlgorithm RS256" {
    const testing = std.testing;

    const key_params = CoseKeyParameters{
        .key_type = .RSA,
        .algorithm = .RS256,
        .curve = null,
        .x = null,
        .y = null,
        .n = null,
        .e = null,
    };

    const alg = try extractCoseAlgorithm(key_params);
    try testing.expectEqual(types.CoseAlg.RS256, alg);
}

test "encodeAttestationObject basic functionality" {
    const testing = std.testing;

    const fmt = "none";
    const auth_data = [_]u8{0} ** 37;
    const att_stmt = [_]u8{0xA0}; // Empty map

    const encoded = try encodeAttestationObject(testing.allocator, fmt, &auth_data, &att_stmt);
    defer testing.allocator.free(encoded);

    const encoded_b64 = try util.encodeBase64Url(testing.allocator, encoded);
    defer testing.allocator.free(encoded_b64);

    const decoded = try parseAttestationObject(testing.allocator, encoded_b64);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqualStrings(fmt, decoded.fmt);
    try testing.expectEqualSlices(u8, &auth_data, decoded.auth_data);
}

test "parseAuthenticatorData with user verified flag" {
    const testing = std.testing;

    var auth_data = [_]u8{0} ** 37; // Minimum length
    std.crypto.random.bytes(auth_data[0..32]);

    auth_data[32] = 0x05; // 0x01 | 0x04

    // Sign count = 42
    auth_data[33] = 0;
    auth_data[34] = 0;
    auth_data[35] = 0;
    auth_data[36] = 42;

    const result = try parseAuthenticatorData(testing.allocator, &auth_data);
    defer result.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, auth_data[0..32], result.rp_id_hash);
    try testing.expectEqual(@as(u8, 0x05), result.flags);
    try testing.expectEqual(@as(u32, 42), result.sign_count);
}

test "parseCoseKey with real ES256 data" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const es256_key_base64 = "pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE";

    const key_bytes = try util.decodeBase64Url(allocator, es256_key_base64);
    defer allocator.free(key_bytes);

    const key_params = try parseCoseKey(allocator, key_bytes);
    defer key_params.deinit(allocator);

    try testing.expectEqual(types.CoseKeyType.EC2, key_params.key_type);
    try testing.expectEqual(types.CoseAlg.ES256, key_params.algorithm.?);
    try testing.expect(key_params.x != null);
    try testing.expect(key_params.y != null);
    try testing.expect(key_params.n == null);
    try testing.expect(key_params.e == null);
}

test "parseCoseKey with real RS256 data" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const rs256_key_base64 = "pAEDAzkBACBZAQDPaaESfnFzHsCujgVbzjpgDuvZBvuV3gIlOMrNRSmVb-zZYNFRN3Rse14jz5QpAXU4qSvkccj1q_tEzvEUCVxXcUNU55PmL3GvmjO8RO0OUM1ALpCTqFWcvR74PqXyTsUzvWMjBrSv2egr-d8PhWFX4zeQZi1B2O0jKAEGCxqIwxH7ZA3cwS4PiwXIiOVDNasGIzJA6DH6NDe45TslNSFqvoHQSUdBEe2gMXGkTeI3Vq6ttB1hrt9jeEUB-wpnz6aMd1ildOmZsZQ4UdeAeVErY2F0gH4IIv8h_ov_W9vRE7Jk5ylqvP9_U2_taVq6z2-5ofCtP3psI3N8yaEDfUL_IUMBAAE";

    const key_bytes = try util.decodeBase64Url(allocator, rs256_key_base64);
    defer allocator.free(key_bytes);

    const key_params = try parseCoseKey(allocator, key_bytes);
    defer key_params.deinit(allocator);

    try testing.expectEqual(types.CoseKeyType.RSA, key_params.key_type);
    try testing.expectEqual(types.CoseAlg.RS256, key_params.algorithm.?);
    try testing.expect(key_params.x == null);
    try testing.expect(key_params.y == null);
    try testing.expect(key_params.n != null);
    try testing.expect(key_params.e != null);
}
