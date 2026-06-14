//! Autonomous FIDO2 conformance harness (library layer).
//!
//! Replays positive and negative attestation/assertion vectors through the
//! public verification API. Negative cases assert the *specific* error — the
//! discipline that distinguishes real conformance from "fails for some reason".
//! Vectors are either real (test_data.zig) or deterministically generated
//! (test_gen.zig) so the suite runs fully offline via `zig build test`.

const std = @import("std");
const testing = std.testing;
const zbor = @import("zbor");
const passcay = @import("root.zig");
const gen = @import("test_gen.zig");
const td = @import("test_data.zig");

const origin = td.origin;
const rp_id = td.rp_id;

fn regOk(a: std.mem.Allocator, exp: passcay.register.RegVerifyExpectations, att: []const u8, cdj: []const u8) !passcay.register.RegVerifyResult {
    return passcay.register.verify(a, .{ .attestation_object = att, .client_data_json = cdj }, exp);
}

/// Extract the first x5c certificate (DER) from an attestation object.
fn firstX5c(a: std.mem.Allocator, attobj_b64: []const u8) ![]u8 {
    const bytes = try passcay.util.decodeBase64Url(a, attobj_b64);
    defer a.free(bytes);
    const di = try zbor.DataItem.new(bytes);
    var map = di.map() orelse return error.NotAMap;
    var att_stmt: ?zbor.DataItem = null;
    while (map.next()) |p| {
        if (p.key.getType() == .TextString and std.mem.eql(u8, p.key.string().?, "attStmt")) att_stmt = p.value;
    }
    var as_map = (att_stmt orelse return error.NoAttStmt).map() orelse return error.NotAMap;
    var x5c: ?zbor.DataItem = null;
    while (as_map.next()) |p| {
        if (p.key.getType() == .TextString and std.mem.eql(u8, p.key.string().?, "x5c")) x5c = p.value;
    }
    var arr = (x5c orelse return error.NoX5c).array() orelse return error.NotAnArray;
    const first = arr.next() orelse return error.EmptyX5c;
    return a.dupe(u8, first.string() orelse return error.NotAByteString);
}

// ===================== Positive: none / ES256 =====================

test "conformance/none: ES256 registration verifies with attestation policy" {
    const a = testing.allocator;
    const result = try regOk(a, .{
        .challenge = td.es256_reg_challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = true,
        .attestation = .{}, // default policy: verify the (empty) statement
    }, td.es256_none_attobj, td.es256_none_cdj);
    defer result.deinit(a);

    try testing.expectEqualStrings("none", result.fmt);
    try testing.expectEqual(passcay.attestation.AttestationType.none, result.attestation_type);
    try testing.expectEqualStrings("y0wYdkdk9SkLcNEA-4HEsAVtIz8", result.credential_id);
}

test "conformance/es256: assertion verifies" {
    const a = testing.allocator;
    const res = try passcay.auth.verify(a, .{
        .authenticator_data = td.es256_auth_authdata,
        .client_data_json = td.es256_auth_cdj,
        .signature = td.es256_auth_sig,
    }, .{
        .public_key = td.es256_pubkey,
        .challenge = td.es256_auth_challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = false,
        .require_user_presence = true,
        .enable_sign_count_check = false,
    });
    defer res.deinit(a);
    try testing.expectEqual(@as(u32, 0), res.sign_count);
}

// ===================== Positive: packed self (generated) =====================

test "conformance/packed-self: ES256 registration verifies" {
    const a = testing.allocator;
    const v = try gen.buildEs256(a, .{ .fmt = "packed", .empty_att_stmt = false });
    defer v.deinit(a);

    const result = try regOk(a, .{
        .challenge = v.challenge,
        .origin = v.origin,
        .rp_id = v.rp_id,
        .require_user_verification = true,
        .attestation = .{},
    }, v.attestation_object_b64, v.client_data_json_b64);
    defer result.deinit(a);

    try testing.expectEqualStrings("packed", result.fmt);
    try testing.expectEqual(passcay.attestation.AttestationType.self, result.attestation_type);
    try testing.expectEqualStrings(v.credential_id_b64, result.credential_id);
}

// ===================== Positive + negative: RS256 round-trip =====================

test "conformance/rs256: packed-full registration then assertion round-trip" {
    const a = testing.allocator;
    // Full packed attestation (x5c) chain validation arrives in a later phase,
    // so registration here runs without an attestation policy.
    const reg = try regOk(a, .{
        .challenge = td.rs256_reg_challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = true,
    }, td.rs256_reg_attobj, td.rs256_reg_cdj);
    defer reg.deinit(a);
    try testing.expectEqualStrings("packed", reg.fmt);

    // Positive assertion with the just-registered RS256 key.
    const auth_res = try passcay.auth.verify(a, .{
        .authenticator_data = td.rs256_auth_authdata,
        .client_data_json = td.rs256_auth_cdj,
        .signature = td.rs256_auth_sig,
    }, .{
        .public_key = reg.public_key,
        .challenge = td.rs256_auth_challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = false,
        .require_user_presence = false,
        .enable_sign_count_check = false,
    });
    defer auth_res.deinit(a);

    // Negative: a tampered signature must fail with SignatureVerificationFailed.
    const sig_src = try passcay.util.decodeBase64Url(a, td.rs256_auth_sig);
    defer a.free(sig_src);
    const sig_bytes = try a.dupe(u8, sig_src);
    defer a.free(sig_bytes);
    sig_bytes[40] ^= 0xFF;
    const bad_sig = try passcay.util.encodeBase64Url(a, sig_bytes);
    defer a.free(bad_sig);

    try testing.expectError(error.SignatureVerificationFailed, passcay.auth.verify(a, .{
        .authenticator_data = td.rs256_auth_authdata,
        .client_data_json = td.rs256_auth_cdj,
        .signature = bad_sig,
    }, .{
        .public_key = reg.public_key,
        .challenge = td.rs256_auth_challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = false,
        .require_user_presence = false,
        .enable_sign_count_check = false,
    }));
}

// ===================== Positive: packed full (real batch cert) =====================

test "conformance/packed-full: RS256 credential with ES256 batch cert verifies as basic" {
    const a = testing.allocator;
    // The attestation statement is signed by the (self-signed conformance) batch
    // certificate using ES256, independent of the RS256 credential key. now_sec
    // null skips cert time validity; empty roots accept the self-signed top.
    const reg = try regOk(a, .{
        .challenge = td.rs256_reg_challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = true,
        .attestation = .{ .now_sec = null, .roots = &.{} },
    }, td.rs256_reg_attobj, td.rs256_reg_cdj);
    defer reg.deinit(a);

    try testing.expectEqualStrings("packed", reg.fmt);
    try testing.expectEqual(passcay.attestation.AttestationType.basic, reg.attestation_type);
}

test "conformance/packed-full: tampered attestation signature -> AttestationSignatureInvalid" {
    const a = testing.allocator;
    // Flip a byte inside the attestation object (in the leaf cert / sig region)
    // and require attestation verification: it must fail with a signature error
    // or a cert-parse error, never silently succeed.
    const obj = try passcay.util.decodeBase64Url(a, td.rs256_reg_attobj);
    defer a.free(obj);
    const tampered = try a.dupe(u8, obj);
    defer a.free(tampered);
    tampered[80] ^= 0x01; // perturb within the attestation statement region
    const tampered_b64 = try passcay.util.encodeBase64Url(a, tampered);
    defer a.free(tampered_b64);

    const res = regOk(a, .{
        .challenge = td.rs256_reg_challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = true,
        .attestation = .{ .now_sec = null },
    }, tampered_b64, td.rs256_reg_cdj);
    try testing.expect(std.meta.isError(res));
}

// ===================== Positive: fido-u2f (real Yubico vector) =====================

test "conformance/fido-u2f: Yubico attestation verifies as basic" {
    const a = testing.allocator;
    const result = try regOk(a, .{
        .challenge = td.u2f_reg_challenge,
        .origin = td.u2f_origin,
        .rp_id = td.u2f_rp_id,
        .require_user_verification = false, // U2F authenticators do not do UV
        .require_user_presence = true,
        .attestation = .{ .now_sec = null }, // expired vendor cert: skip time validity
    }, td.u2f_reg_attobj, td.u2f_reg_cdj);
    defer result.deinit(a);

    try testing.expectEqualStrings("fido-u2f", result.fmt);
    try testing.expectEqual(passcay.attestation.AttestationType.basic, result.attestation_type);
    try testing.expectEqualStrings(td.u2f_cred_id, result.credential_id);
}

// ===================== Positive: tpm (real Surface/webauthn.io vectors) =====================

test "conformance/tpm: RSA credential key verifies as attca" {
    const a = testing.allocator;
    const result = try regOk(a, .{
        .challenge = td.tpm_rsa_challenge,
        .origin = td.tpm_rsa_origin,
        .rp_id = td.tpm_rsa_rp_id,
        .require_user_verification = true,
        // Expired AIK cert: pin the clock inside its validity window; empty roots
        // accept the chain's internal links without enforcing the MS TPM root.
        .attestation = .{ .now_sec = td.tpm_now_sec, .roots = &.{} },
    }, td.tpm_rsa_attobj, td.tpm_rsa_cdj);
    defer result.deinit(a);

    try testing.expectEqualStrings("tpm", result.fmt);
    try testing.expectEqual(passcay.attestation.AttestationType.attca, result.attestation_type);
    try testing.expectEqualStrings(td.tpm_rsa_cred_id, result.credential_id);
}

test "conformance/tpm: ECC P-256 credential key verifies as attca" {
    const a = testing.allocator;
    const result = try regOk(a, .{
        .challenge = td.tpm_ecc_challenge,
        .origin = td.tpm_ecc_origin,
        .rp_id = td.tpm_ecc_rp_id,
        .require_user_verification = true,
        .attestation = .{ .now_sec = td.tpm_now_sec, .roots = &.{} },
    }, td.tpm_ecc_attobj, td.tpm_ecc_cdj);
    defer result.deinit(a);

    try testing.expectEqualStrings("tpm", result.fmt);
    try testing.expectEqual(passcay.attestation.AttestationType.attca, result.attestation_type);
    try testing.expectEqualStrings(td.tpm_ecc_cred_id, result.credential_id);
}

test "conformance/tpm: tampered attestation signature is rejected" {
    const a = testing.allocator;
    // Flip a byte inside the attestation statement region (the leading sig blob)
    // and require attestation: verification must fail, never silently succeed.
    const obj = try passcay.util.decodeBase64Url(a, td.tpm_rsa_attobj);
    defer a.free(obj);
    const tampered = try a.dupe(u8, obj);
    defer a.free(tampered);
    tampered[40] ^= 0x01;
    const tampered_b64 = try passcay.util.encodeBase64Url(a, tampered);
    defer a.free(tampered_b64);

    try testing.expect(std.meta.isError(regOk(a, .{
        .challenge = td.tpm_rsa_challenge,
        .origin = td.tpm_rsa_origin,
        .rp_id = td.tpm_rsa_rp_id,
        .require_user_verification = true,
        .attestation = .{ .now_sec = td.tpm_now_sec, .roots = &.{} },
    }, tampered_b64, td.tpm_rsa_cdj)));
}

// ===================== MDS-anchored full attestation =====================

test "conformance/mds: AAGUID-anchored packed-full verification with status gating" {
    const a = testing.allocator;
    const cert_der = try firstX5c(a, td.rs256_reg_attobj);
    defer a.free(cert_der);

    const aaguid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    const roots = [_][]const u8{cert_der};

    const exp = struct {
        fn make(store: *const passcay.mds.Store) passcay.register.RegVerifyExpectations {
            return .{
                .challenge = td.rs256_reg_challenge,
                .origin = origin,
                .rp_id = rp_id,
                .require_user_verification = true,
                .attestation = .{ .now_sec = null, .mds = store },
            };
        }
    };

    // Positive: certified entry whose root anchors the batch certificate.
    {
        const entry = passcay.mds.Entry{ .aaguid = aaguid, .roots = &roots, .statuses = &.{.fido_certified} };
        const store = passcay.mds.Store{ .entries = &.{entry} };
        const reg = try regOk(a, exp.make(&store), td.rs256_reg_attobj, td.rs256_reg_cdj);
        defer reg.deinit(a);
        try testing.expectEqual(passcay.attestation.AttestationType.basic, reg.attestation_type);
    }

    // Negative: revoked status.
    {
        const entry = passcay.mds.Entry{ .aaguid = aaguid, .roots = &roots, .statuses = &.{.revoked} };
        const store = passcay.mds.Store{ .entries = &.{entry} };
        try testing.expectError(error.AttestationAuthenticatorCompromised, regOk(a, exp.make(&store), td.rs256_reg_attobj, td.rs256_reg_cdj));
    }

    // Negative: AAGUID absent from the metadata store.
    {
        const other = passcay.mds.Entry{ .aaguid = @splat(0xFF), .roots = &roots, .statuses = &.{.fido_certified} };
        const store = passcay.mds.Store{ .entries = &.{other} };
        try testing.expectError(error.AttestationAaguidUnknown, regOk(a, exp.make(&store), td.rs256_reg_attobj, td.rs256_reg_cdj));
    }
}

test "conformance/mds: full attestation rejected when model declares surrogate-only" {
    const a = testing.allocator;
    const cert_der = try firstX5c(a, td.rs256_reg_attobj);
    defer a.free(cert_der);

    const aaguid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    const roots = [_][]const u8{cert_der};

    // Metadata says this model only does surrogate (self) attestation, but the
    // response carries a full ("basic") packed attestation — must be rejected.
    {
        const entry = passcay.mds.Entry{ .aaguid = aaguid, .roots = &roots, .statuses = &.{.fido_certified}, .attestation_types = &.{.basic_surrogate} };
        const store = passcay.mds.Store{ .entries = &.{entry} };
        try testing.expectError(error.AttestationTypeNotAllowed, regOk(a, .{
            .challenge = td.rs256_reg_challenge,
            .origin = origin,
            .rp_id = rp_id,
            .require_user_verification = true,
            .attestation = .{ .now_sec = null, .mds = &store },
        }, td.rs256_reg_attobj, td.rs256_reg_cdj));
    }

    // The same full attestation is accepted when the model declares basic_full.
    {
        const entry = passcay.mds.Entry{ .aaguid = aaguid, .roots = &roots, .statuses = &.{.fido_certified}, .attestation_types = &.{ .basic_full, .basic_surrogate } };
        const store = passcay.mds.Store{ .entries = &.{entry} };
        const reg = try regOk(a, .{
            .challenge = td.rs256_reg_challenge,
            .origin = origin,
            .rp_id = rp_id,
            .require_user_verification = true,
            .attestation = .{ .now_sec = null, .mds = &store },
        }, td.rs256_reg_attobj, td.rs256_reg_cdj);
        defer reg.deinit(a);
        try testing.expectEqual(passcay.attestation.AttestationType.basic, reg.attestation_type);
    }

    // A packed x5c attestation is "Basic OR AttCA" (§6.5.3); a model declaring
    // only attca must still accept it (the on-wire format is indistinguishable).
    {
        const entry = passcay.mds.Entry{ .aaguid = aaguid, .roots = &roots, .statuses = &.{.fido_certified}, .attestation_types = &.{.attca} };
        const store = passcay.mds.Store{ .entries = &.{entry} };
        const reg = try regOk(a, .{
            .challenge = td.rs256_reg_challenge,
            .origin = origin,
            .rp_id = rp_id,
            .require_user_verification = true,
            .attestation = .{ .now_sec = null, .mds = &store },
        }, td.rs256_reg_attobj, td.rs256_reg_cdj);
        defer reg.deinit(a);
        try testing.expectEqual(passcay.attestation.AttestationType.basic, reg.attestation_type);
    }
}

// ===================== Negative: specific-error assertions =====================

test "conformance/neg: challenge mismatch -> ChallengeMismatch" {
    const a = testing.allocator;
    try testing.expectError(error.ChallengeMismatch, regOk(a, .{
        .challenge = "wrong-challenge",
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = true,
    }, td.es256_none_attobj, td.es256_none_cdj));
}

test "conformance/neg: origin mismatch -> OriginMismatch" {
    const a = testing.allocator;
    try testing.expectError(error.OriginMismatch, regOk(a, .{
        .challenge = td.es256_reg_challenge,
        .origin = "https://evil.example",
        .rp_id = rp_id,
        .require_user_verification = true,
    }, td.es256_none_attobj, td.es256_none_cdj));
}

test "conformance/neg: rp id mismatch -> InvalidRpIdHash" {
    const a = testing.allocator;
    try testing.expectError(error.InvalidRpIdHash, regOk(a, .{
        .challenge = td.es256_reg_challenge,
        .origin = origin,
        .rp_id = "evil.example",
        .require_user_verification = true,
    }, td.es256_none_attobj, td.es256_none_cdj));
}

test "conformance/neg: ES256 tampered assertion signature -> SignatureVerificationFailed" {
    const a = testing.allocator;
    const sig_src = try passcay.util.decodeBase64Url(a, td.es256_auth_sig);
    defer a.free(sig_src);
    const sig_bytes = try a.dupe(u8, sig_src);
    defer a.free(sig_bytes);
    sig_bytes[20] ^= 0xFF;
    const bad_sig = try passcay.util.encodeBase64Url(a, sig_bytes);
    defer a.free(bad_sig);

    try testing.expectError(error.SignatureVerificationFailed, passcay.auth.verify(a, .{
        .authenticator_data = td.es256_auth_authdata,
        .client_data_json = td.es256_auth_cdj,
        .signature = bad_sig,
    }, .{
        .public_key = td.es256_pubkey,
        .challenge = td.es256_auth_challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = false,
        .require_user_presence = true,
        .enable_sign_count_check = false,
    }));
}

test "conformance/neg: fmt none with non-empty attStmt -> InvalidAttestationStatement" {
    const a = testing.allocator;
    // Claims "none" but carries a packed-style statement (F-1 style).
    const v = try gen.buildEs256(a, .{ .fmt = "none", .empty_att_stmt = false });
    defer v.deinit(a);
    try testing.expectError(error.InvalidAttestationStatement, regOk(a, .{
        .challenge = v.challenge,
        .origin = v.origin,
        .rp_id = v.rp_id,
        .require_user_verification = true,
        .attestation = .{},
    }, v.attestation_object_b64, v.client_data_json_b64));
}

test "conformance/neg: self attestation rejected when policy forbids it" {
    const a = testing.allocator;
    const v = try gen.buildEs256(a, .{ .fmt = "packed", .empty_att_stmt = false });
    defer v.deinit(a);
    try testing.expectError(error.AttestationTypeNotAllowed, regOk(a, .{
        .challenge = v.challenge,
        .origin = v.origin,
        .rp_id = v.rp_id,
        .require_user_verification = true,
        .attestation = .{ .allow_self = false },
    }, v.attestation_object_b64, v.client_data_json_b64));
}

test "conformance/neg: disallowed attestation format -> AttestationFormatNotAllowed" {
    const a = testing.allocator;
    const v = try gen.buildEs256(a, .{ .fmt = "packed", .empty_att_stmt = false });
    defer v.deinit(a);
    try testing.expectError(error.AttestationFormatNotAllowed, regOk(a, .{
        .challenge = v.challenge,
        .origin = v.origin,
        .rp_id = v.rp_id,
        .require_user_verification = true,
        .attestation = .{ .allowed_formats = &.{"tpm"} },
    }, v.attestation_object_b64, v.client_data_json_b64));
}
