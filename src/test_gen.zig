//! In-test attestation vector generators.
//!
//! Deterministic (fixed-seed) builders used by the conformance harness to
//! exercise verification paths for which we control the keys (e.g. "none",
//! packed self attestation). Not part of the public API.

const std = @import("std");
const Allocator = std.mem.Allocator;

const cbor = @import("cbor.zig");
const util = @import("util.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const List = std.array_list.Managed(u8);

pub const Options = struct {
    /// Attestation format string written into the attestation object.
    fmt: []const u8 = "packed",
    /// When true, attStmt is an empty map (as in "none"); otherwise a packed
    /// self attestation statement {alg:-7, sig} is produced and signed.
    empty_att_stmt: bool = false,
    /// Authenticator data flags (UP | UV | AT by default).
    flags: u8 = 0x45,
    /// Deterministic key seed.
    seed: [32]u8 = @splat(7),
    /// Challenge string as it appears (verbatim) in clientDataJSON.
    challenge: []const u8 = "Y29uZm9ybWFuY2UtdGVzdC1jaGFsbGVuZ2U",
    origin: []const u8 = "http://localhost:8080",
    rp_id: []const u8 = "localhost",
    aaguid: [16]u8 = @splat(0),
    credential_id: []const u8 = "passcay-test-credential-id-0001",
};

pub const Generated = struct {
    attestation_object_b64: []const u8,
    client_data_json_b64: []const u8,
    challenge: []const u8,
    origin: []const u8,
    rp_id: []const u8,
    credential_id_b64: []const u8,

    pub fn deinit(self: Generated, a: Allocator) void {
        a.free(self.attestation_object_b64);
        a.free(self.client_data_json_b64);
        a.free(self.credential_id_b64);
    }
};

pub fn buildEs256(allocator: Allocator, opts: Options) !Generated {
    const kp = try Ecdsa.KeyPair.generateDeterministic(opts.seed);
    const sec1 = kp.public_key.toUncompressedSec1(); // 0x04 || x(32) || y(32)
    const x = sec1[1..33];
    const y = sec1[33..65];

    // COSE_Key for EC2 / P-256 / ES256.
    var cose_key = List.init(allocator);
    defer cose_key.deinit();
    try cose_key.append(0xA5); // map(5)
    try cose_key.appendSlice(&[_]u8{ 0x01, 0x02 }); // kty: EC2
    try cose_key.appendSlice(&[_]u8{ 0x03, 0x26 }); // alg: ES256 (-7)
    try cose_key.appendSlice(&[_]u8{ 0x20, 0x01 }); // crv: P-256
    try cose_key.appendSlice(&[_]u8{ 0x21, 0x58, 0x20 }); // x: bstr(32)
    try cose_key.appendSlice(x);
    try cose_key.appendSlice(&[_]u8{ 0x22, 0x58, 0x20 }); // y: bstr(32)
    try cose_key.appendSlice(y);

    // Authenticator data: rpIdHash || flags || signCount || attestedCredData.
    var auth_data = List.init(allocator);
    defer auth_data.deinit();
    var rp_id_hash: [32]u8 = undefined;
    Sha256.hash(opts.rp_id, &rp_id_hash, .{});
    try auth_data.appendSlice(&rp_id_hash);
    try auth_data.append(opts.flags);
    try auth_data.appendSlice(&[_]u8{ 0, 0, 0, 0 }); // signCount = 0
    try auth_data.appendSlice(&opts.aaguid);
    const cred_id_len: u16 = @intCast(opts.credential_id.len);
    try auth_data.append(@intCast(cred_id_len >> 8));
    try auth_data.append(@intCast(cred_id_len & 0xFF));
    try auth_data.appendSlice(opts.credential_id);
    try auth_data.appendSlice(cose_key.items);

    // clientDataJSON.
    var cdj = List.init(allocator);
    defer cdj.deinit();
    try cdj.appendSlice("{\"type\":\"webauthn.create\",\"challenge\":\"");
    try cdj.appendSlice(opts.challenge);
    try cdj.appendSlice("\",\"origin\":\"");
    try cdj.appendSlice(opts.origin);
    try cdj.appendSlice("\",\"crossOrigin\":false}");

    var client_data_hash: [32]u8 = undefined;
    Sha256.hash(cdj.items, &client_data_hash, .{});

    // Attestation statement.
    var att_stmt = List.init(allocator);
    defer att_stmt.deinit();
    if (opts.empty_att_stmt) {
        try att_stmt.append(0xA0); // empty map
    } else {
        // Self attestation: sign authData || clientDataHash with the credential key.
        var signed = List.init(allocator);
        defer signed.deinit();
        try signed.appendSlice(auth_data.items);
        try signed.appendSlice(&client_data_hash);

        const sig = try kp.sign(signed.items, null);
        var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der = sig.toDer(&der_buf);

        try att_stmt.append(0xA2); // map(2)
        try att_stmt.appendSlice(&[_]u8{ 0x63, 'a', 'l', 'g', 0x26 }); // "alg": -7
        try att_stmt.appendSlice(&[_]u8{ 0x63, 's', 'i', 'g' }); // "sig":
        try att_stmt.append(0x58); // bstr, 1-byte length
        try att_stmt.append(@intCast(der.len));
        try att_stmt.appendSlice(der);
    }

    const att_obj = try cbor.encodeAttestationObject(allocator, opts.fmt, auth_data.items, att_stmt.items);
    defer allocator.free(att_obj);

    return Generated{
        .attestation_object_b64 = try util.encodeBase64Url(allocator, att_obj),
        .client_data_json_b64 = try util.encodeBase64Url(allocator, cdj.items),
        .challenge = opts.challenge,
        .origin = opts.origin,
        .rp_id = opts.rp_id,
        .credential_id_b64 = try util.encodeBase64Url(allocator, opts.credential_id),
    };
}
