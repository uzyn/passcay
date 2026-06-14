//! "fido-u2f" attestation format (§8.6).
//!
//! Legacy U2F attestation: the statement carries {sig, x5c} (a single EC P-256
//! attestation certificate, no alg field). The signature is over
//!   0x00 || rpIdHash || clientDataHash || credentialId || (0x04 || x || y)
//! using the certificate's public key (always ECDSA P-256 / SHA-256).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const zbor = @import("zbor");

const m = @import("mod.zig");
const cbor = @import("../cbor.zig");
const x509 = @import("../x509/mod.zig");

pub fn verify(allocator: Allocator, params: m.VerifyParams, policy: m.Policy) !m.Result {
    const di = zbor.DataItem.new(params.att_stmt) catch return m.Error.InvalidAttestationStatement;
    if (di.getType() != .Map) return m.Error.InvalidAttestationStatement;

    var sig: ?[]const u8 = null;
    var x5c: ?zbor.DataItem = null;
    var it = di.map() orelse return m.Error.InvalidAttestationStatement;
    while (it.next()) |pair| {
        if (pair.key.getType() != .TextString) continue;
        const key = pair.key.string() orelse continue;
        if (mem.eql(u8, key, "sig")) {
            if (pair.value.getType() != .ByteString) return m.Error.InvalidAttestationStatement;
            sig = pair.value.string();
        } else if (mem.eql(u8, key, "x5c")) {
            x5c = pair.value;
        }
    }

    const signature = sig orelse return m.Error.InvalidAttestationStatement;
    const x5c_item = x5c orelse return m.Error.InvalidAttestationStatement;
    if (x5c_item.getType() != .Array) return m.Error.InvalidAttestationStatement;

    var arr = x5c_item.array() orelse return m.Error.InvalidAttestationStatement;
    const cert0 = arr.next() orelse return m.Error.InvalidAttestationStatement;
    if (cert0.getType() != .ByteString) return m.Error.InvalidAttestationStatement;
    const cert_der = cert0.string() orelse return m.Error.InvalidAttestationStatement;

    // U2F authenticators have no AAGUID; it MUST be all zeros (§8.6).
    for (params.aaguid) |b| {
        if (b != 0) return m.Error.AttestationAaguidMismatch;
    }

    // Credential public key must be EC2 / P-256; reconstruct the U2F public key.
    const key = cbor.parseCoseKey(allocator, params.credential_public_key) catch
        return m.Error.InvalidAttestationStatement;
    defer key.deinit(allocator);
    if (key.key_type != .EC2) return m.Error.AttestationAlgorithmMismatch;
    if (key.curve == null or key.curve.? != .P256) return m.Error.AttestationAlgorithmMismatch;
    const x = key.x orelse return m.Error.InvalidAttestationStatement;
    const y = key.y orelse return m.Error.InvalidAttestationStatement;
    if (x.len > 32 or y.len > 32) return m.Error.InvalidAttestationStatement;

    var pub_u2f: [65]u8 = undefined;
    pub_u2f[0] = 0x04;
    @memset(pub_u2f[1..], 0);
    @memcpy(pub_u2f[1 + 32 - x.len .. 33], x);
    @memcpy(pub_u2f[33 + 32 - y.len .. 65], y);

    if (params.auth_data.len < 32) return m.Error.InvalidAttestationStatement;
    const rp_id_hash = params.auth_data[0..32];

    // verificationData = 0x00 || rpIdHash || clientDataHash || credId || pubU2F
    const total = 1 + 32 + params.client_data_hash.len + params.credential_id.len + 65;
    const vd = try allocator.alloc(u8, total);
    defer allocator.free(vd);
    var off: usize = 0;
    vd[off] = 0x00;
    off += 1;
    @memcpy(vd[off..][0..32], rp_id_hash);
    off += 32;
    @memcpy(vd[off..][0..params.client_data_hash.len], params.client_data_hash);
    off += params.client_data_hash.len;
    @memcpy(vd[off..][0..params.credential_id.len], params.credential_id);
    off += params.credential_id.len;
    @memcpy(vd[off..][0..65], &pub_u2f);

    const leaf = x509.parse(cert_der) catch return m.Error.AttestationCertInvalid;
    // U2F attestation is always ES256 (-7).
    const ok = x509.verifyData(leaf, -7, signature, vd) catch return m.Error.AttestationAlgorithmMismatch;
    if (!ok) return m.Error.AttestationSignatureInvalid;

    // U2F authenticators have no AAGUID, so MDS lookup is keyed on the
    // attestation certificate (not modeled yet); trust uses policy.roots
    // directly rather than resolveAnchors.
    x509.verifyChain(allocator, &.{cert_der}, policy.roots, policy.now_sec) catch
        return m.Error.AttestationChainUntrusted;

    return .{ .type = .basic };
}
