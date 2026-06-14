//! "packed" attestation format (§8.2).
//!
//! Two variants:
//!   - Self attestation: attStmt has {alg, sig}; the signature is produced by
//!     the credential private key over authenticatorData || clientDataHash, and
//!     `alg` must equal the credential public key's algorithm.
//!   - Full (basic/AttCA) attestation: attStmt also has x5c; the signature is
//!     verified with the leaf certificate's key, the chain is validated to a
//!     trust anchor, the leaf must not be a CA, and if the leaf carries the
//!     id-fido-gen-ce-aaguid extension it must equal the authenticator AAGUID.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const zbor = @import("zbor");

const m = @import("mod.zig");
const crypto = @import("../crypto.zig");
const cbor = @import("../cbor.zig");
const x509 = @import("../x509/mod.zig");

const max_chain = 8;

pub fn verify(allocator: Allocator, params: m.VerifyParams, policy: m.Policy) !m.Result {
    const di = zbor.DataItem.new(params.att_stmt) catch return m.Error.InvalidAttestationStatement;
    if (di.getType() != .Map) return m.Error.InvalidAttestationStatement;

    var alg_id: ?i64 = null;
    var sig: ?[]const u8 = null;
    var x5c: ?zbor.DataItem = null;

    var it = di.map() orelse return m.Error.InvalidAttestationStatement;
    while (it.next()) |pair| {
        if (pair.key.getType() != .TextString) continue;
        const key = pair.key.string() orelse continue;

        if (mem.eql(u8, key, "alg")) {
            if (pair.value.getType() != .Int) return m.Error.InvalidAttestationStatement;
            alg_id = @intCast(pair.value.int() orelse return m.Error.InvalidAttestationStatement);
        } else if (mem.eql(u8, key, "sig")) {
            if (pair.value.getType() != .ByteString) return m.Error.InvalidAttestationStatement;
            sig = pair.value.string() orelse return m.Error.InvalidAttestationStatement;
        } else if (mem.eql(u8, key, "x5c")) {
            x5c = pair.value;
        }
    }

    const declared_alg = alg_id orelse return m.Error.InvalidAttestationStatement;
    const signature = sig orelse return m.Error.InvalidAttestationStatement;
    if (signature.len == 0) return m.Error.InvalidAttestationStatement;
    const declared_alg32 = std.math.cast(i32, declared_alg) orelse return m.Error.AttestationAlgorithmMismatch;

    // Message base: authenticatorData || clientDataHash.
    const signed = try allocator.alloc(u8, params.auth_data.len + params.client_data_hash.len);
    defer allocator.free(signed);
    @memcpy(signed[0..params.auth_data.len], params.auth_data);
    @memcpy(signed[params.auth_data.len..], params.client_data_hash);

    if (x5c) |x5c_item| {
        return verifyFull(allocator, params, policy, declared_alg32, signature, signed, x5c_item);
    }
    return verifySelf(allocator, params, declared_alg32, signature, signed);
}

fn verifySelf(allocator: Allocator, params: m.VerifyParams, declared_alg: i32, signature: []const u8, signed: []const u8) !m.Result {
    const cred_alg = crypto.getAlgorithmId(params.credential_public_key) catch return m.Error.InvalidAttestationStatement;
    if (declared_alg != cred_alg) return m.Error.AttestationAlgorithmMismatch;

    const ok = crypto.verifyWithCoseKey(allocator, params.credential_public_key, signature, signed) catch
        return m.Error.AttestationSignatureInvalid;
    if (!ok) return m.Error.AttestationSignatureInvalid;

    return .{ .type = .self };
}

fn verifyFull(
    allocator: Allocator,
    params: m.VerifyParams,
    policy: m.Policy,
    declared_alg: i32,
    signature: []const u8,
    signed: []const u8,
    x5c_item: zbor.DataItem,
) !m.Result {
    if (x5c_item.getType() != .Array) return m.Error.InvalidAttestationStatement;

    var chain: [max_chain][]const u8 = undefined;
    var n: usize = 0;
    var arr = x5c_item.array() orelse return m.Error.InvalidAttestationStatement;
    while (arr.next()) |cert| {
        if (cert.getType() != .ByteString) return m.Error.InvalidAttestationStatement;
        if (n >= max_chain) return m.Error.AttestationCertInvalid;
        chain[n] = cert.string() orelse return m.Error.InvalidAttestationStatement;
        n += 1;
    }
    if (n == 0) return m.Error.InvalidAttestationStatement;

    // The attestation x5c MUST NOT embed the trust anchor (root). A multi-cert
    // chain whose top is self-signed inlines the root — reject it. (A single
    // self-signed batch certificate referenced in metadata is allowed.)
    if (n > 1) {
        const top = x509.parse(chain[n - 1]) catch return m.Error.AttestationCertInvalid;
        if (mem.eql(u8, top.parsed.subject(), top.parsed.issuer())) {
            return m.Error.AttestationCertInvalid;
        }
    }

    const leaf = x509.parse(chain[0]) catch return m.Error.AttestationCertInvalid;

    // 1. Attestation signature verified with the leaf certificate's public key.
    const ok = x509.verifyData(leaf, declared_alg, signature, signed) catch
        return m.Error.AttestationAlgorithmMismatch;
    if (!ok) return m.Error.AttestationSignatureInvalid;

    // 2. Certificate chain validates to a trust anchor (MDS-resolved if configured).
    const anchors = try m.resolveAnchors(policy, params.aaguid);
    x509.verifyChain(allocator, chain[0..n], anchors, policy.now_sec) catch
        return m.Error.AttestationChainUntrusted;

    // 3. Leaf MUST NOT be a CA (basicConstraints CA == false / absent).
    if (try leaf.getExtension(x509.asn1.oid.basic_constraints)) |bc| {
        if (isCa(bc)) return m.Error.AttestationCertInvalid;
    }

    // 4. If the leaf carries the FIDO AAGUID extension it must match authData.
    if (try leaf.getExtension(x509.asn1.oid.fido_aaguid)) |ext_val| {
        const aaguid = unwrapOctetString(ext_val) orelse return m.Error.AttestationCertInvalid;
        if (!mem.eql(u8, aaguid, params.aaguid)) return m.Error.AttestationAaguidMismatch;
    }

    // 5. The attestation (batch) certificate MUST NOT be the credential's own
    // key — that would be self attestation masquerading as full.
    if (leafKeyEqualsCredential(allocator, leaf, params.credential_public_key)) {
        return m.Error.AttestationCertInvalid;
    }

    return .{ .type = .basic };
}

/// Whether the leaf certificate's public key equals the credential public key
/// (EC2 only; the case that distinguishes a disguised self attestation).
fn leafKeyEqualsCredential(allocator: Allocator, leaf: x509.Cert, cred_cose: []const u8) bool {
    if (leaf.parsed.pub_key_algo != .X9_62_id_ecPublicKey) return false;
    const sec1 = leaf.publicKey(); // 0x04 || x || y
    if (sec1.len < 3 or sec1[0] != 0x04) return false;
    const flen = (sec1.len - 1) / 2;

    const key = cbor.parseCoseKey(allocator, cred_cose) catch return false;
    defer key.deinit(allocator);
    if (key.key_type != .EC2) return false;
    const x = key.x orelse return false;
    const y = key.y orelse return false;
    return coordEq(sec1[1 .. 1 + flen], x) and coordEq(sec1[1 + flen .. 1 + 2 * flen], y);
}

/// Compare a fixed-width coordinate to a COSE coordinate (which may have had
/// leading zero bytes stripped).
fn coordEq(field: []const u8, coord: []const u8) bool {
    if (coord.len > field.len) return false;
    const pad = field.len - coord.len;
    for (field[0..pad]) |b| {
        if (b != 0) return false;
    }
    return mem.eql(u8, field[pad..], coord);
}

/// Parse a BasicConstraints extension value, returning whether cA is TRUE.
fn isCa(bc_der: []const u8) bool {
    const seq = x509.asn1.parse(bc_der, 0) catch return false;
    if (@intFromEnum(seq.identifier.tag) != @intFromEnum(std.crypto.Certificate.der.Tag.sequence)) return false;
    var i = seq.slice.start;
    while (i < seq.slice.end) {
        const e = x509.asn1.parse(bc_der, i) catch return false;
        i = e.slice.end;
        if (e.identifier.class == .universal and @intFromEnum(e.identifier.tag) == 1) { // BOOLEAN
            if (e.slice.end > e.slice.start and bc_der[e.slice.start] != 0x00) return true;
        }
    }
    return false;
}

/// Unwrap a DER OCTET STRING, returning its content (the inner 16-byte AAGUID).
fn unwrapOctetString(der_bytes: []const u8) ?[]const u8 {
    const e = x509.asn1.parse(der_bytes, 0) catch return null;
    if (@intFromEnum(e.identifier.tag) != 4) return null; // octetstring
    return der_bytes[e.slice.start..e.slice.end];
}
