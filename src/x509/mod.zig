//! X.509 certificate handling for attestation, layered over std.crypto.Certificate.
//!
//! Provides parsing, single-link and chain signature verification against trust
//! anchors, and extension-by-OID lookup. Time is injected (`now_sec`) so vectors
//! with expired vendor certificates can be verified at a pinned instant.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;

pub const asn1 = @import("asn1.zig");
pub const crl = @import("crl.zig");
const alg = @import("../alg.zig");

pub const Error = error{
    CertParseFailed,
    ChainEmpty,
    UntrustedRoot,
    UnsupportedAlgorithm,
    UnsupportedCertKey,
    SignatureAlgorithmMismatch,
};

pub const Cert = struct {
    der: []const u8,
    parsed: Certificate.Parsed,

    /// Subject public key bytes (SEC1 point for EC, DER RSAPublicKey for RSA).
    pub fn publicKey(self: Cert) []const u8 {
        return self.parsed.pubKey();
    }

    /// Fetch an extension's value by OID content bytes, or null if absent.
    pub fn getExtension(self: Cert, oid_content: []const u8) !?[]const u8 {
        return asn1.findExtension(self.der, oid_content);
    }
};

/// Parse a DER-encoded certificate.
pub fn parse(der_bytes: []const u8) !Cert {
    const c = Certificate{ .buffer = der_bytes, .index = 0 };
    const p = c.parse() catch return Error.CertParseFailed;
    return .{ .der = der_bytes, .parsed = p };
}

/// Verify that `subject` was signed by `issuer` and is time-valid at now_sec.
pub fn verifySignedBy(subject: Cert, issuer: Cert, now_sec: i64) !void {
    try subject.parsed.verify(issuer.parsed, now_sec);
}

/// Verify an x5c chain (leaf first). Each certificate must be signed by the
/// next (internal links). If trust anchors are supplied, the topmost cert must
/// additionally be signed by — or be byte-identical to — one of them; if no
/// anchors are supplied, root-of-trust is not enforced (the "no metadata
/// service configured" mode, matching common WebAuthn server behaviour — the
/// attestation signature itself is still verified by the caller). Anchors are
/// raw DER.
///
/// `now_sec` pins the verification instant; pass null to skip certificate time
/// validity (each link is verified at its own notBefore) — used for borrowed
/// vectors with expired vendor certificates.
///
/// Note: internal links are verified cryptographically and for time validity,
/// but intermediate `basicConstraints` (cA / pathLenConstraint) are not
/// enforced — a deliberate simplification versus full RFC 5280 path validation.
/// Trust still derives from the supplied anchors; forging a chain requires a
/// CA key. The attestation leaf's CA flag is checked by the format verifiers.
pub fn verifyChain(
    allocator: Allocator,
    chain_der: []const []const u8,
    anchors_der: []const []const u8,
    now_sec: ?i64,
) !void {
    if (chain_der.len == 0) return Error.ChainEmpty;

    const certs = try allocator.alloc(Cert, chain_der.len);
    defer allocator.free(certs);
    for (chain_der, 0..) |d, idx| certs[idx] = try parse(d);

    var idx: usize = 0;
    while (idx + 1 < certs.len) : (idx += 1) {
        try verifySignedBy(certs[idx], certs[idx + 1], linkTime(now_sec, certs[idx]));
    }

    if (anchors_der.len == 0) return; // no root-of-trust enforcement

    const top = certs[certs.len - 1];
    for (anchors_der) |anchor_der| {
        if (std.mem.eql(u8, anchor_der, top.der)) return;
        const anchor = parse(anchor_der) catch continue;
        if (verifySignedBy(top, anchor, linkTime(now_sec, top))) |_| return else |_| {}
    }
    return Error.UntrustedRoot;
}

fn linkTime(now_sec: ?i64, subject: Cert) i64 {
    return now_sec orelse @as(i64, @intCast(subject.parsed.validity.not_before));
}

/// ECDSA signature encoding: WebAuthn uses ASN.1 DER; JOSE/JWS uses raw r‖s.
pub const SigFormat = enum { der, raw };

/// Verify a signature over `data` using this certificate's public key, for the
/// given COSE algorithm id. Supports ECDSA (P-256/P-384) and RSA PKCS#1 v1.5
/// (SHA-1/256/384/512). The declared algorithm must match the certificate key.
pub fn verifyData(cert: Cert, alg_id: i32, signature: []const u8, data: []const u8) !bool {
    return verifyDataFmt(cert, alg_id, signature, data, .der);
}

pub fn verifyDataFmt(cert: Cert, alg_id: i32, signature: []const u8, data: []const u8, fmt: SigFormat) !bool {
    const desc = alg.describe(alg_id) orelse return Error.UnsupportedAlgorithm;
    if (!desc.supported) return Error.UnsupportedAlgorithm;
    const pubkey = cert.publicKey();

    switch (cert.parsed.pub_key_algo) {
        .X9_62_id_ecPublicKey => |named| {
            if (desc.scheme != .ecdsa) return Error.SignatureAlgorithmMismatch;
            switch (named) {
                .X9_62_prime256v1 => {
                    if (desc.curve != .P256) return Error.SignatureAlgorithmMismatch;
                    return verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP256Sha256, pubkey, signature, data, fmt);
                },
                .secp384r1 => {
                    if (desc.curve != .P384) return Error.SignatureAlgorithmMismatch;
                    return verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP384Sha384, pubkey, signature, data, fmt);
                },
                .secp521r1 => return Error.UnsupportedAlgorithm,
            }
        },
        .rsaEncryption => {
            return switch (desc.scheme) {
                .rsa_pkcs1 => verifyRsaPkcs1(pubkey, signature, data, desc.hash),
                .rsa_pss => verifyRsaPss(pubkey, signature, data, desc.hash),
                else => Error.SignatureAlgorithmMismatch,
            };
        },
        .curveEd25519 => {
            if (desc.scheme != .eddsa) return Error.SignatureAlgorithmMismatch;
            return verifyEd25519(pubkey, signature, data);
        },
        else => return Error.UnsupportedCertKey,
    }
}

fn verifyEcdsa(comptime Scheme: type, sec1: []const u8, sig: []const u8, data: []const u8, fmt: SigFormat) bool {
    const pk = Scheme.PublicKey.fromSec1(sec1) catch return false;
    const s = switch (fmt) {
        .der => Scheme.Signature.fromDer(sig) catch return false,
        .raw => blk: {
            const n = Scheme.Signature.encoded_length;
            if (sig.len != n) return false;
            break :blk Scheme.Signature.fromBytes(sig[0..n].*);
        },
    };
    s.verify(data, pk) catch return false;
    return true;
}

fn verifyRsaPkcs1(spki_der: []const u8, sig: []const u8, data: []const u8, hash: alg.HashAlg) bool {
    const rsa = Certificate.rsa;
    const parsed = rsa.PublicKey.parseDer(spki_der) catch return false;
    const pk = rsa.PublicKey.fromBytes(parsed.exponent, parsed.modulus) catch return false;
    return switch (hash) {
        .sha1 => verifyRsaHash(pk, sig, data, std.crypto.hash.Sha1),
        .sha256 => verifyRsaHash(pk, sig, data, std.crypto.hash.sha2.Sha256),
        .sha384 => verifyRsaHash(pk, sig, data, std.crypto.hash.sha2.Sha384),
        .sha512 => verifyRsaHash(pk, sig, data, std.crypto.hash.sha2.Sha512),
    };
}

fn verifyRsaHash(pk: Certificate.rsa.PublicKey, sig: []const u8, data: []const u8, comptime Hash: type) bool {
    inline for (.{ 256, 384, 512 }) |klen| {
        if (sig.len == klen) {
            const s: [klen]u8 = sig[0..klen].*;
            Certificate.rsa.PKCS1v1_5Signature.verify(klen, s, data, pk, Hash) catch return false;
            return true;
        }
    }
    return false;
}

fn verifyRsaPss(spki_der: []const u8, sig: []const u8, data: []const u8, hash: alg.HashAlg) bool {
    const rsa = Certificate.rsa;
    const parsed = rsa.PublicKey.parseDer(spki_der) catch return false;
    const pk = rsa.PublicKey.fromBytes(parsed.exponent, parsed.modulus) catch return false;
    return switch (hash) {
        .sha1 => verifyRsaPssHash(pk, sig, data, std.crypto.hash.Sha1),
        .sha256 => verifyRsaPssHash(pk, sig, data, std.crypto.hash.sha2.Sha256),
        .sha384 => verifyRsaPssHash(pk, sig, data, std.crypto.hash.sha2.Sha384),
        .sha512 => verifyRsaPssHash(pk, sig, data, std.crypto.hash.sha2.Sha512),
    };
}

fn verifyRsaPssHash(pk: Certificate.rsa.PublicKey, sig: []const u8, data: []const u8, comptime Hash: type) bool {
    inline for (.{ 256, 384, 512 }) |klen| {
        if (sig.len == klen) {
            const s: [klen]u8 = sig[0..klen].*;
            Certificate.rsa.PSSSignature.verify(klen, s, data, pk, Hash) catch return false;
            return true;
        }
    }
    return false;
}

/// Verify an Ed25519 signature (raw 64-byte, as used by JOSE EdDSA) with the
/// certificate's 32-byte Ed25519 public key.
fn verifyEd25519(pub_key: []const u8, sig: []const u8, data: []const u8) bool {
    const Ed = std.crypto.sign.Ed25519;
    if (pub_key.len != Ed.PublicKey.encoded_length) return false;
    if (sig.len != Ed.Signature.encoded_length) return false;
    const pk = Ed.PublicKey.fromBytes(pub_key[0..Ed.PublicKey.encoded_length].*) catch return false;
    const s = Ed.Signature.fromBytes(sig[0..Ed.Signature.encoded_length].*);
    s.verify(data, pk) catch return false;
    return true;
}

// ===================== Tests =====================

const zbor = @import("zbor");
const util = @import("../util.zig");

/// Extract the first x5c certificate (DER) from an attestation object. Caller
/// owns the returned slice.
fn extractFirstX5c(allocator: Allocator, attobj_b64: []const u8) ![]u8 {
    const bytes = try util.decodeBase64Url(allocator, attobj_b64);
    defer allocator.free(bytes);

    const di = try zbor.DataItem.new(bytes);
    var map = di.map() orelse return error.NotAMap;

    var att_stmt: ?zbor.DataItem = null;
    while (map.next()) |pair| {
        if (pair.key.getType() == .TextString and std.mem.eql(u8, pair.key.string().?, "attStmt")) {
            att_stmt = pair.value;
        }
    }
    var as_map = (att_stmt orelse return error.NoAttStmt).map() orelse return error.NotAMap;

    var x5c: ?zbor.DataItem = null;
    while (as_map.next()) |pair| {
        if (pair.key.getType() == .TextString and std.mem.eql(u8, pair.key.string().?, "x5c")) {
            x5c = pair.value;
        }
    }
    var arr = (x5c orelse return error.NoX5c).array() orelse return error.NotAnArray;
    const first = arr.next() orelse return error.EmptyX5c;
    return allocator.dupe(u8, first.string() orelse return error.NotAByteString);
}

const td = @import("../test_data.zig");

test "x509 parse, self-signed verify, chain, and extension lookup on real batch cert" {
    const a = std.testing.allocator;
    const now: i64 = 1_600_000_000; // 2020, within the batch cert's validity window

    const cert_der = try extractFirstX5c(a, td.rs256_reg_attobj);
    defer a.free(cert_der);

    const cert = try parse(cert_der);

    // The conformance batch cert is self-signed (subject == issuer).
    try verifySignedBy(cert, cert, now);
    try verifyChain(a, &.{cert_der}, &.{}, now);

    // basicConstraints and the FIDO U2F transports extension are present.
    try std.testing.expect((try cert.getExtension(asn1.oid.basic_constraints)) != null);
    try std.testing.expect((try cert.getExtension(asn1.oid.fido_u2f_transports)) != null);

    // An extension the cert does not carry is reported absent.
    try std.testing.expect((try cert.getExtension(asn1.oid.apple_nonce)) == null);
}

test "x509 signature check enforces certificate time validity" {
    const a = std.testing.allocator;

    const cert_der = try extractFirstX5c(a, td.rs256_reg_attobj);
    defer a.free(cert_der);
    const cert = try parse(cert_der);

    // 1970 is before the batch cert's notBefore (2017): verification must fail.
    try std.testing.expect(std.meta.isError(verifySignedBy(cert, cert, 100)));
    // Within the validity window it succeeds.
    try verifySignedBy(cert, cert, 1_600_000_000);
}

test "x509 verifyChain rejects a chain whose top is not anchored" {
    const a = std.testing.allocator;
    const cert_der = try extractFirstX5c(a, td.rs256_reg_attobj);
    defer a.free(cert_der);
    // An unrelated certificate as the only trust anchor: the self-signed batch
    // cert is neither byte-identical to it nor signed by it -> UntrustedRoot.
    try std.testing.expectError(Error.UntrustedRoot, verifyChain(a, &.{cert_der}, &.{@embedFile("../testdata/test_crl_ca.der")}, 1_600_000_000));
}

test "x509 verifies an RSA-PSS (PS256) certificate signature" {
    const cert = try parse(@embedFile("../testdata/test_pss_cert.der"));
    const sig = @embedFile("../testdata/test_pss_sig.bin");
    try std.testing.expect(try verifyData(cert, -37, sig, "passcay x509 alg test vector"));
    try std.testing.expect(!try verifyData(cert, -37, sig, "tampered message"));
}

test "x509 verifies an Ed25519 (EdDSA) certificate signature" {
    const cert = try parse(@embedFile("../testdata/test_ed25519_cert.der"));
    const sig = @embedFile("../testdata/test_ed25519_sig.bin");
    // JOSE EdDSA is raw 64-byte; the format flag is irrelevant for Ed25519.
    try std.testing.expect(try verifyDataFmt(cert, -8, sig, "passcay x509 alg test vector", .raw));
    try std.testing.expect(!try verifyDataFmt(cert, -8, sig, "tampered message", .raw));
}
