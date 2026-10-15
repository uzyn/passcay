//! "tpm" attestation format (§8.3).
//!
//! The statement carries {ver, alg, x5c, sig, certInfo, pubArea}. Verification
//! (per W3C WebAuthn §8.3):
//!   1. pubArea's public key matches the credential public key in authData.
//!   2. certInfo is a well-formed TPMS_ATTEST: magic == TPM_GENERATED_VALUE,
//!      type == TPM_ST_ATTEST_CERTIFY, extraData == hash(authData||clientDataHash)
//!      under `alg`'s hash, and attested.name == nameAlg || hash(pubArea).
//!   3. sig is a valid signature over certInfo by the AIK (x5c[0]) under `alg`.
//!   4. The x5c chain validates to a trust anchor (MDS-resolved if configured).
//!   5. The AIK certificate meets the §8.3.1 requirements (v3, empty subject,
//!      TPM SAN, tcg-kp-AIKCertificate EKU, CA:FALSE, optional AAGUID match).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const zbor = @import("zbor");

const m = @import("mod.zig");
const cbor = @import("../cbor.zig");
const x509 = @import("../x509/mod.zig");
const asn1 = x509.asn1;
const algmod = @import("../alg.zig");
const types = @import("../types.zig");

const max_chain = 8;

// TPM constants (TPM 2.0, Trusted Computing Group).
const TPM_GENERATED_VALUE: u32 = 0xff544347;
const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_SHA384: u16 = 0x000C;
const TPM_ALG_SHA512: u16 = 0x000D;
const TPM_ECC_NIST_P256: u16 = 0x0003;
const TPM_ECC_NIST_P384: u16 = 0x0004;

pub fn verify(allocator: Allocator, params: m.VerifyParams, policy: m.Policy) !m.Result {
    const di = zbor.DataItem.new(params.att_stmt) catch return m.Error.InvalidAttestationStatement;
    if (di.getType() != .Map) return m.Error.InvalidAttestationStatement;

    var ver: ?[]const u8 = null;
    var alg_id: ?i64 = null;
    var sig: ?[]const u8 = null;
    var cert_info: ?[]const u8 = null;
    var pub_area: ?[]const u8 = null;
    var x5c: ?zbor.DataItem = null;

    var it = di.map() orelse return m.Error.InvalidAttestationStatement;
    while (it.next()) |pair| {
        if (pair.key.getType() != .TextString) continue;
        const key = pair.key.string() orelse continue;
        if (mem.eql(u8, key, "ver")) {
            if (pair.value.getType() != .TextString) return m.Error.InvalidAttestationStatement;
            ver = pair.value.string();
        } else if (mem.eql(u8, key, "alg")) {
            if (pair.value.getType() != .Int) return m.Error.InvalidAttestationStatement;
            alg_id = @intCast(pair.value.int() orelse return m.Error.InvalidAttestationStatement);
        } else if (mem.eql(u8, key, "sig")) {
            if (pair.value.getType() != .ByteString) return m.Error.InvalidAttestationStatement;
            sig = pair.value.string();
        } else if (mem.eql(u8, key, "certInfo")) {
            if (pair.value.getType() != .ByteString) return m.Error.InvalidAttestationStatement;
            cert_info = pair.value.string();
        } else if (mem.eql(u8, key, "pubArea")) {
            if (pair.value.getType() != .ByteString) return m.Error.InvalidAttestationStatement;
            pub_area = pair.value.string();
        } else if (mem.eql(u8, key, "x5c")) {
            x5c = pair.value;
        }
    }

    const version = ver orelse return m.Error.InvalidAttestationStatement;
    if (!mem.eql(u8, version, "2.0")) return m.Error.InvalidAttestationStatement;
    const declared_alg = alg_id orelse return m.Error.InvalidAttestationStatement;
    const declared_alg32 = std.math.cast(i32, declared_alg) orelse return m.Error.AttestationAlgorithmMismatch;
    const desc = algmod.describe(declared_alg32) orelse return m.Error.AttestationAlgorithmMismatch;
    if (!desc.supported) return m.Error.AttestationAlgorithmMismatch;
    const signature = sig orelse return m.Error.InvalidAttestationStatement;
    const ci = cert_info orelse return m.Error.InvalidAttestationStatement;
    const pa_bytes = pub_area orelse return m.Error.InvalidAttestationStatement;
    const x5c_item = x5c orelse return m.Error.InvalidAttestationStatement;

    // x5c chain (leaf first).
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

    // 1. pubArea public key must equal the credential public key.
    const pa = try parsePubArea(pa_bytes);
    try matchCredentialKey(allocator, pa, params.credential_public_key);

    // 2. certInfo validation.
    const cert = try parseCertInfo(ci);
    if (cert.magic != TPM_GENERATED_VALUE) return m.Error.InvalidAttestationStatement;
    if (cert.type != TPM_ST_ATTEST_CERTIFY) return m.Error.InvalidAttestationStatement;

    // extraData == hash_alg(authData || clientDataHash).
    {
        const atbs = try allocator.alloc(u8, params.auth_data.len + params.client_data_hash.len);
        defer allocator.free(atbs);
        @memcpy(atbs[0..params.auth_data.len], params.auth_data);
        @memcpy(atbs[params.auth_data.len..], params.client_data_hash);
        var buf: [64]u8 = undefined;
        const ed = digestInto(desc.hash, atbs, &buf);
        if (!mem.eql(u8, cert.extra_data, ed)) return m.Error.AttestationSignatureInvalid;
    }

    // attested.name == pubArea.nameAlg || hash_{nameAlg}(pubArea).
    {
        const name_hash = nameAlgHash(pa.name_alg) orelse return m.Error.InvalidAttestationStatement;
        var buf: [64]u8 = undefined;
        const ph = digestInto(name_hash, pa_bytes, &buf);
        if (cert.attested_name.len != 2 + ph.len) return m.Error.AttestationCertInvalid;
        if (!mem.eql(u8, cert.attested_name[0..2], pa_bytes[2..4])) return m.Error.AttestationCertInvalid;
        if (!mem.eql(u8, cert.attested_name[2..], ph)) return m.Error.AttestationCertInvalid;
    }

    // 3. sig over certInfo with the AIK (leaf) certificate.
    const leaf = x509.parse(chain[0]) catch return m.Error.AttestationCertInvalid;
    const ok = x509.verifyData(leaf, declared_alg32, signature, ci) catch return m.Error.AttestationAlgorithmMismatch;
    if (!ok) return m.Error.AttestationSignatureInvalid;

    // 4. Chain validates to a trust anchor (MDS-resolved if configured).
    const anchors = try m.resolveAnchors(policy, params.aaguid);
    x509.verifyChain(allocator, chain[0..n], anchors, policy.now_sec) catch return m.Error.AttestationChainUntrusted;

    // 5. AIK certificate requirements (§8.3.1).
    try checkAikCert(leaf, chain[0], params.aaguid);

    return .{ .type = .attca };
}

// ---- pubArea (TPMT_PUBLIC) ----

const PubArea = struct {
    type: u16,
    name_alg: u16,
    /// For RSA: the modulus. For ECC: x coordinate.
    unique_x: []const u8,
    /// ECC only: y coordinate.
    unique_y: []const u8,
    /// RSA only: public exponent (0 means the default 65537).
    exponent: u32,
    /// ECC only: TPM curve id.
    curve_id: u16,
};

fn parsePubArea(b: []const u8) !PubArea {
    var r = Reader{ .b = b };
    const typ = try r.readU16();
    const name_alg = try r.readU16();
    _ = try r.readU32(); // objectAttributes
    _ = try r.tpm2b(); // authPolicy

    if (typ == TPM_ALG_RSA) {
        _ = try r.readU16(); // symmetric
        _ = try r.readU16(); // scheme
        _ = try r.readU16(); // keyBits
        const exponent = try r.readU32();
        const modulus = try r.tpm2b();
        return .{ .type = typ, .name_alg = name_alg, .unique_x = modulus, .unique_y = &.{}, .exponent = exponent, .curve_id = 0 };
    } else if (typ == TPM_ALG_ECC) {
        _ = try r.readU16(); // symmetric
        _ = try r.readU16(); // scheme
        const curve_id = try r.readU16();
        _ = try r.readU16(); // kdf
        const x = try r.tpm2b();
        const y = try r.tpm2b();
        return .{ .type = typ, .name_alg = name_alg, .unique_x = x, .unique_y = y, .exponent = 0, .curve_id = curve_id };
    }
    return m.Error.InvalidAttestationStatement;
}

fn matchCredentialKey(allocator: Allocator, pa: PubArea, cred_cose: []const u8) !void {
    const key = cbor.parseCoseKey(allocator, cred_cose) catch return m.Error.InvalidAttestationStatement;
    defer key.deinit(allocator);

    if (pa.type == TPM_ALG_RSA) {
        if (key.key_type != .RSA) return m.Error.AttestationCertInvalid;
        const n = key.n orelse return m.Error.AttestationCertInvalid;
        if (!bigEq(pa.unique_x, n)) return m.Error.AttestationCertInvalid;
        const e = key.e orelse return m.Error.AttestationCertInvalid;
        const want_exp: u64 = if (pa.exponent == 0) 65537 else pa.exponent;
        if (beToU64(e) != want_exp) return m.Error.AttestationCertInvalid;
    } else if (pa.type == TPM_ALG_ECC) {
        if (key.key_type != .EC2) return m.Error.AttestationCertInvalid;
        const x = key.x orelse return m.Error.AttestationCertInvalid;
        const y = key.y orelse return m.Error.AttestationCertInvalid;
        if (!bigEq(pa.unique_x, x) or !bigEq(pa.unique_y, y)) return m.Error.AttestationCertInvalid;
        const want_crv: types.CoseCurve = switch (pa.curve_id) {
            TPM_ECC_NIST_P256 => .P256,
            TPM_ECC_NIST_P384 => .P384,
            else => return m.Error.AttestationCertInvalid,
        };
        if (key.curve == null or key.curve.? != want_crv) return m.Error.AttestationCertInvalid;
    } else {
        return m.Error.InvalidAttestationStatement;
    }
}

// ---- certInfo (TPMS_ATTEST) ----

const CertInfo = struct {
    magic: u32,
    type: u16,
    extra_data: []const u8,
    attested_name: []const u8,
};

fn parseCertInfo(b: []const u8) !CertInfo {
    var r = Reader{ .b = b };
    const magic = try r.readU32();
    const typ = try r.readU16();
    _ = try r.tpm2b(); // qualifiedSigner
    const extra_data = try r.tpm2b();
    try r.skip(17); // clockInfo (TPMS_CLOCK_INFO)
    try r.skip(8); // firmwareVersion
    const attested_name = try r.tpm2b();
    // qualifiedName follows but is unused.
    return .{ .magic = magic, .type = typ, .extra_data = extra_data, .attested_name = attested_name };
}

// ---- AIK certificate requirements (§8.3.1) ----

fn checkAikCert(leaf: x509.Cert, leaf_der: []const u8, aaguid: []const u8) !void {
    // Version MUST be 3.
    if (!certIsV3(leaf_der)) return m.Error.AttestationCertInvalid;
    // Subject MUST be empty.
    if (leaf.parsed.subject().len != 0) return m.Error.AttestationCertInvalid;
    // SubjectAltName MUST carry the TPM manufacturer, model, and version.
    const san = (try leaf.getExtension(asn1.oid.subject_alt_name)) orelse return m.Error.AttestationCertInvalid;
    if (mem.indexOf(u8, san, asn1.oid.tcg_tpm_manufacturer) == null) return m.Error.AttestationCertInvalid;
    if (mem.indexOf(u8, san, asn1.oid.tcg_tpm_model) == null) return m.Error.AttestationCertInvalid;
    if (mem.indexOf(u8, san, asn1.oid.tcg_tpm_version) == null) return m.Error.AttestationCertInvalid;
    // ExtendedKeyUsage MUST contain tcg-kp-AIKCertificate (2.23.133.8.3).
    const eku = (try leaf.getExtension(asn1.oid.ext_key_usage)) orelse return m.Error.AttestationCertInvalid;
    if (mem.indexOf(u8, eku, asn1.oid.tcg_kp_aik) == null) return m.Error.AttestationCertInvalid;
    // BasicConstraints MUST have CA == false.
    const bc = (try leaf.getExtension(asn1.oid.basic_constraints)) orelse return m.Error.AttestationCertInvalid;
    if (isCa(bc)) return m.Error.AttestationCertInvalid;
    // If the FIDO AAGUID extension is present it MUST match authData.
    if (try leaf.getExtension(asn1.oid.fido_aaguid)) |ext_val| {
        const ag = unwrapOctetString(ext_val) orelse return m.Error.AttestationCertInvalid;
        if (!mem.eql(u8, ag, aaguid)) return m.Error.AttestationAaguidMismatch;
    }
}

/// Whether the certificate's X.509 version is v3 (TBSCertificate [0] == 2).
fn certIsV3(der: []const u8) bool {
    const c = asn1.parse(der, 0) catch return false;
    const tbs = asn1.parse(der, c.slice.start) catch return false;
    const first = asn1.parse(der, tbs.slice.start) catch return false;
    if (first.identifier.class != .context_specific or @backingInt(first.identifier.tag) != 0) return false;
    const ver = asn1.parse(der, first.slice.start) catch return false;
    if (ver.slice.end <= ver.slice.start) return false;
    return der[ver.slice.end - 1] == 2;
}

fn isCa(bc_der: []const u8) bool {
    const seq = asn1.parse(bc_der, 0) catch return false;
    if (@backingInt(seq.identifier.tag) != @backingInt(std.crypto.Certificate.der.Tag.sequence)) return false;
    var i = seq.slice.start;
    while (i < seq.slice.end) {
        const e = asn1.parse(bc_der, i) catch return false;
        i = e.slice.end;
        if (e.identifier.class == .universal and @backingInt(e.identifier.tag) == 1) { // BOOLEAN
            if (e.slice.end > e.slice.start and bc_der[e.slice.start] != 0x00) return true;
        }
    }
    return false;
}

fn unwrapOctetString(der_bytes: []const u8) ?[]const u8 {
    const e = asn1.parse(der_bytes, 0) catch return null;
    if (@backingInt(e.identifier.tag) != 4) return null; // octetstring
    return der_bytes[e.slice.start..e.slice.end];
}

// ---- helpers ----

const Reader = struct {
    b: []const u8,
    pos: usize = 0,

    fn readU16(self: *Reader) !u16 {
        if (self.pos + 2 > self.b.len) return m.Error.InvalidAttestationStatement;
        const v = (@as(u16, self.b[self.pos]) << 8) | self.b[self.pos + 1];
        self.pos += 2;
        return v;
    }

    fn readU32(self: *Reader) !u32 {
        if (self.pos + 4 > self.b.len) return m.Error.InvalidAttestationStatement;
        const v = (@as(u32, self.b[self.pos]) << 24) | (@as(u32, self.b[self.pos + 1]) << 16) |
            (@as(u32, self.b[self.pos + 2]) << 8) | self.b[self.pos + 3];
        self.pos += 4;
        return v;
    }

    fn take(self: *Reader, len: usize) ![]const u8 {
        if (self.pos + len > self.b.len) return m.Error.InvalidAttestationStatement;
        const s = self.b[self.pos .. self.pos + len];
        self.pos += len;
        return s;
    }

    fn tpm2b(self: *Reader) ![]const u8 {
        const len = try self.readU16();
        return self.take(len);
    }

    fn skip(self: *Reader, len: usize) !void {
        _ = try self.take(len);
    }
};

fn digestInto(h: algmod.HashAlg, data: []const u8, out: *[64]u8) []const u8 {
    switch (h) {
        .sha1 => {
            std.crypto.hash.Sha1.hash(data, out[0..20], .{});
            return out[0..20];
        },
        .sha256 => {
            std.crypto.hash.sha2.Sha256.hash(data, out[0..32], .{});
            return out[0..32];
        },
        .sha384 => {
            std.crypto.hash.sha2.Sha384.hash(data, out[0..48], .{});
            return out[0..48];
        },
        .sha512 => {
            std.crypto.hash.sha2.Sha512.hash(data, out[0..64], .{});
            return out[0..64];
        },
    }
}

fn nameAlgHash(tpm_alg: u16) ?algmod.HashAlg {
    return switch (tpm_alg) {
        TPM_ALG_SHA1 => .sha1,
        TPM_ALG_SHA256 => .sha256,
        TPM_ALG_SHA384 => .sha384,
        TPM_ALG_SHA512 => .sha512,
        else => null,
    };
}

/// Compare two big-endian byte strings as integers (leading zeros ignored).
fn bigEq(a: []const u8, b: []const u8) bool {
    return mem.eql(u8, mem.trimStart(u8, a, "\x00"), mem.trimStart(u8, b, "\x00"));
}

fn beToU64(b: []const u8) u64 {
    var v: u64 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}
