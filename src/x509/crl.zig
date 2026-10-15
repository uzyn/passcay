//! X.509 Certificate Revocation List (CRL) parsing and revocation checks.
//!
//! Used to honour the FIDO Metadata Service requirement that an MDS3 BLOB's
//! signing chain must not contain a revoked certificate. The CRL location is
//! read from a certificate's cRLDistributionPoints extension; the fetched CRL
//! is parsed for revoked serial numbers and (best effort) verified against its
//! issuer's public key.

const std = @import("std");
const mem = std.mem;

const asn1 = @import("asn1.zig");
const x509 = @import("mod.zig");
const alg = @import("../alg.zig");

pub const Error = error{ CrlParseFailed, CrlUnsupportedAlgorithm };

/// A parsed CRL. All slices borrow into the `der` passed to `parse`.
pub const Crl = struct {
    der: []const u8,
    /// Raw tbsCertList element (the signed bytes).
    tbs: []const u8,
    /// signatureAlgorithm OID content bytes.
    sig_alg_oid: []const u8,
    /// signatureValue (BIT STRING content minus the unused-bits byte).
    signature: []const u8,
    /// revokedCertificates SEQUENCE content range within `der` (empty if absent).
    revoked_start: u32,
    revoked_end: u32,

    /// Whether `serial` (DER INTEGER content) appears in revokedCertificates.
    pub fn isRevoked(self: Crl, serial: []const u8) bool {
        var i: u32 = self.revoked_start;
        while (i < self.revoked_end) {
            const entry = asn1.parse(self.der, i) catch return false;
            i = entry.slice.end;
            const sn = asn1.parse(self.der, entry.slice.start) catch continue;
            const sn_bytes = self.der[sn.slice.start..sn.slice.end];
            if (bigEq(sn_bytes, serial)) return true;
        }
        return false;
    }

    /// Verify the CRL signature with `issuer`'s public key. Errors if the
    /// signature algorithm is not supported; returns whether the signature is
    /// valid otherwise.
    pub fn verifiedBy(self: Crl, issuer: x509.Cert) !bool {
        const cose = sigAlgToCose(self.sig_alg_oid) orelse return Error.CrlUnsupportedAlgorithm;
        return x509.verifyData(issuer, cose, self.signature, self.tbs) catch Error.CrlUnsupportedAlgorithm;
    }
};

/// Parse a DER-encoded CRL (CertificateList).
pub fn parse(der: []const u8) !Crl {
    const list = asn1.parse(der, 0) catch return Error.CrlParseFailed; // CertificateList SEQUENCE
    const tbs_elem = asn1.parse(der, list.slice.start) catch return Error.CrlParseFailed; // tbsCertList
    const tbs = der[list.slice.start..tbs_elem.slice.end];

    const sig_alg = asn1.parse(der, tbs_elem.slice.end) catch return Error.CrlParseFailed; // AlgorithmIdentifier
    const oid = asn1.parse(der, sig_alg.slice.start) catch return Error.CrlParseFailed; // OBJECT IDENTIFIER
    const sig_alg_oid = der[oid.slice.start..oid.slice.end];

    const sig_val = asn1.parse(der, sig_alg.slice.end) catch return Error.CrlParseFailed; // BIT STRING
    if (sig_val.slice.end <= sig_val.slice.start) return Error.CrlParseFailed;
    const signature = der[sig_val.slice.start + 1 .. sig_val.slice.end]; // skip unused-bits byte

    // Locate revokedCertificates within tbsCertList by walking its fields:
    //   [version] signature issuer thisUpdate [nextUpdate] [revokedCertificates] ...
    var revoked_start: u32 = 0;
    var revoked_end: u32 = 0;
    {
        var i = tbs_elem.slice.start;
        const end = tbs_elem.slice.end;
        var e = asn1.parse(der, i) catch return Error.CrlParseFailed;
        // version (optional INTEGER)
        if (isUniversal(e, 2)) {
            i = e.slice.end;
            e = asn1.parse(der, i) catch return Error.CrlParseFailed;
        }
        i = e.slice.end; // skip signature AlgorithmIdentifier
        e = asn1.parse(der, i) catch return Error.CrlParseFailed;
        i = e.slice.end; // skip issuer Name
        e = asn1.parse(der, i) catch return Error.CrlParseFailed;
        i = e.slice.end; // skip thisUpdate Time
        if (i < end) {
            e = asn1.parse(der, i) catch return Error.CrlParseFailed;
            // nextUpdate (optional Time: UTCTime 23 / GeneralizedTime 24)
            if (isUniversal(e, 23) or isUniversal(e, 24)) {
                i = e.slice.end;
                if (i < end) e = asn1.parse(der, i) catch return Error.CrlParseFailed;
            }
            // revokedCertificates (optional SEQUENCE) — distinguished from the
            // crlExtensions [0] context tag by being a universal SEQUENCE.
            if (i < end and isUniversal(e, 16)) {
                revoked_start = e.slice.start;
                revoked_end = e.slice.end;
            }
        }
    }

    return .{
        .der = der,
        .tbs = tbs,
        .sig_alg_oid = sig_alg_oid,
        .signature = signature,
        .revoked_start = revoked_start,
        .revoked_end = revoked_end,
    };
}

/// Extract a certificate's serialNumber (DER INTEGER content bytes).
pub fn serialNumber(cert_der: []const u8) ![]const u8 {
    const cert = asn1.parse(cert_der, 0) catch return Error.CrlParseFailed;
    const tbs = asn1.parse(cert_der, cert.slice.start) catch return Error.CrlParseFailed;
    var e = asn1.parse(cert_der, tbs.slice.start) catch return Error.CrlParseFailed;
    // Skip the optional [0] version.
    if (e.identifier.class == .context_specific and @backingInt(e.identifier.tag) == 0) {
        e = asn1.parse(cert_der, e.slice.end) catch return Error.CrlParseFailed;
    }
    return cert_der[e.slice.start..e.slice.end];
}

/// First HTTP(S) CRL distribution point URL in a certificate, or null.
pub fn distributionUrl(cert_der: []const u8) ?[]const u8 {
    const ext = (asn1.findExtension(cert_der, asn1.oid.crl_distribution_points) catch return null) orelse return null;
    // The URL is a GeneralName [6] (uniformResourceIdentifier), an IA5String
    // carried with the context-primitive tag 0x86 somewhere inside the nested
    // DistributionPoint structure.
    var i: u32 = 0;
    while (i < ext.len) : (i += 1) {
        if (ext[i] != 0x86) continue;
        const e = asn1.parse(ext, i) catch continue;
        if (e.identifier.class != .context_specific or @backingInt(e.identifier.tag) != 6) continue;
        const url = ext[e.slice.start..e.slice.end];
        if (mem.startsWith(u8, url, "http")) return url;
    }
    return null;
}

fn isUniversal(e: asn1.Element, tag: u5) bool {
    return e.identifier.class == .universal and @backingInt(e.identifier.tag) == tag;
}

/// Compare two big-endian byte strings as integers (leading zeros ignored).
fn bigEq(a: []const u8, b: []const u8) bool {
    return mem.eql(u8, mem.trimStart(u8, a, "\x00"), mem.trimStart(u8, b, "\x00"));
}

/// Map a signature-algorithm OID (content bytes) to a COSE algorithm id.
fn sigAlgToCose(oid: []const u8) ?i32 {
    const eql = mem.eql;
    // PKCS#1: 1.2.840.113549.1.1.{5,11,12,13} (sha1/256/384/512 WithRSA).
    if (eql(u8, oid, &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 })) return -65535; // RS1
    if (eql(u8, oid, &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B })) return -257; // RS256
    if (eql(u8, oid, &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C })) return -258; // RS384
    if (eql(u8, oid, &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D })) return -259; // RS512
    // ECDSA: 1.2.840.10045.4.3.{2,3} (sha256/384).
    if (eql(u8, oid, &.{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 })) return -7; // ES256
    if (eql(u8, oid, &.{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 })) return -35; // ES384
    return null;
}

// ===================== Tests =====================

const test_crl = @embedFile("../testdata/test_crl.der");
const test_crl_ca = @embedFile("../testdata/test_crl_ca.der");

test "crl parse, revocation membership, and issuer signature verification" {
    const crl = try parse(test_crl);

    // Serial 0x2001 is revoked; 0x2002 is not.
    try std.testing.expect(crl.isRevoked(&.{ 0x20, 0x01 }));
    try std.testing.expect(!crl.isRevoked(&.{ 0x20, 0x02 }));
    // Leading-zero-insensitive comparison.
    try std.testing.expect(crl.isRevoked(&.{ 0x00, 0x20, 0x01 }));

    // CRL is RSA/SHA-256 signed by the embedded test CA.
    const ca = try x509.parse(test_crl_ca);
    try std.testing.expect(try crl.verifiedBy(ca));
}

test "crl serialNumber extraction" {
    // The test CA certificate's own serial round-trips through serialNumber.
    const sn = try serialNumber(test_crl_ca);
    try std.testing.expect(sn.len > 0);
}
