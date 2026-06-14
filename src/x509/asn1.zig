//! Minimal ASN.1 DER helpers built on std.crypto.Certificate.der.
//!
//! std parses only the X.509 extensions it recognises and silently skips the
//! rest, so attestation formats that carry custom extensions (FIDO AAGUID,
//! Android key attestation, Apple nonce, TPM) need a way to fetch an extension
//! by OID. This walks the certificate's TBS extensions directly.

const std = @import("std");
const der = std.crypto.Certificate.der;

pub const Element = der.Element;

pub fn parse(bytes: []const u8, index: u32) !Element {
    return der.Element.parse(bytes, index);
}

fn tagNum(e: Element) u5 {
    return @intFromEnum(e.identifier.tag);
}

/// Find an X.509v3 extension by its OID content bytes (the bytes inside the
/// OBJECT IDENTIFIER value, e.g. `2B 06 01 04 01 82 E5 1C 01 01 04` for the
/// FIDO AAGUID extension). Returns the extnValue OCTET STRING contents, or null.
pub fn findExtension(cert_der: []const u8, oid_content: []const u8) !?[]const u8 {
    const cert = try parse(cert_der, 0); // Certificate SEQUENCE
    const tbs = try parse(cert_der, cert.slice.start); // TBSCertificate SEQUENCE

    // Locate the extensions [3] context-specific element among the TBS fields.
    var i = tbs.slice.start;
    var extensions: ?Element = null;
    while (i < tbs.slice.end) {
        const e = try parse(cert_der, i);
        if (e.identifier.class == .context_specific and tagNum(e) == 3) {
            extensions = e;
            break;
        }
        i = e.slice.end;
    }
    const ext_ctx = extensions orelse return null;

    // Inside [3] is a SEQUENCE OF Extension.
    const ext_seq = try parse(cert_der, ext_ctx.slice.start);
    var j = ext_seq.slice.start;
    while (j < ext_seq.slice.end) {
        const ext = try parse(cert_der, j); // Extension SEQUENCE
        j = ext.slice.end;

        const oid_elem = try parse(cert_der, ext.slice.start); // extnID OBJECT IDENTIFIER
        const oid_bytes = cert_der[oid_elem.slice.start..oid_elem.slice.end];

        // Next is either critical BOOLEAN (skip) or extnValue OCTET STRING.
        var value_elem = try parse(cert_der, oid_elem.slice.end);
        if (value_elem.identifier.class == .universal and tagNum(value_elem) == @intFromEnum(der.Tag.boolean)) {
            value_elem = try parse(cert_der, value_elem.slice.end);
        }

        if (std.mem.eql(u8, oid_bytes, oid_content)) {
            return cert_der[value_elem.slice.start..value_elem.slice.end];
        }
    }
    return null;
}

// Common OID content bytes (the value inside the OBJECT IDENTIFIER TLV).
pub const oid = struct {
    /// 2.5.29.19 basicConstraints
    pub const basic_constraints = &[_]u8{ 0x55, 0x1D, 0x13 };
    /// 2.5.29.37 extKeyUsage
    pub const ext_key_usage = &[_]u8{ 0x55, 0x1D, 0x25 };
    /// 1.3.6.1.4.1.45724.1.1.4 id-fido-gen-ce-aaguid
    pub const fido_aaguid = &[_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x01, 0x01, 0x04 };
    /// 1.3.6.1.4.1.45724.2.1.1 id-fido-u2f-ce-transports
    pub const fido_u2f_transports = &[_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x02, 0x01, 0x01 };
    /// 1.3.6.1.4.1.11129.2.1.17 Android key attestation
    pub const android_key_attestation = &[_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11 };
    /// 1.2.840.113635.100.8.2 Apple anonymous attestation nonce
    pub const apple_nonce = &[_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x08, 0x02 };
    /// 2.5.29.17 subjectAltName
    pub const subject_alt_name = &[_]u8{ 0x55, 0x1D, 0x11 };
    /// 2.5.29.31 cRLDistributionPoints
    pub const crl_distribution_points = &[_]u8{ 0x55, 0x1D, 0x1F };
    /// 2.23.133.8.3 tcg-kp-AIKCertificate (TPM attestation EKU)
    pub const tcg_kp_aik = &[_]u8{ 0x67, 0x81, 0x05, 0x08, 0x03 };
    /// 2.23.133.2.1 tcg-at-tpmManufacturer
    pub const tcg_tpm_manufacturer = &[_]u8{ 0x67, 0x81, 0x05, 0x02, 0x01 };
    /// 2.23.133.2.2 tcg-at-tpmModel
    pub const tcg_tpm_model = &[_]u8{ 0x67, 0x81, 0x05, 0x02, 0x02 };
    /// 2.23.133.2.3 tcg-at-tpmVersion
    pub const tcg_tpm_version = &[_]u8{ 0x67, 0x81, 0x05, 0x02, 0x03 };
};
