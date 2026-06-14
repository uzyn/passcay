//! Central COSE algorithm registry.
//!
//! Single source of truth mapping COSE algorithm identifiers to the key kind,
//! curve, hash, and signature scheme needed to verify a signature. `supported`
//! indicates whether the algorithm is verifiable with the Zig standard library
//! alone (no vendored curve implementations).

const types = @import("types.zig");

pub const Curve = types.CoseCurve;

pub const KeyKind = enum { ec2, rsa, okp };

pub const HashAlg = enum { sha1, sha256, sha384, sha512 };

pub const SigScheme = enum { ecdsa, rsa_pkcs1, rsa_pss, eddsa };

/// COSE algorithm identifiers (RFC 9053 / IANA COSE registry).
pub const Alg = enum(i32) {
    es256 = -7,
    eddsa = -8,
    es384 = -35,
    es512 = -36,
    ps256 = -37,
    ps384 = -38,
    ps512 = -39,
    es256k = -47,
    rs256 = -257,
    rs384 = -258,
    rs512 = -259,
    rs1 = -65535,
    _,
};

pub const Descriptor = struct {
    alg: Alg,
    key_kind: KeyKind,
    curve: ?Curve,
    hash: HashAlg,
    scheme: SigScheme,
    /// Verifiable using only `std.crypto`. `false` for algorithms whose
    /// primitives are absent from the standard library (e.g. P-521/ES512).
    supported: bool,
};

/// Describe a COSE algorithm id, or null if it is not in the registry.
pub fn describe(alg_id: i32) ?Descriptor {
    return switch (alg_id) {
        -7 => .{ .alg = .es256, .key_kind = .ec2, .curve = .P256, .hash = .sha256, .scheme = .ecdsa, .supported = true },
        -8 => .{ .alg = .eddsa, .key_kind = .okp, .curve = .ED25519, .hash = .sha512, .scheme = .eddsa, .supported = true },
        -35 => .{ .alg = .es384, .key_kind = .ec2, .curve = .P384, .hash = .sha384, .scheme = .ecdsa, .supported = true },
        // ES512 uses NIST P-521, which std.crypto does not implement.
        -36 => .{ .alg = .es512, .key_kind = .ec2, .curve = .P521, .hash = .sha512, .scheme = .ecdsa, .supported = false },
        -37 => .{ .alg = .ps256, .key_kind = .rsa, .curve = null, .hash = .sha256, .scheme = .rsa_pss, .supported = true },
        -38 => .{ .alg = .ps384, .key_kind = .rsa, .curve = null, .hash = .sha384, .scheme = .rsa_pss, .supported = true },
        -39 => .{ .alg = .ps512, .key_kind = .rsa, .curve = null, .hash = .sha512, .scheme = .rsa_pss, .supported = true },
        -47 => .{ .alg = .es256k, .key_kind = .ec2, .curve = .SECP256K1, .hash = .sha256, .scheme = .ecdsa, .supported = true },
        -257 => .{ .alg = .rs256, .key_kind = .rsa, .curve = null, .hash = .sha256, .scheme = .rsa_pkcs1, .supported = true },
        -258 => .{ .alg = .rs384, .key_kind = .rsa, .curve = null, .hash = .sha384, .scheme = .rsa_pkcs1, .supported = true },
        -259 => .{ .alg = .rs512, .key_kind = .rsa, .curve = null, .hash = .sha512, .scheme = .rsa_pkcs1, .supported = true },
        -65535 => .{ .alg = .rs1, .key_kind = .rsa, .curve = null, .hash = .sha1, .scheme = .rsa_pkcs1, .supported = true },
        else => null,
    };
}

/// Whether the algorithm can be verified with std.crypto alone.
pub fn isSupported(alg_id: i32) bool {
    if (describe(alg_id)) |d| return d.supported;
    return false;
}

test "describe known algorithms" {
    const std = @import("std");
    try std.testing.expectEqual(KeyKind.ec2, describe(-7).?.key_kind);
    try std.testing.expectEqual(SigScheme.rsa_pkcs1, describe(-257).?.scheme);
    try std.testing.expect(!describe(-36).?.supported); // ES512 / P-521 unsupported
    try std.testing.expect(describe(1234) == null);
}
