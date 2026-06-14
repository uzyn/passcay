//! Compact JWS / JWT parsing and verification.
//!
//! Used for the FIDO MDS3 metadata BLOB (a JWT signed with an x5c chain) and,
//! later, android-safetynet. The signing input is the ASCII
//! "<header_b64url>.<payload_b64url>"; the signature is verified with the leaf
//! certificate from the protected header's x5c, and the chain is validated to a
//! trust anchor.

const std = @import("std");
const Allocator = std.mem.Allocator;

const util = @import("util.zig");
const x509 = @import("x509/mod.zig");

pub const Error = error{
    InvalidJws,
    UnsupportedJwsAlg,
    JwsSignatureInvalid,
    JwsChainUntrusted,
    NoX5c,
};

pub const Jws = struct {
    arena: std.heap.ArenaAllocator,
    /// Decoded protected header JSON.
    header: []const u8,
    /// Decoded payload JSON.
    payload: []const u8,
    /// Decoded signature bytes.
    signature: []const u8,
    /// ASCII signing input ("<header>.<payload>"), owned.
    signing_input: []const u8,
    /// JOSE `alg` (e.g. "RS256").
    alg: []const u8,
    /// x5c certificate chain (DER, leaf first), owned.
    x5c: []const []const u8,

    pub fn deinit(self: *Jws) void {
        self.arena.deinit();
    }

    /// Verify the JWS signature using its x5c leaf certificate, and validate the
    /// chain to a trust anchor (empty anchors: no root-of-trust enforcement).
    pub fn verify(self: *const Jws, allocator: Allocator, anchors_der: []const []const u8, now_sec: ?i64) !void {
        if (self.x5c.len == 0) return Error.NoX5c;
        const alg_id = joseAlgToCose(self.alg) orelse return Error.UnsupportedJwsAlg;

        const leaf = x509.parse(self.x5c[0]) catch return Error.JwsSignatureInvalid;
        // JOSE encodes ECDSA signatures as raw r‖s (not DER).
        const ok = x509.verifyDataFmt(leaf, alg_id, self.signature, self.signing_input, .raw) catch
            return Error.UnsupportedJwsAlg;
        if (!ok) return Error.JwsSignatureInvalid;

        x509.verifyChain(allocator, self.x5c, anchors_der, now_sec) catch return Error.JwsChainUntrusted;
    }
};

const Header = struct {
    alg: []const u8,
    x5c: ?[]const []const u8 = null,
};

/// Parse a compact JWS. The returned Jws owns its memory via an internal arena.
pub fn parse(allocator: Allocator, compact: []const u8) !Jws {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const dot1 = std.mem.indexOfScalar(u8, compact, '.') orelse return Error.InvalidJws;
    const dot2 = std.mem.lastIndexOfScalar(u8, compact, '.') orelse return Error.InvalidJws;
    if (dot2 <= dot1) return Error.InvalidJws;

    const header = try util.decodeBase64Url(a, compact[0..dot1]);
    const payload = try util.decodeBase64Url(a, compact[dot1 + 1 .. dot2]);
    const signature = try util.decodeBase64Url(a, compact[dot2 + 1 ..]);
    const signing_input = try a.dupe(u8, compact[0..dot2]);

    const hdr = std.json.parseFromSliceLeaky(Header, a, header, .{ .ignore_unknown_fields = true }) catch
        return Error.InvalidJws;

    // x5c entries are standard (not URL-safe) base64-encoded DER certificates.
    var x5c_list = std.array_list.Managed([]const u8).init(a);
    if (hdr.x5c) |entries| {
        for (entries) |entry| {
            const der = try decodeStdBase64(a, entry);
            try x5c_list.append(der);
        }
    }

    return Jws{
        .arena = arena,
        .header = header,
        .payload = payload,
        .signature = signature,
        .signing_input = signing_input,
        .alg = try a.dupe(u8, hdr.alg),
        .x5c = try x5c_list.toOwnedSlice(),
    };
}

fn joseAlgToCose(alg: []const u8) ?i32 {
    const eql = std.mem.eql;
    if (eql(u8, alg, "RS256")) return -257;
    if (eql(u8, alg, "RS384")) return -258;
    if (eql(u8, alg, "RS512")) return -259;
    if (eql(u8, alg, "ES256")) return -7;
    if (eql(u8, alg, "ES384")) return -35;
    if (eql(u8, alg, "PS256")) return -37;
    if (eql(u8, alg, "PS384")) return -38;
    if (eql(u8, alg, "PS512")) return -39;
    if (eql(u8, alg, "EdDSA")) return -8;
    return null;
}

fn decodeStdBase64(allocator: Allocator, encoded: []const u8) ![]u8 {
    const dec = std.base64.standard.Decoder;
    const len = dec.calcSizeForSlice(encoded) catch return Error.InvalidJws;
    const out = try allocator.alloc(u8, len);
    dec.decode(out, encoded) catch return Error.InvalidJws;
    return out;
}

// ===================== Tests =====================

const mds_test_jwt = @embedFile("testdata/mds_test.jwt");

test "jws parse and verify a real RS256 JWT with x5c (self-signed)" {
    const a = std.testing.allocator;
    var jws = try parse(a, mds_test_jwt);
    defer jws.deinit();

    try std.testing.expectEqualStrings("RS256", jws.alg);
    try std.testing.expectEqual(@as(usize, 1), jws.x5c.len);

    // Signature verifies against the embedded leaf; self-signed chain accepted
    // (empty anchors) and also when the leaf is supplied as its own anchor.
    try jws.verify(a, &.{}, null);
    try jws.verify(a, &.{jws.x5c[0]}, null);
}

test "jws rejects a tampered payload" {
    const a = std.testing.allocator;
    const tampered = try a.dupe(u8, mds_test_jwt);
    defer a.free(tampered);
    // Flip a character in the payload segment (between the two dots).
    const d1 = std.mem.indexOfScalar(u8, tampered, '.').?;
    tampered[d1 + 5] = if (tampered[d1 + 5] == 'A') 'B' else 'A';

    var jws = try parse(a, tampered);
    defer jws.deinit();
    try std.testing.expectError(Error.JwsSignatureInvalid, jws.verify(a, &.{}, null));
}
