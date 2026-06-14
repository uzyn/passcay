//! FIDO Metadata Service (MDS3) trust store.
//!
//! Holds authenticator metadata keyed by AAGUID: the attestation root
//! certificates that anchor full-attestation chains, and the status reports
//! that gate whether an authenticator model is acceptable. Entries can be built
//! programmatically or parsed from MDS3 metadata-statement / BLOB-entry JSON.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    AaguidNotInMetadata,
    AuthenticatorCompromised,
    InvalidMetadata,
    BlobSignatureInvalid,
};

/// AuthenticatorStatus values from the FIDO Metadata Service.
pub const AuthenticatorStatus = enum {
    fido_certified,
    not_fido_certified,
    revoked,
    user_verification_bypass,
    attestation_key_compromise,
    user_key_remote_compromise,
    user_key_physical_compromise,
    update_available,
    self_assertion_submitted,
    unknown,

    pub fn fromString(s: []const u8) AuthenticatorStatus {
        const eql = std.mem.eql;
        if (eql(u8, s, "REVOKED")) return .revoked;
        if (eql(u8, s, "USER_VERIFICATION_BYPASS")) return .user_verification_bypass;
        if (eql(u8, s, "ATTESTATION_KEY_COMPROMISE")) return .attestation_key_compromise;
        if (eql(u8, s, "USER_KEY_REMOTE_COMPROMISE")) return .user_key_remote_compromise;
        if (eql(u8, s, "USER_KEY_PHYSICAL_COMPROMISE")) return .user_key_physical_compromise;
        if (eql(u8, s, "NOT_FIDO_CERTIFIED")) return .not_fido_certified;
        if (eql(u8, s, "UPDATE_AVAILABLE")) return .update_available;
        if (eql(u8, s, "SELF_ASSERTION_SUBMITTED")) return .self_assertion_submitted;
        if (std.mem.startsWith(u8, s, "FIDO_CERTIFIED")) return .fido_certified;
        return .unknown;
    }

    /// Whether this status means the authenticator must be rejected.
    pub fn isCompromised(self: AuthenticatorStatus) bool {
        return switch (self) {
            .revoked,
            .user_verification_bypass,
            .attestation_key_compromise,
            .user_key_remote_compromise,
            .user_key_physical_compromise,
            => true,
            else => false,
        };
    }
};

/// Attestation types a model may produce (FIDO MDS `attestationTypes`).
pub const AttType = enum {
    basic_full,
    basic_surrogate,
    attca,
    anonca,

    pub fn fromString(s: []const u8) ?AttType {
        const eql = std.mem.eql;
        if (eql(u8, s, "basic_full")) return .basic_full;
        if (eql(u8, s, "basic_surrogate")) return .basic_surrogate;
        if (eql(u8, s, "attca")) return .attca;
        if (eql(u8, s, "anonca")) return .anonca;
        return null; // ignore unknown/"none"
    }
};

pub const Entry = struct {
    aaguid: [16]u8,
    /// Attestation root certificates (DER) — trust anchors for this model.
    roots: []const []const u8,
    /// Status reports for this model.
    statuses: []const AuthenticatorStatus,
    /// Declared attestation types. Empty means unspecified (no enforcement).
    attestation_types: []const AttType = &.{},

    /// Whether the model is permitted to produce attestations of `kind`. An
    /// empty declaration permits any type.
    pub fn allows(entry: *const Entry, kind: AttType) bool {
        if (entry.attestation_types.len == 0) return true;
        for (entry.attestation_types) |t| {
            if (t == kind) return true;
        }
        return false;
    }
};

pub const Store = struct {
    entries: []const Entry,

    pub fn lookup(self: Store, aaguid: []const u8) ?*const Entry {
        if (aaguid.len != 16) return null;
        for (self.entries) |*e| {
            if (std.mem.eql(u8, &e.aaguid, aaguid)) return e;
        }
        return null;
    }

    /// Whether `kind` is permitted for `aaguid`, considering all matching
    /// entries. An unknown AAGUID, or one whose entries declare no types, is
    /// unrestricted; a known AAGUID is rejected only if no matching entry
    /// permits the type (robust to duplicate blob/local entries).
    pub fn attestationTypeAllowed(self: Store, aaguid: []const u8, kind: AttType) bool {
        if (aaguid.len != 16) return true;
        var known = false;
        for (self.entries) |*e| {
            if (!std.mem.eql(u8, &e.aaguid, aaguid)) continue;
            known = true;
            if (e.allows(kind)) return true;
        }
        return !known;
    }

    /// Reject if any status report marks the authenticator compromised.
    pub fn checkStatus(entry: *const Entry) !void {
        for (entry.statuses) |s| {
            if (s.isCompromised()) return Error.AuthenticatorCompromised;
        }
    }
};

// ---- JSON parsing of an MDS3 metadata statement / BLOB entry ----

const StatusReport = struct { status: []const u8 };
const Inner = struct {
    aaguid: ?[]const u8 = null,
    attestationRootCertificates: ?[]const []const u8 = null,
    attestationTypes: ?[]const []const u8 = null,
};
const Statement = struct {
    aaguid: ?[]const u8 = null,
    attestationRootCertificates: ?[]const []const u8 = null,
    statusReports: ?[]const StatusReport = null,
    attestationTypes: ?[]const []const u8 = null,
    metadataStatement: ?Inner = null,
};

/// Parse a single MDS3 metadata statement / BLOB entry JSON into an Entry.
/// Allocations are made in `arena` (caller owns the arena).
pub fn parseStatement(arena: Allocator, json: []const u8) !Entry {
    const s = std.json.parseFromSliceLeaky(Statement, arena, json, .{ .ignore_unknown_fields = true }) catch
        return Error.InvalidMetadata;
    return stmtToEntry(arena, s);
}

fn stmtToEntry(arena: Allocator, s: Statement) !Entry {
    const aaguid_str = s.aaguid orelse
        (if (s.metadataStatement) |ms| ms.aaguid else null) orelse return Error.InvalidMetadata;
    const roots_b64 = s.attestationRootCertificates orelse
        (if (s.metadataStatement) |ms| ms.attestationRootCertificates else null) orelse &.{};

    var aaguid: [16]u8 = undefined;
    try parseUuid(aaguid_str, &aaguid);

    var roots = std.array_list.Managed([]const u8).init(arena);
    for (roots_b64) |b64| {
        try roots.append(try decodeStdBase64(arena, b64));
    }

    var statuses = std.array_list.Managed(AuthenticatorStatus).init(arena);
    if (s.statusReports) |reports| {
        for (reports) |r| try statuses.append(AuthenticatorStatus.fromString(r.status));
    }

    const types_str = s.attestationTypes orelse
        (if (s.metadataStatement) |ms| ms.attestationTypes else null) orelse &.{};
    var atypes = std.array_list.Managed(AttType).init(arena);
    for (types_str) |t| {
        if (AttType.fromString(t)) |k| try atypes.append(k);
    }

    return Entry{
        .aaguid = aaguid,
        .roots = try roots.toOwnedSlice(),
        .statuses = try statuses.toOwnedSlice(),
        .attestation_types = try atypes.toOwnedSlice(),
    };
}

/// Parse a signed MDS3 metadata BLOB (a compact JWS/JWT). Verifies the blob
/// signature against the trust anchors (the MDS3 BLOB root), then parses the
/// `entries` array into Entries. Entries that lack an AAGUID (e.g. U2F) are
/// skipped. now_sec pins certificate time validity (null = lenient).
pub fn parseBlob(arena: Allocator, blob: []const u8, anchors: []const []const u8, now_sec: ?i64) ![]Entry {
    const jws = @import("../jws.zig");

    var parsed = jws.parse(arena, blob) catch return Error.InvalidMetadata;
    defer parsed.deinit();
    parsed.verify(arena, anchors, now_sec) catch return Error.BlobSignatureInvalid;

    const Payload = struct { entries: []const Statement = &.{} };
    const payload = std.json.parseFromSliceLeaky(Payload, arena, parsed.payload, .{ .ignore_unknown_fields = true }) catch
        return Error.InvalidMetadata;

    var entries = std.array_list.Managed(Entry).init(arena);
    for (payload.entries) |s| {
        const e = stmtToEntry(arena, s) catch continue; // skip entries without an AAGUID
        try entries.append(e);
    }
    return entries.toOwnedSlice();
}

fn parseUuid(s: []const u8, out: *[16]u8) !void {
    var n: usize = 0;
    var hi: ?u8 = null;
    for (s) |c| {
        if (c == '-') continue;
        const v = hexVal(c) orelse return Error.InvalidMetadata;
        if (hi) |h| {
            if (n >= 16) return Error.InvalidMetadata;
            out[n] = (h << 4) | v;
            n += 1;
            hi = null;
        } else {
            hi = v;
        }
    }
    if (n != 16 or hi != null) return Error.InvalidMetadata;
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn decodeStdBase64(allocator: Allocator, encoded: []const u8) ![]u8 {
    const dec = std.base64.standard.Decoder;
    const len = dec.calcSizeForSlice(encoded) catch return Error.InvalidMetadata;
    const out = try allocator.alloc(u8, len);
    dec.decode(out, encoded) catch return Error.InvalidMetadata;
    return out;
}

// ===================== Tests =====================

test "mds store lookup and status gating" {
    const aaguid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    const all_ff: [16]u8 = @splat(0xFF);
    const absent: [16]u8 = @splat(0xAB);
    const root = [_]u8{ 0x30, 0x00 };
    const ok_entry = Entry{ .aaguid = aaguid, .roots = &.{&root}, .statuses = &.{.fido_certified} };
    const bad_entry = Entry{ .aaguid = all_ff, .roots = &.{}, .statuses = &.{.revoked} };

    const store = Store{ .entries = &.{ ok_entry, bad_entry } };

    try std.testing.expect(store.lookup(&aaguid) != null);
    try std.testing.expect(store.lookup(&absent) == null);
    try Store.checkStatus(store.lookup(&aaguid).?);
    try std.testing.expectError(Error.AuthenticatorCompromised, Store.checkStatus(store.lookup(&all_ff).?));
}

test "mds parse a metadata BLOB entry JSON" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const json =
        \\{"aaguid":"01020304-0506-0708-0102-030405060708",
        \\ "statusReports":[{"status":"FIDO_CERTIFIED_L1"},{"status":"REVOKED"}],
        \\ "metadataStatement":{"attestationRootCertificates":["AQIDBA=="]}}
    ;
    const entry = try parseStatement(arena.allocator(), json);
    try std.testing.expectEqual([_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 }, entry.aaguid);
    try std.testing.expectEqual(@as(usize, 1), entry.roots.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, entry.roots[0]);
    try std.testing.expectEqual(AuthenticatorStatus.fido_certified, entry.statuses[0]);
    try std.testing.expectError(Error.AuthenticatorCompromised, Store.checkStatus(&entry));
}
