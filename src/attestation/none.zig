//! "none" attestation format (§8.7).
//!
//! No attestation is provided; the statement must be an empty map.

const std = @import("std");
const Allocator = std.mem.Allocator;
const zbor = @import("zbor");

const m = @import("mod.zig");

pub fn verify(allocator: Allocator, params: m.VerifyParams) !m.Result {
    _ = allocator;

    const di = zbor.DataItem.new(params.att_stmt) catch return m.Error.InvalidAttestationStatement;
    if (di.getType() != .Map) return m.Error.InvalidAttestationStatement;

    var it = di.map() orelse return m.Error.InvalidAttestationStatement;
    if (it.next() != null) return m.Error.InvalidAttestationStatement; // must be empty

    return .{ .type = .none };
}
