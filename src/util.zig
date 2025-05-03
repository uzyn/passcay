//! Utility functions for WebAuthn operations
//!
//! Common utilities for encoding/decoding, parsing, and data validation.

const std = @import("std");
const crypto = std.crypto;
const base64 = std.base64;
const mem = std.mem;
const Allocator = mem.Allocator;
const json = std.json;

// Direct import instead of going through root.zig
const types = @import("types.zig");

/// Base64URL decode a string to raw bytes
pub fn decodeBase64Url(allocator: Allocator, encoded: []const u8) ![]const u8 {
    const decoded_len = try base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);

    try base64.url_safe_no_pad.Decoder.decode(decoded, encoded);
    return decoded;
}

/// Encode raw bytes to base64url string
pub fn encodeBase64Url(allocator: Allocator, data: []const u8) ![]const u8 {
    const encoded_len = base64.url_safe_no_pad.Encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);

    _ = base64.url_safe_no_pad.Encoder.encode(encoded, data);
    return encoded;
}

pub fn parseClientDataJson(allocator: Allocator, client_data_json_b64: []const u8) !types.ClientData {
    var client_data_json_slice: []const u8 = undefined;
    var need_free = false;

    if (std.mem.indexOf(u8, client_data_json_b64, "{") == null) {
        const decoded = try decodeBase64Url(allocator, client_data_json_b64);
        client_data_json_slice = decoded;
        need_free = true;
    } else {
        client_data_json_slice = client_data_json_b64;
    }
    defer if (need_free) allocator.free(client_data_json_slice);

    var parsed_json = try json.parseFromSlice(types.ClientDataJson, allocator, client_data_json_slice, .{});
    defer parsed_json.deinit();

    const client_data = parsed_json.value;

    const type_copy = try allocator.dupe(u8, client_data.type);
    errdefer allocator.free(type_copy);

    const challenge_copy = try allocator.dupe(u8, client_data.challenge);
    errdefer allocator.free(challenge_copy);

    const origin_copy = try allocator.dupe(u8, client_data.origin);
    errdefer allocator.free(origin_copy);

    return types.ClientData{
        .type = type_copy,
        .challenge = challenge_copy,
        .origin = origin_copy,
    };
}

pub fn hasFlag(flags: u8, flag: types.AuthenticatorDataFlag) bool {
    return (flags & @intFromEnum(flag)) != 0;
}

test "base64url encoding/decoding" {
    const allocator = std.testing.allocator;
    const test_bytes = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    const encoded = try encodeBase64Url(allocator, &test_bytes);
    defer allocator.free(encoded);

    const decoded = try decodeBase64Url(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &test_bytes, decoded);
}

test "authenticator data flag checking" {
    const flags: u8 = 0x05; // UP and UV flags set

    try std.testing.expect(hasFlag(flags, .userPresent));
    try std.testing.expect(hasFlag(flags, .userVerified));
    try std.testing.expect(!hasFlag(flags, .attestedCredentialData));
}

test "parseClientDataJson memory management" {
    const allocator = std.testing.allocator;
    const test_json =
        \\{"type":"webauthn.get","challenge":"test_challenge","origin":"https://example.com"}
    ;

    var client_data = try parseClientDataJson(allocator, test_json);
    defer client_data.deinit(allocator);

    try std.testing.expectEqualStrings("webauthn.get", client_data.type);
    try std.testing.expectEqualStrings("test_challenge", client_data.challenge);
    try std.testing.expectEqualStrings("https://example.com", client_data.origin);
}
