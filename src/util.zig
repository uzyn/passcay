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

/// Raw clientDataJSON bytes. Base64url input is decoded into an owned buffer
/// (`owned` true, caller frees via deinit); raw JSON input is borrowed (`owned` false).
pub const ClientDataBytes = struct {
    bytes: []const u8,
    owned: bool,

    pub fn deinit(self: ClientDataBytes, allocator: Allocator) void {
        if (self.owned) allocator.free(self.bytes);
    }
};

/// Decode clientDataJSON exactly once. '{' is not in the base64url alphabet, so its
/// presence distinguishes raw JSON from base64url-encoded input.
pub fn decodeClientDataJson(allocator: Allocator, input: []const u8) !ClientDataBytes {
    if (std.mem.indexOf(u8, input, "{") == null) {
        return .{ .bytes = try decodeBase64Url(allocator, input), .owned = true };
    }
    return .{ .bytes = input, .owned = false };
}

/// Parse already-decoded raw clientDataJSON bytes into an owned ClientData.
pub fn parseClientDataJsonBytes(allocator: Allocator, json_bytes: []const u8) !types.ClientData {
    var parsed_json = try json.parseFromSlice(types.ClientDataJson, allocator, json_bytes, .{ .ignore_unknown_fields = true });
    defer parsed_json.deinit();

    const client_data = parsed_json.value;

    // If tokenBinding is present, its status must be a recognized value.
    // (A non-object tokenBinding or a missing status fail JSON parsing above.)
    if (client_data.tokenBinding) |tb| {
        if (!mem.eql(u8, tb.status, "present") and
            !mem.eql(u8, tb.status, "supported") and
            !mem.eql(u8, tb.status, "not-supported"))
        {
            return error.InvalidTokenBinding;
        }
    }

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

pub fn parseClientDataJson(allocator: Allocator, client_data_json_b64: []const u8) !types.ClientData {
    const cd = try decodeClientDataJson(allocator, client_data_json_b64);
    defer cd.deinit(allocator);
    return parseClientDataJsonBytes(allocator, cd.bytes);
}

pub fn hasFlag(flags: u8, flag: types.AuthenticatorDataFlag) bool {
    return (flags & @backingInt(flag)) != 0;
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

test "parseClientDataJson ignores unknown fields" {
    const allocator = std.testing.allocator;
    const test_json =
        \\{"type":"webauthn.get","challenge":"test_challenge","origin":"https://example.com","topOrigin":"https://example.com","other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}
    ;

    var client_data = try parseClientDataJson(allocator, test_json);
    defer client_data.deinit(allocator);

    try std.testing.expectEqualStrings("webauthn.get", client_data.type);
    try std.testing.expectEqualStrings("test_challenge", client_data.challenge);
    try std.testing.expectEqualStrings("https://example.com", client_data.origin);
}

test "decodeClientDataJson base64url vs raw" {
    const allocator = std.testing.allocator;
    const raw_json =
        \\{"type":"webauthn.get","challenge":"test_challenge","origin":"https://example.com"}
    ;

    const encoded = try encodeBase64Url(allocator, raw_json);
    defer allocator.free(encoded);

    const from_b64 = try decodeClientDataJson(allocator, encoded);
    defer from_b64.deinit(allocator);
    try std.testing.expect(from_b64.owned);
    try std.testing.expectEqualStrings(raw_json, from_b64.bytes);

    const from_raw = try decodeClientDataJson(allocator, raw_json);
    defer from_raw.deinit(allocator);
    try std.testing.expect(!from_raw.owned);
    try std.testing.expectEqual(raw_json.ptr, from_raw.bytes.ptr);
}
