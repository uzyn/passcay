const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;

pub const DEFAULT_CHALLENGE_SIZE: usize = 32;

/// Generate a cryptographically secure 32-byte random challenge for WebAuthn operations
/// Returns base64url-encoded string that can be sent to the client
pub fn generate(allocator: std.mem.Allocator) ![]const u8 {
    return generateWithSize(allocator, DEFAULT_CHALLENGE_SIZE);
}

/// Generate a challenge with a specific size in bytes
/// Returns base64url-encoded string that can be sent to the client
pub fn generateWithSize(allocator: std.mem.Allocator, size: usize) ![]const u8 {
    const random_bytes = try allocator.alloc(u8, size);
    defer allocator.free(random_bytes);

    crypto.random.bytes(random_bytes);

    const encoded_size = base64.url_safe_no_pad.Encoder.calcSize(random_bytes.len);
    const encoded = try allocator.alloc(u8, encoded_size);

    _ = base64.url_safe_no_pad.Encoder.encode(encoded, random_bytes);

    return encoded;
}

test "fixed 32-byte challenge generation" {
    const allocator = std.testing.allocator;
    const challenge2 = try generate(allocator);
    defer allocator.free(challenge2);
    try std.testing.expectEqual(@as(usize, 43), challenge2.len);
}

test "variable size challenge generation" {
    const allocator = std.testing.allocator;

    const challenge = try generate(allocator);
    defer allocator.free(challenge);
    try std.testing.expectEqual(@as(usize, 43), challenge.len);

    const challenge_64 = try generateWithSize(allocator, 64);
    defer allocator.free(challenge_64);

    // Calculate the expected size correctly based on the Base64 encoding
    const expected_size = base64.url_safe_no_pad.Encoder.calcSize(64);
    try std.testing.expectEqual(expected_size, challenge_64.len);
}
