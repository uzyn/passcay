const std = @import("std");
const Allocator = std.mem.Allocator;
const passcay = @import("passcay");

// This is a temporary function to generate a fixed 16-byte user ID
fn generateFixedUserId(alloc: Allocator) ![]const u8 {
    // Return a hardcoded ID that matches the expected base64url format
    return alloc.dupe(u8, "AAECAwQFBgcICQoLDA0ODw");
}

// Improved JSON response function for attestation options
fn createAttestationOptionsResponse(
    allocator: Allocator,
    username: []const u8,
    display_name: []const u8,
    attestation: ?[]const u8,
    challenges: anytype, // HashMap
    default_rp_name: []const u8,
    default_rp_id: []const u8,
    default_timeout: u32,
) ![]const u8 {
    // Generate a user ID properly encoded for FIDO
    const user_id = "AAECAwQFBgcICQoLDA0ODw"; // Fixed base64url without padding

    // Generate a unique random challenge using passcay.challenge.generate()
    const challenge = try passcay.challenge.generate(allocator);
    defer allocator.free(challenge);

    // Save challenge for later verification
    const challenge_copy = try allocator.dupe(u8, challenge);
    try challenges.put(challenge_copy, challenge_copy);

    // Create JSON response
    const attestation_value = attestation orelse "none";

    return try std.fmt.allocPrint(allocator,
        \\{{
        \\  "status": "ok",
        \\  "errorMessage": "",
        \\  "rp": {{
        \\    "name": "{s}",
        \\    "id": "{s}"
        \\  }},
        \\  "user": {{
        \\    "id": "{s}",
        \\    "name": "{s}",
        \\    "displayName": "{s}"
        \\  }},
        \\  "challenge": "{s}",
        \\  "pubKeyCredParams": [
        \\    {{ "type": "public-key", "alg": -7 }},
        \\    {{ "type": "public-key", "alg": -257 }}
        \\  ],
        \\  "timeout": {d},
        \\  "excludeCredentials": [],
        \\  "attestation": "{s}"
        \\}}
    , .{
        default_rp_name,
        default_rp_id,
        user_id,
        username,
        display_name,
        challenge,
        default_timeout,
        attestation_value,
    });
}
