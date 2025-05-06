//! FIDO2 Conformance Server Library
//!
//! This module contains shared types and utilities for the FIDO2
//! conformance test server.

const std = @import("std");
const json = std.json;
const testing = std.testing;

// Common types and structures used by the FIDO2 conformance API
pub const ServerResponse = struct {
    status: []const u8, // "ok" or "failed"
    errorMessage: []const u8 = "",

    pub fn init(status: []const u8, error_message: []const u8) ServerResponse {
        return .{
            .status = status,
            .errorMessage = error_message,
        };
    }

    pub fn success() ServerResponse {
        return .{
            .status = "ok",
            .errorMessage = "",
        };
    }

    pub fn failure(message: []const u8) ServerResponse {
        return .{
            .status = "failed",
            .errorMessage = message,
        };
    }
};

pub const PublicKeyCredentialRpEntity = struct {
    id: ?[]const u8 = null,
    name: []const u8,
};

pub const ServerPublicKeyCredentialUserEntity = struct {
    id: []const u8,
    name: []const u8,
    displayName: []const u8,
};

pub const PublicKeyCredentialDescriptor = struct {
    type: []const u8,
    id: []const u8,
    transports: ?[][]const u8 = null,
};

pub const ServerPublicKeyCredentialDescriptor = struct {
    type: []const u8,
    id: []const u8,
    transports: ?[][]const u8 = null,
};

pub const PublicKeyCredentialParameters = struct {
    type: []const u8,
    alg: i32,
};

pub const AuthenticatorSelectionCriteria = struct {
    authenticatorAttachment: ?[]const u8 = null,
    requireResidentKey: ?bool = null,
    residentKey: ?[]const u8 = null,
    userVerification: ?[]const u8 = null,
};

pub const AuthenticationExtensionsClientInputs = struct {
    credProps: ?bool = null,
};

// Registration types
pub const ServerPublicKeyCredentialCreationOptionsRequest = struct {
    username: []const u8,
    displayName: []const u8,
    authenticatorSelection: ?AuthenticatorSelectionCriteria = null,
    attestation: ?[]const u8 = null,
    extensions: ?AuthenticationExtensionsClientInputs = null,
};

pub const ServerPublicKeyCredentialCreationOptionsResponse = struct {
    status: []const u8 = "ok",
    errorMessage: []const u8 = "",
    rp: PublicKeyCredentialRpEntity,
    user: ServerPublicKeyCredentialUserEntity,
    challenge: []const u8,
    pubKeyCredParams: []const PublicKeyCredentialParameters,
    timeout: ?u32 = null,
    excludeCredentials: ?[]const ServerPublicKeyCredentialDescriptor = null,
    authenticatorSelection: ?AuthenticatorSelectionCriteria = null,
    attestation: ?[]const u8 = null,
    extensions: ?AuthenticationExtensionsClientInputs = null,
};

pub const ServerAuthenticatorResponse = struct {
    clientDataJSON: []const u8,
};

pub const ServerAuthenticatorAttestationResponse = struct {
    clientDataJSON: []const u8,
    attestationObject: []const u8,
    transports: ?[][]const u8 = null,
    publicKeyAlgorithm: ?i32 = null,
    publicKey: ?[]const u8 = null,
    authenticatorData: ?[]const u8 = null,
};

pub const ServerPublicKeyCredential = struct {
    id: []const u8,
    rawId: []const u8,
    response: ServerAuthenticatorAttestationResponse,
    getClientExtensionResults: std.json.Value = std.json.Value{ .object = std.json.ObjectMap.init(std.heap.page_allocator) },
    type: []const u8,
    clientExtensionResults: ?std.json.Value = null,
    authenticatorAttachment: ?[]const u8 = null,
};

// Authentication types
pub const ServerPublicKeyCredentialGetOptionsRequest = struct {
    username: []const u8,
    userVerification: ?[]const u8 = null,
    extensions: ?AuthenticationExtensionsClientInputs = null,
};

pub const ServerPublicKeyCredentialGetOptionsResponse = struct {
    status: []const u8 = "ok",
    errorMessage: []const u8 = "",
    challenge: []const u8,
    timeout: ?u32 = null,
    rpId: ?[]const u8 = null,
    allowCredentials: ?[]const ServerPublicKeyCredentialDescriptor = null,
    userVerification: ?[]const u8 = null,
    extensions: ?AuthenticationExtensionsClientInputs = null,
};

pub const ServerAuthenticatorAssertionResponse = struct {
    clientDataJSON: []const u8,
    authenticatorData: []const u8,
    signature: []const u8,
    userHandle: []const u8,
};

pub const ServerPublicKeyCredentialAssertion = struct {
    id: []const u8,
    rawId: []const u8,
    response: ServerAuthenticatorAssertionResponse,
    getClientExtensionResults: std.json.Value = std.json.Value{ .object = std.json.ObjectMap.init(std.heap.page_allocator) },
    type: []const u8,
    clientExtensionResults: ?std.json.Value = null,
    authenticatorAttachment: ?[]const u8 = null,
};

// User credential storage (in-memory for this implementation)
pub const UserCredential = struct {
    username: []const u8,
    displayName: []const u8,
    id: []const u8,
    credential_id: []const u8,
    public_key: []const u8,
    sign_count: u32,
};

// Utility functions for JSON encoding/decoding
pub fn jsonStringify(
    value: anytype,
    options: json.StringifyOptions,
    writer: anytype,
) !void {
    try json.stringify(value, options, writer);
}

pub fn jsonParse(comptime T: type, allocator: std.mem.Allocator, input: []const u8) !T {
    var parsed = try std.json.parseFromSlice(T, allocator, input, .{});
    defer parsed.deinit();
    return parsed.value;
}

test "basic ServerResponse functionality" {
    try testing.expectEqualStrings("ok", ServerResponse.success().status);
    try testing.expectEqualStrings("", ServerResponse.success().errorMessage);

    const err_response = ServerResponse.failure("Test error");
    try testing.expectEqualStrings("failed", err_response.status);
    try testing.expectEqualStrings("Test error", err_response.errorMessage);
}
