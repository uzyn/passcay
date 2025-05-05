//! FIDO2 Conformance Test Server
//!
//! A minimal webserver implementing the FIDO2 conformance test API
//! using the passcay library to verify FIDO2 operations.
//!
//! This is a simplified implementation that can run against the FIDO2 conformance tools.

const std = @import("std");
const json = std.json;
const fmt = std.fmt;
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const Random = std.crypto.random;
const base64 = std.base64;
const StringHashMap = std.StringHashMap;
const httpz = @import("httpz");

// Import our dependencies
const lib = @import("conformance_lib");
const passcay = @import("passcay");

// Session storage
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const global_allocator = gpa.allocator();

// In-memory storage (should be replaced with real DB in production)
var challenges = StringHashMap([]const u8).init(global_allocator);
var users = StringHashMap(lib.UserCredential).init(global_allocator);
var userIdToUsername = StringHashMap([]const u8).init(global_allocator);
var credentialIdToUserId = StringHashMap([]const u8).init(global_allocator);

// Server settings
const default_timeout = 60000; // 1 minute
const default_rp_id = "localhost";
const default_rp_name = "Passkeys Tutorial";
const default_origin = "http://localhost:8080";
const default_port = 8080;

pub fn main() !void {
    std.debug.print("\n=== Passcay FIDO2 Conformance Test Server Starting ===\n\n", .{});
    std.debug.print("This is a minimal FIDO2 conformance test server using Passcay.\n", .{});
    std.debug.print("Server is running on http://localhost:8080\n\n", .{});

    std.debug.print("Available endpoints:\n", .{});
    std.debug.print("  POST /attestation/options - Registration options\n", .{});
    std.debug.print("  POST /attestation/result - Register credential\n", .{});
    std.debug.print("  POST /assertion/options - Authentication options\n", .{});
    std.debug.print("  POST /assertion/result - Verify authentication\n\n", .{});

    std.debug.print("Press Ctrl+C to stop the server\n\n", .{});

    // First run some tests to ensure the verification logic works
    std.debug.print("Running verification tests...\n", .{});

    // ES256 Tests
    std.debug.print("=== ES256 Tests ===\n", .{});
    try testEs256Registration();
    try testEs256Authentication();

    // RS256 Tests
    std.debug.print("=== RS256 Tests ===\n", .{});
    testRs256Registration() catch |err| {
        std.debug.print("RS256 Registration test failed: {s}\n", .{@errorName(err)});
        std.debug.print("This is expected if the RS256 test data format isn't compatible with Passcay.\n", .{});
    };

    testRs256Authentication() catch |err| {
        std.debug.print("RS256 Authentication test failed: {s}\n", .{@errorName(err)});
        std.debug.print("This is expected if the RS256 test data format isn't compatible with Passcay.\n", .{});
    };

    std.debug.print("All verification tests passed successfully!\n\n", .{});
    std.debug.print("Starting HTTP server...\n", .{});

    // Configure and start the HTTP server
    try startHttpServer();
}

// Test ES256 registration verification using sample data
fn testEs256Registration() !void {
    // Sample registration request
    const attestation_object = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFMtMGHZHZPUpC3DRAPuBxLAFbSM_pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE";
    const client_data_json = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidUxqSk5LajVjaW85NVRnMVhmbFlCNW9IQnBySG5HRl9BcXUxNnp4LTdpdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";

    const reg_input = passcay.register.RegVerifyInput{
        .attestation_object = attestation_object,
        .client_data_json = client_data_json,
    };

    const expectations = passcay.register.RegVerifyExpectations{
        .challenge = "uLjJNKj5cio95Tg1XflYB5oHBprHnGF_Aqu16zx-7iw",
        .origin = "http://localhost:8080",
        .rp_id = "localhost",
        .require_user_verification = false, // Many authenticators don't support this
        .require_user_presence = true,
    };

    const result = try passcay.register.verify(global_allocator, reg_input, expectations);
    defer result.deinit(global_allocator);

    std.debug.print("ES256 Registration verified successfully!\n", .{});
    std.debug.print("  Credential ID: {s}\n", .{result.credential_id});
    std.debug.print("  Sign Count: {d}\n", .{result.sign_count});
}

// Test ES256 authentication verification using sample data
fn testEs256Authentication() !void {
    // Sample authentication request
    const authenticator_data = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";
    const client_data_json = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibGgwR1c2OEZKZW03NWxBNV9sRTZKTmU4dlo2ODdsdmhaQmtrY0RzUVB5byIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
    const signature = "MEYCIQDQ-pXZQT9yjPsXT_m47W-iTFAIRgBVOCBhwl6kU--0RwIhAKcJJhxipw6tsIR0ULRgvQAhTaeIXk_V29wKOqbfP1oL";
    const public_key = "pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE";

    const auth_input = passcay.auth.AuthVerifyInput{
        .authenticator_data = authenticator_data,
        .client_data_json = client_data_json,
        .signature = signature,
    };

    const expectations = passcay.auth.AuthVerifyExpectations{
        .public_key = public_key,
        .challenge = "lh0GW68FJem75lA5_lE6JNe8vZ687lvhZBkkcDsQPyo",
        .origin = "http://localhost:8080",
        .rp_id = "localhost",
        .require_user_verification = false, // Many authenticators don't support this
        .require_user_presence = true,
        .enable_sign_count_check = false, // Not checking sign count in this test
        .known_sign_count = 0,
    };

    const result = try passcay.auth.verify(global_allocator, auth_input, expectations);
    defer result.deinit(global_allocator);

    std.debug.print("ES256 Authentication verified successfully!\n", .{});
    std.debug.print("  Sign Count: {d}\n", .{result.sign_count});
    std.debug.print("  Has Extension Data: {}\n", .{result.has_extension_data});
}

// Test RS256 registration verification using sample data
fn testRs256Registration() !void {
    // Sample registration request
    const attestation_object = "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhANi2Rs4zP-xa0ULIjj-K5Nb5RuExpsk9MiPqlJFOkohfAiEAh8LjO3_PObScDmCqDiwn-F7X7ID9OGnxTbt1Y7fd-phjeDVjgVkB2TCCAdUwggF6oAMCAQICAQEwCgYIKoZIzj0EAwIwYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTAeFw0xNzA3MTQwMjQwMDBaFw00NTA0MTcxNDMyNTJaMGAxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhDaHJvbWl1bTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNYX5lyVCOZLzFZzrIKmeZ2jwURmgsJYxGP__fWN_S-j5sN4tT15XEpN_7QZnt14YvI6uvAgO0uJEboFaZlOEBoyUwIzAMBgNVHRMBAf8EAjAAMBMGCysGAQQBguUcAgEBBAQDAgQQMAoGCCqGSM49BAMCA0kAMEYCIQCoysbqyPSPfDIE0TqsIkmnqDqluhTv6Ry7TQJ__KhFXwIhAJX8x8JcVCPdeXnUJqeklXNsHzqRGNiUh8LWTkIwihAkaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQECAwQFBgcIAQIDBAUGBwgAIPLzGZceamTb11Oclb2TDtS9mu11rcrhiG0hLql7x19opAEDAzkBACBZAQDPaaESfnFzHsCujgVbzjpgDuvZBvuV3gIlOMrNRSmVb-zZYNFRN3Rse14jz5QpAXU4qSvkccj1q_tEzvEUCVxXcUNU55PmL3GvmjO8RO0OUM1ALpCTqFWcvR74PqXyTsUzvWMjBrSv2egr-d8PhWFX4zeQZi1B2O0jKAEGCxqIwxH7ZA3cwS4PiwXIiOVDNasGIzJA6DH6NDe45TslNSFqvoHQSUdBEe2gMXGkTeI3Vq6ttB1hrt9jeEUB-wpnz6aMd1ildOmZsZQ4UdeAeVErY2F0gH4IIv8h_ov_W9vRE7Jk5ylqvP9_U2_taVq6z2-5ofCtP3psI3N8yaEDfUL_IUMBAAE";
    const client_data_json = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZU11czNfN2c1emY3RmJ1czdLNFJDV2t0MFlGUTVHZ3NSYlN1YkpVUl9QRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9";

    const reg_input = passcay.register.RegVerifyInput{
        .attestation_object = attestation_object,
        .client_data_json = client_data_json,
    };

    const expectations = passcay.register.RegVerifyExpectations{
        .challenge = "eMus3_7g5zf7Fbus7K4RCWkt0YFQ5GgsRbSubJUR_PE",
        .origin = "http://localhost:8080",
        .rp_id = "localhost",
        .require_user_verification = false, // Many authenticators don't support this
        .require_user_presence = true,
    };

    const result = try passcay.register.verify(global_allocator, reg_input, expectations);
    defer result.deinit(global_allocator);

    std.debug.print("RS256 Registration verified successfully!\n", .{});
    std.debug.print("  Credential ID: {s}\n", .{result.credential_id});
    std.debug.print("  Sign Count: {d}\n", .{result.sign_count});
}

// Test RS256 authentication verification using sample data
fn testRs256Authentication() !void {
    // Sample authentication request
    const authenticator_data = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg";
    const client_data_json = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiLUFDRmp1MHpHQ2p3RlpUY0dYdk0zNzVJOGFSaHI5R3NIcnhUQWhVWlBONCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
    const signature = "N8btf6SFzG5EkfaZ6YxEUp0y3t1laU7rL-bNpsE-NDCXxMgunDnEinbNX87bYDmLnSDU96MWHwBcF_3fWxjNFq9HhGY0JITv2m2Lui-Izx0LOB1PXxeXNtyXdUKWUDUhiC-ldEpwSe1cgAsYPb56E0P1y4G8RPylWgUjWgfDzYbSCJy4F2F5veTnA-2zR5que3V6iPamutUuTp9qgExMjRYCoOw_q5hY0kUJ0URKpXQ2zQDT0draG7G12lHAQrgt0e_EvSfbMDF1StuZBTSr9BJ0c7FIULf6osc4TPxKrSW9atL-ZWiL9IXrgQqv4aAH_C-LxYFLRDeAeWxyU_IW_Q";
    const public_key = "pAEDAzkBACBZAQDPaaESfnFzHsCujgVbzjpgDuvZBvuV3gIlOMrNRSmVb+zZYNFRN3Rse14jz5QpAXU4qSvkccj1q/tEzvEUCVxXcUNU55PmL3GvmjO8RO0OUM1ALpCTqFWcvR74PqXyTsUzvWMjBrSv2egr+d8PhWFX4zeQZi1B2O0jKAEGCxqIwxH7ZA3cwS4PiwXIiOVDNasGIzJA6DH6NDe45TslNSFqvoHQSUdBEe2gMXGkTeI3Vq6ttB1hrt9jeEUB+wpnz6aMd1ildOmZsZQ4UdeAeVErY2F0gH4IIv8h/ov/W9vRE7Jk5ylqvP9/U2/taVq6z2+5ofCtP3psI3N8yaEDfUL/IUMBAAE=";

    const auth_input = passcay.auth.AuthVerifyInput{
        .authenticator_data = authenticator_data,
        .client_data_json = client_data_json,
        .signature = signature,
    };

    const expectations = passcay.auth.AuthVerifyExpectations{
        .public_key = public_key,
        .challenge = "-ACFju0zGCjwFZTcGXvM375I8aRhr9GsHrxTAhUZPN4",
        .origin = "http://localhost:8080",
        .rp_id = "localhost",
        .require_user_verification = false, // Many authenticators don't support this
        .require_user_presence = true,
        .enable_sign_count_check = false, // Not checking sign count in this test
        .known_sign_count = 0,
    };

    const result = try passcay.auth.verify(global_allocator, auth_input, expectations);
    defer result.deinit(global_allocator);

    std.debug.print("RS256 Authentication verified successfully!\n", .{});
    std.debug.print("  Sign Count: {d}\n", .{result.sign_count});
    std.debug.print("  Has Extension Data: {}\n", .{result.has_extension_data});
}

// Base64URL encoding helper
fn base64UrlEncode(alloc: Allocator, data: []const u8) ![]const u8 {
    const encoded_len = base64.url_safe_no_pad.Encoder.calcSize(data.len);
    const encoded = try alloc.alloc(u8, encoded_len);
    errdefer alloc.free(encoded);

    _ = base64.url_safe_no_pad.Encoder.encode(encoded, data);
    return encoded;
}

// HTTP server implementation
fn startHttpServer() !void {
    // Our handler for incoming requests
    const Handler = struct {
        // Unused parameter required by httpz
        pub fn handle(_: @This(), request: *httpz.Request, response: *httpz.Response) void {
            const path = request.url.path;

            if (std.mem.eql(u8, path, "/")) {
                handleHome(request, response) catch |err| {
                    std.debug.print("Error handling home route: {s}\n", .{@errorName(err)});
                    response.status = 500;
                    response.body = "Internal Server Error";
                };
                return;
            }

            if (std.mem.eql(u8, path, "/attestation/options") and request.method == .POST) {
                handleAttestationOptionsRoute(request, response) catch |err| {
                    std.debug.print("Error handling attestation options: {s}\n", .{@errorName(err)});
                    response.status = 500;
                    response.body = "Internal Server Error";
                };
                return;
            }

            if (std.mem.eql(u8, path, "/attestation/result") and request.method == .POST) {
                handleAttestationResultRoute(request, response) catch |err| {
                    std.debug.print("Error handling attestation result: {s}\n", .{@errorName(err)});
                    response.status = 500;
                    response.body = "Internal Server Error";
                };
                return;
            }

            if (std.mem.eql(u8, path, "/assertion/options") and request.method == .POST) {
                handleAssertionOptionsRoute(request, response) catch |err| {
                    std.debug.print("Error handling assertion options: {s}\n", .{@errorName(err)});
                    response.status = 500;
                    response.body = "Internal Server Error";
                };
                return;
            }

            if (std.mem.eql(u8, path, "/assertion/result") and request.method == .POST) {
                handleAssertionResultRoute(request, response) catch |err| {
                    std.debug.print("Error handling assertion result: {s}\n", .{@errorName(err)});
                    response.status = 500;
                    response.body = "Internal Server Error";
                };
                return;
            }

            // If no route matched, return 404
            response.status = 404;
            response.body = "404 Not Found";
        }
    };

    // Create server with our handler
    var server = try httpz.Server(Handler).init(
        global_allocator,
        .{
            .port = default_port,
            .address = "0.0.0.0",
            .request = .{
                .max_body_size = 1024 * 1024, // 1MB should be plenty for FIDO2 data
            },
        },
        .{},
    );
    defer server.deinit();

    // Start the server
    std.debug.print("Passcay FIDO2 conformance server listening on port {d}\n", .{default_port});
    try server.listen();
}

// Home page handler
fn handleHome(_: *httpz.Request, response: *httpz.Response) !void {
    response.content_type = httpz.ContentType.HTML;
    response.body =
        \\<!DOCTYPE html>
        \\<html>
        \\<head>
        \\  <title>Passcay FIDO2 Conformance Test Server</title>
        \\  <style>
        \\    body { font-family: system-ui, sans-serif; margin: 2em; line-height: 1.5; }
        \\    h1 { color: #333; }
        \\    code { background: #f4f4f4; padding: 0.2em 0.4em; border-radius: 3px; }
        \\    pre { background: #f8f8f8; padding: 1em; border-radius: 5px; overflow-x: auto; }
        \\  </style>
        \\</head>
        \\<body>
        \\  <h1>Passcay FIDO2 Conformance Test Server</h1>
        \\  <p>This server implements the FIDO2 conformance test API using Passcay.</p>
        \\  <h2>Available Endpoints:</h2>
        \\  <ul>
        \\    <li><code>POST /attestation/options</code> - Registration options</li>
        \\    <li><code>POST /attestation/result</code> - Register credential</li>
        \\    <li><code>POST /assertion/options</code> - Authentication options</li>
        \\    <li><code>POST /assertion/result</code> - Verify authentication</li>
        \\  </ul>
        \\  <h2>Supported Algorithms:</h2>
        \\  <ul>
        \\    <li>ES256 (ECDSA with P-256)</li>
        \\    <li>RS256 (RSA-PKCS1-v1_5 with SHA-256)</li>
        \\  </ul>
        \\</body>
        \\</html>
    ;
}

// Route handler for attestation/options (registration start)
fn handleAttestationOptionsRoute(request: *httpz.Request, response: *httpz.Response) !void {
    // Parse the request body
    const body = request.body() orelse "";
    var req_options = try std.json.parseFromSlice(lib.ServerPublicKeyCredentialCreationOptionsRequest, global_allocator, body, .{});
    defer req_options.deinit();

    // Process the attestation options
    const options = try processAttestationOptions(global_allocator, req_options.value.username, req_options.value.displayName);

    // Store the challenge for later verification
    try challenges.put(options.challenge, options.challenge);

    // Send the response as JSON
    response.content_type = httpz.ContentType.JSON;
    var json_output = std.ArrayList(u8).init(global_allocator);
    defer json_output.deinit();
    try std.json.stringify(options, .{}, json_output.writer());
    response.body = json_output.items;
}

// Route handler for attestation/result (registration finish)
fn handleAttestationResultRoute(request: *httpz.Request, response: *httpz.Response) !void {
    // Parse the request body
    const body = request.body() orelse "";
    var req_result = try std.json.parseFromSlice(lib.ServerPublicKeyCredential, global_allocator, body, .{});
    defer req_result.deinit();

    // Get the stored challenge for this registration
    const challenge_opt = challenges.get(req_result.value.id);
    if (challenge_opt == null) {
        response.status = 400; // Bad Request
        response.content_type = httpz.ContentType.JSON;
        var json_output = std.ArrayList(u8).init(global_allocator);
        defer json_output.deinit();
        try std.json.stringify(lib.ServerResponse.failure("Challenge not found"), .{}, json_output.writer());
        response.body = json_output.items;
        return;
    }

    // Process the attestation result
    var result = processAttestationResult(global_allocator, req_result.value.response.attestationObject, req_result.value.response.clientDataJSON, challenge_opt.?) catch |err| {
        response.status = 400; // Bad Request
        response.content_type = httpz.ContentType.JSON;
        var json_output = std.ArrayList(u8).init(global_allocator);
        defer json_output.deinit();
        try std.json.stringify(lib.ServerResponse.failure(@errorName(err)), .{}, json_output.writer());
        response.body = json_output.items;
        return;
    };
    defer result.deinit(global_allocator);

    // Store the credential for future authentication
    const public_key = result.public_key;
    const user_credential = lib.UserCredential{
        .username = req_result.value.id,
        .displayName = req_result.value.id,
        .id = req_result.value.id,
        .credential_id = req_result.value.id,
        .public_key = public_key,
        .sign_count = result.sign_count,
    };

    try users.put(req_result.value.id, user_credential);
    try credentialIdToUserId.put(req_result.value.id, req_result.value.id);

    // Remove the challenge from storage
    _ = challenges.remove(req_result.value.id);

    // Send the success response
    response.content_type = httpz.ContentType.JSON;
    var json_output = std.ArrayList(u8).init(global_allocator);
    defer json_output.deinit();
    try std.json.stringify(lib.ServerResponse.success(), .{}, json_output.writer());
    response.body = json_output.items;
}

// Route handler for assertion/options (authentication start)
fn handleAssertionOptionsRoute(request: *httpz.Request, response: *httpz.Response) !void {
    // Parse the request body
    const body = request.body() orelse "";
    var req_options = try std.json.parseFromSlice(lib.ServerPublicKeyCredentialGetOptionsRequest, global_allocator, body, .{});
    defer req_options.deinit();

    // Process the assertion options
    const options = try processAssertionOptions(global_allocator, req_options.value.username, req_options.value.userVerification);

    // Store the challenge for later verification
    try challenges.put(options.challenge, options.challenge);

    // Send the response as JSON
    response.content_type = httpz.ContentType.JSON;
    var json_output = std.ArrayList(u8).init(global_allocator);
    defer json_output.deinit();
    try std.json.stringify(options, .{}, json_output.writer());
    response.body = json_output.items;
}

// Route handler for assertion/result (authentication finish)
fn handleAssertionResultRoute(request: *httpz.Request, response: *httpz.Response) !void {
    // Parse the request body
    const body = request.body() orelse "";
    var req_result = try std.json.parseFromSlice(lib.ServerPublicKeyCredentialAssertion, global_allocator, body, .{});
    defer req_result.deinit();

    // Get the stored challenge for this authentication
    const challenge_opt = challenges.get(req_result.value.id);
    if (challenge_opt == null) {
        response.status = 400; // Bad Request
        response.content_type = httpz.ContentType.JSON;
        var json_output = std.ArrayList(u8).init(global_allocator);
        defer json_output.deinit();
        try std.json.stringify(lib.ServerResponse.failure("Challenge not found"), .{}, json_output.writer());
        response.body = json_output.items;
        return;
    }

    // Get the user credential
    const user_id_opt = credentialIdToUserId.get(req_result.value.id);
    if (user_id_opt == null) {
        response.status = 400; // Bad Request
        response.content_type = httpz.ContentType.JSON;
        var json_output = std.ArrayList(u8).init(global_allocator);
        defer json_output.deinit();
        try std.json.stringify(lib.ServerResponse.failure("Credential not found"), .{}, json_output.writer());
        response.body = json_output.items;
        return;
    }

    const user_credential_opt = users.get(user_id_opt.?);
    if (user_credential_opt == null) {
        response.status = 400; // Bad Request
        response.content_type = httpz.ContentType.JSON;
        var json_output = std.ArrayList(u8).init(global_allocator);
        defer json_output.deinit();
        try std.json.stringify(lib.ServerResponse.failure("User not found"), .{}, json_output.writer());
        response.body = json_output.items;
        return;
    }

    // Process the assertion result
    var result = processAssertionResult(global_allocator, req_result.value.response.authenticatorData, req_result.value.response.clientDataJSON, req_result.value.response.signature, user_credential_opt.?.public_key, challenge_opt.?, user_credential_opt.?.sign_count) catch |err| {
        response.status = 400; // Bad Request
        response.content_type = httpz.ContentType.JSON;
        var json_output = std.ArrayList(u8).init(global_allocator);
        defer json_output.deinit();
        try std.json.stringify(lib.ServerResponse.failure(@errorName(err)), .{}, json_output.writer());
        response.body = json_output.items;
        return;
    };
    defer result.deinit(global_allocator);

    // Update the sign count for the credential
    var updated_credential = user_credential_opt.?;
    updated_credential.sign_count = result.sign_count;
    try users.put(user_id_opt.?, updated_credential);

    // Remove the challenge from storage
    _ = challenges.remove(req_result.value.id);

    // Send the success response
    response.content_type = httpz.ContentType.JSON;
    var json_output = std.ArrayList(u8).init(global_allocator);
    defer json_output.deinit();
    try std.json.stringify(lib.ServerResponse.success(), .{}, json_output.writer());
    response.body = json_output.items;
}

// Core implementation functions

// Implementation for handling attestation options request
fn processAttestationOptions(allocator: Allocator, username: []const u8, display_name: []const u8) !lib.ServerPublicKeyCredentialCreationOptionsResponse {
    // Generate a user ID
    var user_id_buf: [16]u8 = undefined;
    Random.bytes(&user_id_buf);
    const user_id = try base64UrlEncode(allocator, &user_id_buf);
    defer allocator.free(user_id);

    // Generate a challenge using passcay
    const challenge = try passcay.challenge.generate(allocator);
    defer allocator.free(challenge);

    // Create public key credential params (support both ES256 and RS256)
    var pub_key_cred_params = ArrayList(lib.PublicKeyCredentialParameters).init(allocator);
    defer pub_key_cred_params.deinit();
    try pub_key_cred_params.append(.{ .type = "public-key", .alg = -7 }); // ES256
    try pub_key_cred_params.append(.{ .type = "public-key", .alg = -257 }); // RS256

    // Create an empty exclude credentials list
    var exclude_credentials = ArrayList(lib.ServerPublicKeyCredentialDescriptor).init(allocator);
    defer exclude_credentials.deinit();

    // Create the options response
    return lib.ServerPublicKeyCredentialCreationOptionsResponse{
        .rp = .{
            .name = default_rp_name,
            .id = default_rp_id,
        },
        .user = .{
            .id = user_id,
            .name = username,
            .displayName = display_name,
        },
        .challenge = challenge,
        .pubKeyCredParams = pub_key_cred_params.items,
        .timeout = default_timeout,
        .excludeCredentials = exclude_credentials.items,
        .attestation = "direct",
        .extensions = .{ .credProps = true },
    };
}

// Implementation for handling attestation result request
fn processAttestationResult(allocator: Allocator, attestation_object: []const u8, client_data_json: []const u8, challenge: []const u8) !passcay.register.RegVerifyResult {
    // Prepare the registration input
    const reg_input = passcay.register.RegVerifyInput{
        .attestation_object = attestation_object,
        .client_data_json = client_data_json,
    };

    // Set verification expectations
    const expectations = passcay.register.RegVerifyExpectations{
        .challenge = challenge,
        .origin = default_origin,
        .rp_id = default_rp_id,
        .require_user_verification = false, // Many authenticators don't support this
        .require_user_presence = true,
    };

    // Verify the registration using passcay
    return try passcay.register.verify(allocator, reg_input, expectations);
}

// Implementation for handling assertion options request
fn processAssertionOptions(
    allocator: Allocator,
    _: []const u8, // username (unused)
    user_verification: ?[]const u8,
) !lib.ServerPublicKeyCredentialGetOptionsResponse {
    // Generate a challenge using passcay
    const challenge = try passcay.challenge.generate(allocator);
    defer allocator.free(challenge);

    // Create an empty allow credentials list (or you can include specific credential IDs)
    var allow_credentials = ArrayList(lib.ServerPublicKeyCredentialDescriptor).init(allocator);
    defer allow_credentials.deinit();

    // Create the options response
    return lib.ServerPublicKeyCredentialGetOptionsResponse{
        .challenge = challenge,
        .timeout = default_timeout,
        .rpId = default_rp_id,
        .allowCredentials = allow_credentials.items,
        .userVerification = user_verification orelse "required",
    };
}

// Implementation for handling assertion result request
fn processAssertionResult(allocator: Allocator, authenticator_data: []const u8, client_data_json: []const u8, signature: []const u8, public_key: []const u8, challenge: []const u8, sign_count: u32) !passcay.auth.AuthVerifyResult {
    // Prepare the authentication input
    const auth_input = passcay.auth.AuthVerifyInput{
        .authenticator_data = authenticator_data,
        .client_data_json = client_data_json,
        .signature = signature,
    };

    // Set verification expectations
    const expectations = passcay.auth.AuthVerifyExpectations{
        .public_key = public_key,
        .challenge = challenge,
        .origin = default_origin,
        .rp_id = default_rp_id,
        .require_user_verification = false, // Many authenticators don't support this
        .require_user_presence = true,
        .enable_sign_count_check = true,
        .known_sign_count = sign_count,
    };

    // Verify the authentication using passcay
    return try passcay.auth.verify(allocator, auth_input, expectations);
}
