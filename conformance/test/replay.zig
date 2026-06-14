//! HTTP-level conformance replay harness (Layer B).
//!
//! Drives the four conformance endpoints with recorded transcripts — full
//! options -> result sequences using real WebAuthn vectors — and asserts the
//! {status, errorMessage} envelope. Stateful: a registration result stores the
//! credential that the matching assertion then verifies against. Runs offline
//! via `zig build test`; no sockets, no FIDO desktop tool.

const std = @import("std");
const testing = std.testing;
const srv = @import("server");

// ---- real vectors (mirrors of src/test_data.zig; the conformance project is standalone) ----
const es256_reg_challenge = "uLjJNKj5cio95Tg1XflYB5oHBprHnGF_Aqu16zx-7iw";
const es256_reg_cdj = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidUxqSk5LajVjaW85NVRnMVhmbFlCNW9IQnBySG5HRl9BcXUxNnp4LTdpdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
const es256_reg_attobj = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFMtMGHZHZPUpC3DRAPuBxLAFbSM_pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE";
const es256_cred_id = "y0wYdkdk9SkLcNEA-4HEsAVtIz8";
const es256_auth_challenge = "lh0GW68FJem75lA5_lE6JNe8vZ687lvhZBkkcDsQPyo";
const es256_auth_cdj = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibGgwR1c2OEZKZW03NWxBNV9sRTZKTmU4dlo2ODdsdmhaQmtrY0RzUVB5byIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
const es256_auth_authdata = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";
const es256_auth_sig = "MEYCIQDQ-pXZQT9yjPsXT_m47W-iTFAIRgBVOCBhwl6kU--0RwIhAKcJJhxipw6tsIR0ULRgvQAhTaeIXk_V29wKOqbfP1oL";

const u2f_origin = "http://localhost:5000";
const u2f_reg_challenge = "ZJVNlmOrXwwgQkd1gDMly8BIiIMV4IQDDsCr6KPbCIHcOZ5waKHm-MZtuY748SCqg-NZVpRrYFyFrc36gQoFtw";
const u2f_reg_cdj = "eyJjaGFsbGVuZ2UiOiJaSlZObG1Pclh3d2dRa2QxZ0RNbHk4QklpSU1WNElRRERzQ3I2S1BiQ0lIY09aNXdhS0htLU1adHVZNzQ4U0NxZy1OWlZwUnJZRnlGcmMzNmdRb0Z0dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ";
const u2f_reg_attobj = "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAIJO_x-FicMO0XDFwnVfXWyF-Dp7GW7oL43QfZyUjKU0AiAxQBUFu17l9rmKmqAWnHL6F1dDaIu54WYc9Mi_jtdNL2N4NWOBWQLBMIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4aGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAlrjqbPdLbWXTJ2sFIreka9aWd2ED-SDx_VAgBAh4XmCJgjCjudEjoi42pGQd-_Bi6nNPQ3T7-xOEgty2I3m7c6UBAgMmIAEhWCDpQmUwrGnn3mk-T27A6awwL4HJG62Plj8Hz-lL0KltuiJYILwFIu48iEB8Ov6mEAqtCxn3mQOoaGIG4eidiWyLRg05";
const u2f_cred_id = "lrjqbPdLbWXTJ2sFIreka9aWd2ED-SDx_VAgBAh4XmCJgjCjudEjoi42pGQd-_Bi6nNPQ3T7-xOEgty2I3m7cw";

fn attResultBody(a: std.mem.Allocator, id: []const u8, cdj: []const u8, attobj: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{{\"id\":\"{s}\",\"type\":\"public-key\",\"response\":{{\"clientDataJSON\":\"{s}\",\"attestationObject\":\"{s}\"}}}}", .{ id, cdj, attobj });
}

fn asrResultBody(a: std.mem.Allocator, id: []const u8, cdj: []const u8, ad: []const u8, sig: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{{\"id\":\"{s}\",\"type\":\"public-key\",\"response\":{{\"clientDataJSON\":\"{s}\",\"authenticatorData\":\"{s}\",\"signature\":\"{s}\"}}}}", .{ id, cdj, ad, sig });
}

fn expectOk(resp: srv.Response) !void {
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"status\":\"ok\"") != null);
}

fn expectFailWith(resp: srv.Response, needle: []const u8) !void {
    try testing.expectEqual(@as(u16, 400), resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"status\":\"failed\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, needle) != null);
}

test "replay: ES256 none registration then assertion round-trip" {
    const a = testing.allocator;
    var ctx = srv.Context.init(a);
    defer ctx.deinit();

    {
        const resp = try srv.attestationOptions(&ctx, a, "{\"username\":\"asdf3\"}", es256_reg_challenge);
        defer resp.deinit(a);
        try expectOk(resp);
    }
    {
        const body = try attResultBody(a, es256_cred_id, es256_reg_cdj, es256_reg_attobj);
        defer a.free(body);
        const resp = try srv.attestationResult(&ctx, a, body);
        defer resp.deinit(a);
        try expectOk(resp);
    }
    {
        const resp = try srv.assertionOptions(&ctx, a, "{\"username\":\"asdf3\"}", es256_auth_challenge);
        defer resp.deinit(a);
        try expectOk(resp);
    }
    {
        const body = try asrResultBody(a, es256_cred_id, es256_auth_cdj, es256_auth_authdata, es256_auth_sig);
        defer a.free(body);
        const resp = try srv.assertionResult(&ctx, a, body);
        defer resp.deinit(a);
        try expectOk(resp);
    }
}

test "replay: fido-u2f full attestation registration" {
    const a = testing.allocator;
    var ctx = srv.Context.init(a);
    ctx.origin = u2f_origin;
    defer ctx.deinit();

    {
        const resp = try srv.attestationOptions(&ctx, a, "{\"username\":\"u2f\"}", u2f_reg_challenge);
        defer resp.deinit(a);
        try expectOk(resp);
    }
    {
        const body = try attResultBody(a, u2f_cred_id, u2f_reg_cdj, u2f_reg_attobj);
        defer a.free(body);
        const resp = try srv.attestationResult(&ctx, a, body);
        defer resp.deinit(a);
        try expectOk(resp);
    }
}

test "replay/neg: result without a prior options is rejected (unknown challenge)" {
    const a = testing.allocator;
    var ctx = srv.Context.init(a);
    defer ctx.deinit();

    const body = try attResultBody(a, es256_cred_id, es256_reg_cdj, es256_reg_attobj);
    defer a.free(body);
    const resp = try srv.attestationResult(&ctx, a, body);
    defer resp.deinit(a);
    try expectFailWith(resp, "challenge");
}

test "replay/neg: wrong origin is rejected" {
    const a = testing.allocator;
    var ctx = srv.Context.init(a);
    ctx.origin = "https://evil.example"; // mismatches the vector's origin
    defer ctx.deinit();

    {
        const resp = try srv.attestationOptions(&ctx, a, "{\"username\":\"asdf3\"}", es256_reg_challenge);
        defer resp.deinit(a);
        try expectOk(resp);
    }
    {
        const body = try attResultBody(a, es256_cred_id, es256_reg_cdj, es256_reg_attobj);
        defer a.free(body);
        const resp = try srv.attestationResult(&ctx, a, body);
        defer resp.deinit(a);
        try expectFailWith(resp, "origin");
    }
}

test "replay/neg: tampered assertion signature is rejected" {
    const a = testing.allocator;
    var ctx = srv.Context.init(a);
    defer ctx.deinit();

    // register first so the credential exists
    {
        const resp = try srv.attestationOptions(&ctx, a, "{\"username\":\"asdf3\"}", es256_reg_challenge);
        defer resp.deinit(a);
        try expectOk(resp);
    }
    {
        const body = try attResultBody(a, es256_cred_id, es256_reg_cdj, es256_reg_attobj);
        defer a.free(body);
        const resp = try srv.attestationResult(&ctx, a, body);
        defer resp.deinit(a);
        try expectOk(resp);
    }
    {
        const resp = try srv.assertionOptions(&ctx, a, "{\"username\":\"asdf3\"}", es256_auth_challenge);
        defer resp.deinit(a);
        try expectOk(resp);
    }
    {
        // Corrupt the signature's middle character.
        const bad_sig = try a.dupe(u8, es256_auth_sig);
        defer a.free(bad_sig);
        bad_sig[bad_sig.len / 2] = if (bad_sig[bad_sig.len / 2] == 'A') 'B' else 'A';
        const body = try asrResultBody(a, es256_cred_id, es256_auth_cdj, es256_auth_authdata, bad_sig);
        defer a.free(body);
        const resp = try srv.assertionResult(&ctx, a, body);
        defer resp.deinit(a);
        try expectFailWith(resp, "signature");
    }
}
