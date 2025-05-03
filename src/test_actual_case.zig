//! Tests for passcay library using real WebAuthn data
//! This file contains tests using actual WebAuthn registration and authentication data

const std = @import("std");
const passcay = @import("root.zig");
const testing = std.testing;

test "ES256 registration verification with real data" {
    const allocator = testing.allocator;

    // Test data from CLAUDE.md
    const attestation_object = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFMtMGHZHZPUpC3DRAPuBxLAFbSM_pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE";
    const client_data_json = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidUxqSk5LajVjaW85NVRnMVhmbFlCNW9IQnBySG5HRl9BcXUxNnp4LTdpdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
    const challenge = "uLjJNKj5cio95Tg1XflYB5oHBprHnGF_Aqu16zx-7iw";
    const origin = "http://localhost:8080";
    const rp_id = "localhost";

    // Set up the registration input and expectations
    const reg_input = passcay.register.RegVerifyInput{
        .attestation_object = attestation_object,
        .client_data_json = client_data_json,
    };

    const reg_expectations = passcay.register.RegVerifyExpectations{
        .challenge = challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = true,
    };

    // Perform the verification with actual WebAuthn data
    const result = try passcay.register.verify(allocator, reg_input, reg_expectations);
    defer result.deinit(allocator);

    // Verify the expected results
    try testing.expectEqualStrings("y0wYdkdk9SkLcNEA-4HEsAVtIz8", result.credential_id);
    try testing.expectEqualStrings("pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE", result.public_key);
    try testing.expectEqual(@as(u32, 0), result.sign_count);
    try testing.expectEqual(result.flags & 0x01, 0x01); // User Present flag should be set
}

test "ES256 authentication verification with real data" {
    const allocator = testing.allocator;

    // Test data from CLAUDE.md
    const authenticator_data = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";
    const client_data_json = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibGgwR1c2OEZKZW03NWxBNV9sRTZKTmU4dlo2ODdsdmhaQmtrY0RzUVB5byIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
    const signature = "MEYCIQDQ-pXZQT9yjPsXT_m47W-iTFAIRgBVOCBhwl6kU--0RwIhAKcJJhxipw6tsIR0ULRgvQAhTaeIXk_V29wKOqbfP1oL";
    const public_key = "pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE";
    const challenge = "lh0GW68FJem75lA5_lE6JNe8vZ687lvhZBkkcDsQPyo";
    const origin = "http://localhost:8080";
    const rp_id = "localhost";

    // Set up the authentication input and expectations
    const auth_input = passcay.auth.AuthVerifyInput{
        .authenticator_data = authenticator_data,
        .client_data_json = client_data_json,
        .signature = signature,
    };

    const auth_expectations = passcay.auth.AuthVerifyExpectations{
        .public_key = public_key,
        .challenge = challenge,
        .origin = origin,
        .rp_id = rp_id,
        .require_user_verification = true,
        .require_user_presence = true,
        .enable_sign_count_check = true,
        .known_sign_count = 0,
    };

    // Perform the verification with actual WebAuthn data
    const auth_result = try passcay.auth.verify(allocator, auth_input, auth_expectations);
    defer auth_result.deinit(allocator);

    // Verify the expected results
    try testing.expectEqual(@as(u32, 0), auth_result.sign_count);
    try testing.expectEqual(@as(u32, 0), auth_result.recommended_sign_count);
    try testing.expectEqual(auth_result.flags & 0x01, 0x01); // User Present flag should be set
}
