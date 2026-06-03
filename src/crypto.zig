//! WebAuthn Cryptographic Verification
//!
//! Provides functions for verifying WebAuthn signatures with support
//! for ES256 (ECDSA with P-256) and RS256 (RSASSA-PKCS1-v1_5).

const std = @import("std");
const crypto = std.crypto;
const base64 = std.base64;
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const cbor = @import("zbor");

const passcay = @import("root.zig");
const types = passcay.types;
const util = passcay.util;

/// Compute the SHA-256 hash of a message
/// For backward compatibility with existing code
pub fn sha256(data: []const u8, out: *[32]u8, _: anytype) void {
    var hash = crypto.hash.sha2.Sha256.init(.{});
    hash.update(data);
    hash.final(out);
}

pub const CoseAlg = types.CoseAlg;
pub const VerifyError = types.VerifyError;

/// Detect algorithm from a CBOR-encoded public key
/// Explicitly identifies the algorithm by parsing the CBOR structure
/// Returns ES256 or RS256 if supported, or an error otherwise
pub fn getAlgorithm(key_bytes: []const u8) !CoseAlg {
    if (key_bytes.len < 4) return VerifyError.InvalidKeyFormat;

    var data_item = try cbor.DataItem.new(key_bytes);
    if (data_item.getType() != .Map) return VerifyError.InvalidKeyFormat;

    const map = data_item.map().?;

    // Look for the algorithm identifier (key = 3)
    var map_iter = map;
    while (map_iter.next()) |pair| {
        if (pair.key.getType() == .Int) {
            const key_int = pair.key.int().?;

            if (key_int == 3) { // 3 is the key for algorithm
                if (pair.value.getType() != .Int) continue;
                const alg_int = pair.value.int().?;
                if (alg_int == -7) return CoseAlg.ES256;
                if (alg_int == -257) return CoseAlg.RS256;
                return VerifyError.UnsupportedAlgorithm;
            }
        }
    }
    return VerifyError.UnsupportedAlgorithm;
}

/// Verify a signature using ES256 algorithm (ECDSA with P-256 curve and SHA-256)
fn verifyES256(_: Allocator, public_key_bytes: []const u8, data: []const u8, signature: []const u8) !bool {
    var data_item = try cbor.DataItem.new(public_key_bytes);

    if (data_item.getType() != .Map) {
        return VerifyError.CBORParsingFailed;
    }

    const map = data_item.map().?;

    var x_bytes: ?[]const u8 = null;
    var y_bytes: ?[]const u8 = null;

    var map_iter = map;
    while (map_iter.next()) |pair| {
        if (pair.key.getType() == .Int) {
            const key_int = pair.key.int().?;

            if (key_int == -2) { // x coordinate
                if (pair.value.getType() == .ByteString) {
                    x_bytes = pair.value.string().?;
                }
            } else if (key_int == -3) { // y coordinate
                if (pair.value.getType() == .ByteString) {
                    y_bytes = pair.value.string().?;
                }
            }
        }
    }

    if (x_bytes == null or y_bytes == null) {
        return VerifyError.MissingKeyComponent;
    }

    const Ecdsa = crypto.sign.ecdsa.EcdsaP256Sha256;
    const coord_len = 32;

    if (x_bytes.?.len > coord_len or y_bytes.?.len > coord_len) {
        return VerifyError.InvalidPublicKey;
    }

    // SEC1 uncompressed point: 0x04 || x || y, left-padding each coordinate to
    // 32 bytes (COSE normally provides exactly 32).
    var sec1: [1 + 2 * coord_len]u8 = undefined;
    sec1[0] = 0x04;
    @memset(sec1[1..], 0);
    @memcpy(sec1[1 + coord_len - x_bytes.?.len .. 1 + coord_len], x_bytes.?);
    @memcpy(sec1[1 + 2 * coord_len - y_bytes.?.len ..], y_bytes.?);

    const pk = Ecdsa.PublicKey.fromSec1(&sec1) catch return VerifyError.InvalidPublicKey;
    const sig = Ecdsa.Signature.fromDer(signature) catch return false;
    sig.verify(data, pk) catch return false;
    return true;
}

/// Verify a signature with RS256 (RSA with SHA-256) algorithm
fn verifyRS256(_: Allocator, public_key_bytes: []const u8, data: []const u8, signature: []const u8) !bool {
    var data_item = try cbor.DataItem.new(public_key_bytes);

    if (data_item.getType() != .Map) {
        return VerifyError.CBORParsingFailed;
    }

    const map = data_item.map().?;

    var n_bytes: ?[]const u8 = null;
    var e_bytes: ?[]const u8 = null;

    var map_iter = map;
    while (map_iter.next()) |pair| {
        if (pair.key.getType() == .Int) {
            const key_int = pair.key.int().?;

            if (key_int == -1) { // n (modulus)
                if (pair.value.getType() == .ByteString) {
                    n_bytes = pair.value.string().?;
                }
            } else if (key_int == -2) { // e (exponent)
                if (pair.value.getType() == .ByteString) {
                    e_bytes = pair.value.string().?;
                }
            }
        }
    }

    if (n_bytes == null or e_bytes == null) {
        return VerifyError.MissingKeyComponent;
    }

    // Strip leading zero bytes (DER positive-integer padding) from the modulus
    // and exponent.
    const n = mem.trimStart(u8, n_bytes.?, "\x00");
    const e = mem.trimStart(u8, e_bytes.?, "\x00");

    const rsa = crypto.Certificate.rsa;
    const Sha256 = crypto.hash.sha2.Sha256;

    const pk = rsa.PublicKey.fromBytes(e, n) catch return VerifyError.InvalidPublicKey;

    // PKCS1v1_5Signature.verify takes a comptime modulus length and a
    // fixed-size signature; the signature length equals the RSA key size.
    inline for (.{ 256, 384, 512 }) |klen| {
        if (signature.len == klen) {
            const sig: [klen]u8 = signature[0..klen].*;
            rsa.PKCS1v1_5Signature.verify(klen, sig, data, pk, Sha256) catch return false;
            return true;
        }
    }

    return VerifyError.InvalidSignature;
}

pub fn verifySignature(allocator: Allocator, public_key_base64url: []const u8, signature: []const u8, data: []const u8) !bool {
    var decoder = base64.url_safe_no_pad.Decoder;
    const key_size = try decoder.calcSizeForSlice(public_key_base64url);
    const key_buf = try allocator.alloc(u8, key_size);
    defer allocator.free(key_buf);

    _ = try decoder.decode(key_buf, public_key_base64url);
    const key_bytes = key_buf[0..key_size];

    const algorithm = try getAlgorithm(key_bytes);

    return switch (algorithm) {
        .ES256 => try verifyES256(allocator, key_bytes, data, signature),
        .RS256 => try verifyRS256(allocator, key_bytes, data, signature),
        else => VerifyError.UnsupportedAlgorithm,
    };
}

pub fn verifyBase64Url(allocator: Allocator, public_key_base64url: []const u8, signature_base64url: []const u8, data_base64url: []const u8) !bool {
    var decoder = base64.url_safe_no_pad.Decoder;

    const sig_size = try decoder.calcSizeForSlice(signature_base64url);
    const sig_buf = try allocator.alloc(u8, sig_size);
    defer allocator.free(sig_buf);

    _ = try decoder.decode(sig_buf, signature_base64url);
    const sig_bytes = sig_buf[0..sig_size];

    const data_size = try decoder.calcSizeForSlice(data_base64url);
    const data_buf = try allocator.alloc(u8, data_size);
    defer allocator.free(data_buf);

    _ = try decoder.decode(data_buf, data_base64url);
    const data_bytes = data_buf[0..data_size];

    return try verifySignature(allocator, public_key_base64url, sig_bytes, data_bytes);
}

fn base64urlToBytes(allocator: Allocator, b64str: []const u8) ![]u8 {
    var decoder = base64.url_safe_no_pad.Decoder;
    const buf_size = try decoder.calcSizeForSlice(b64str);
    const buf = try allocator.alloc(u8, buf_size);
    errdefer allocator.free(buf);

    _ = try decoder.decode(buf, b64str);
    return buf[0..buf_size];
}

test "verifyES256_signature using real WebAuthn data" {
    const allocator = testing.allocator;

    // Public key from credential registration
    const public_key_b64 = "pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE";

    const auth_data_b64 = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";
    const auth_data = try base64urlToBytes(allocator, auth_data_b64);
    defer allocator.free(auth_data);

    const client_data_json_b64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibGgwR1c2OEZKZW03NWxBNV9sRTZKTmU4dlo2ODdsdmhaQmtrY0RzUVB5byIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
    const client_data_json = try base64urlToBytes(allocator, client_data_json_b64);
    defer allocator.free(client_data_json);

    var client_data_hash: [32]u8 = undefined;
    sha256(client_data_json, &client_data_hash, .{});

    const signed_data_len = auth_data.len + client_data_hash.len;
    var signed_data = try allocator.alloc(u8, signed_data_len);
    defer allocator.free(signed_data);

    @memcpy(signed_data[0..auth_data.len], auth_data);
    @memcpy(signed_data[auth_data.len..], &client_data_hash);

    const signature_b64 = "MEYCIQDQ-pXZQT9yjPsXT_m47W-iTFAIRgBVOCBhwl6kU--0RwIhAKcJJhxipw6tsIR0ULRgvQAhTaeIXk_V29wKOqbfP1oL";
    const signature = try base64urlToBytes(allocator, signature_b64);
    defer allocator.free(signature);

    const verified = try verifySignature(allocator, public_key_b64, signature, signed_data);

    try testing.expect(verified);
}

test "verifyRS256_signature using real WebAuthn data" {
    const allocator = testing.allocator;

    // Real WebAuthn RS256 data
    const pubkey_bytes = [_]u8{ 0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20, 0x59, 0x01, 0x00, 0xcf, 0x69, 0xa1, 0x12, 0x7e, 0x71, 0x73, 0x1e, 0xc0, 0xae, 0x8e, 0x05, 0x5b, 0xce, 0x3a, 0x60, 0x0e, 0xeb, 0xd9, 0x06, 0xfb, 0x95, 0xde, 0x02, 0x25, 0x38, 0xca, 0xcd, 0x45, 0x29, 0x95, 0x6f, 0xec, 0xd9, 0x60, 0xd1, 0x51, 0x37, 0x74, 0x6c, 0x7b, 0x5e, 0x23, 0xcf, 0x94, 0x29, 0x01, 0x75, 0x38, 0xa9, 0x2b, 0xe4, 0x71, 0xc8, 0xf5, 0xab, 0xfb, 0x44, 0xce, 0xf1, 0x14, 0x09, 0x5c, 0x57, 0x71, 0x43, 0x54, 0xe7, 0x93, 0xe6, 0x2f, 0x71, 0xaf, 0x9a, 0x33, 0xbc, 0x44, 0xed, 0x0e, 0x50, 0xcd, 0x40, 0x2e, 0x90, 0x93, 0xa8, 0x55, 0x9c, 0xbd, 0x1e, 0xf8, 0x3e, 0xa5, 0xf2, 0x4e, 0xc5, 0x33, 0xbd, 0x63, 0x23, 0x06, 0xb4, 0xaf, 0xd9, 0xe8, 0x2b, 0xf9, 0xdf, 0x0f, 0x85, 0x61, 0x57, 0xe3, 0x37, 0x90, 0x66, 0x2d, 0x41, 0xd8, 0xed, 0x23, 0x28, 0x01, 0x06, 0x0b, 0x1a, 0x88, 0xc3, 0x11, 0xfb, 0x64, 0x0d, 0xdc, 0xc1, 0x2e, 0x0f, 0x8b, 0x05, 0xc8, 0x88, 0xe5, 0x43, 0x35, 0xab, 0x06, 0x23, 0x32, 0x40, 0xe8, 0x31, 0xfa, 0x34, 0x37, 0xb8, 0xe5, 0x3b, 0x25, 0x35, 0x21, 0x6a, 0xbe, 0x81, 0xd0, 0x49, 0x47, 0x41, 0x11, 0xed, 0xa0, 0x31, 0x71, 0xa4, 0x4d, 0xe2, 0x37, 0x56, 0xae, 0xad, 0xb4, 0x1d, 0x61, 0xae, 0xdf, 0x63, 0x78, 0x45, 0x01, 0xfb, 0x0a, 0x67, 0xcf, 0xa6, 0x8c, 0x77, 0x58, 0xa5, 0x74, 0xe9, 0x99, 0xb1, 0x94, 0x38, 0x51, 0xd7, 0x80, 0x79, 0x51, 0x2b, 0x63, 0x61, 0x74, 0x80, 0x7e, 0x08, 0x22, 0xff, 0x21, 0xfe, 0x8b, 0xff, 0x5b, 0xdb, 0xd1, 0x13, 0xb2, 0x64, 0xe7, 0x29, 0x6a, 0xbc, 0xff, 0x7f, 0x53, 0x6f, 0xed, 0x69, 0x5a, 0xba, 0xcf, 0x6f, 0xb9, 0xa1, 0xf0, 0xad, 0x3f, 0x7a, 0x6c, 0x23, 0x73, 0x7c, 0xc9, 0xa1, 0x03, 0x7d, 0x42, 0xff, 0x21, 0x43, 0x01, 0x00, 0x01 };

    var key_buf: [512]u8 = undefined; // Large enough buffer for the encoded key
    const encoded_len = base64.url_safe_no_pad.Encoder.calcSize(pubkey_bytes.len);
    const encoded_buf = key_buf[0..encoded_len];
    _ = base64.url_safe_no_pad.Encoder.encode(encoded_buf, &pubkey_bytes);
    const public_key_b64 = encoded_buf;

    const auth_data_b64 = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg";
    const auth_data = try base64urlToBytes(allocator, auth_data_b64);
    defer allocator.free(auth_data);

    const client_data_json_b64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiLUFDRmp1MHpHQ2p3RlpUY0dYdk0zNzVJOGFSaHI5R3NIcnhUQWhVWlBONCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
    const client_data_json = try base64urlToBytes(allocator, client_data_json_b64);
    defer allocator.free(client_data_json);

    var client_data_hash: [32]u8 = undefined;
    sha256(client_data_json, &client_data_hash, .{});

    const signed_data_len = auth_data.len + client_data_hash.len;
    var signed_data = try allocator.alloc(u8, signed_data_len);
    defer allocator.free(signed_data);

    @memcpy(signed_data[0..auth_data.len], auth_data);
    @memcpy(signed_data[auth_data.len..], &client_data_hash);

    const signature_b64 = "N8btf6SFzG5EkfaZ6YxEUp0y3t1laU7rL-bNpsE-NDCXxMgunDnEinbNX87bYDmLnSDU96MWHwBcF_3fWxjNFq9HhGY0JITv2m2Lui-Izx0LOB1PXxeXNtyXdUKWUDUhiC-ldEpwSe1cgAsYPb56E0P1y4G8RPylWgUjWgfDzYbSCJy4F2F5veTnA-2zR5que3V6iPamutUuTp9qgExMjRYCoOw_q5hY0kUJ0URKpXQ2zQDT0draG7G12lHAQrgt0e_EvSfbMDF1StuZBTSr9BJ0c7FIULf6osc4TPxKrSW9atL-ZWiL9IXrgQqv4aAH_C-LxYFLRDeAeWxyU_IW_Q";
    const signature = try base64urlToBytes(allocator, signature_b64);
    defer allocator.free(signature);

    const verified = try verifySignature(allocator, public_key_b64, signature, signed_data);

    try testing.expect(verified);
}

test "verify signature rejection with corrupted signatures" {
    const allocator = testing.allocator;

    // Test ES256 signature rejection
    {
        // Real WebAuthn ES256 data
        const public_key_b64 = "pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE";

        const auth_data_b64 = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";
        const auth_data = try base64urlToBytes(allocator, auth_data_b64);
        defer allocator.free(auth_data);

        const client_data_json_b64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibGgwR1c2OEZKZW03NWxBNV9sRTZKTmU4dlo2ODdsdmhaQmtrY0RzUVB5byIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
        const client_data_json = try base64urlToBytes(allocator, client_data_json_b64);
        defer allocator.free(client_data_json);

        var client_data_hash: [32]u8 = undefined;
        sha256(client_data_json, &client_data_hash, .{});

        // Concatenate authenticator data and client data hash to form the signed data
        const signed_data_len = auth_data.len + client_data_hash.len;
        var signed_data = try allocator.alloc(u8, signed_data_len);
        defer allocator.free(signed_data);

        @memcpy(signed_data[0..auth_data.len], auth_data);
        @memcpy(signed_data[auth_data.len..], &client_data_hash);

        // Create a corrupted signature by changing a byte in the real signature
        const real_signature_b64 = "MEYCIQDQ-pXZQT9yjPsXT_m47W-iTFAIRgBVOCBhwl6kU--0RwIhAKcJJhxipw6tsIR0ULRgvQAhTaeIXk_V29wKOqbfP1oL";
        var real_signature = try base64urlToBytes(allocator, real_signature_b64);
        defer allocator.free(real_signature);

        // Corrupt the signature by changing a byte
        if (real_signature.len > 20) {
            real_signature[20] = real_signature[20] ^ 0xFF; // Flip all bits in this byte
        }

        // Verify the signature - should fail
        const verified_es256 = try verifySignature(allocator, public_key_b64, real_signature, signed_data);
        try testing.expect(!verified_es256);
    }

    // Test RS256 signature rejection
    {
        // Raw key bytes for RS256
        const pubkey_bytes = [_]u8{ 0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20, 0x59, 0x01, 0x00, 0xcf, 0x69, 0xa1, 0x12, 0x7e, 0x71, 0x73, 0x1e, 0xc0, 0xae, 0x8e, 0x05, 0x5b, 0xce, 0x3a, 0x60, 0x0e, 0xeb, 0xd9, 0x06, 0xfb, 0x95, 0xde, 0x02, 0x25, 0x38, 0xca, 0xcd, 0x45, 0x29, 0x95, 0x6f, 0xec, 0xd9, 0x60, 0xd1, 0x51, 0x37, 0x74, 0x6c, 0x7b, 0x5e, 0x23, 0xcf, 0x94, 0x29, 0x01, 0x75, 0x38, 0xa9, 0x2b, 0xe4, 0x71, 0xc8, 0xf5, 0xab, 0xfb, 0x44, 0xce, 0xf1, 0x14, 0x09, 0x5c, 0x57, 0x71, 0x43, 0x54, 0xe7, 0x93, 0xe6, 0x2f, 0x71, 0xaf, 0x9a, 0x33, 0xbc, 0x44, 0xed, 0x0e, 0x50, 0xcd, 0x40, 0x2e, 0x90, 0x93, 0xa8, 0x55, 0x9c, 0xbd, 0x1e, 0xf8, 0x3e, 0xa5, 0xf2, 0x4e, 0xc5, 0x33, 0xbd, 0x63, 0x23, 0x06, 0xb4, 0xaf, 0xd9, 0xe8, 0x2b, 0xf9, 0xdf, 0x0f, 0x85, 0x61, 0x57, 0xe3, 0x37, 0x90, 0x66, 0x2d, 0x41, 0xd8, 0xed, 0x23, 0x28, 0x01, 0x06, 0x0b, 0x1a, 0x88, 0xc3, 0x11, 0xfb, 0x64, 0x0d, 0xdc, 0xc1, 0x2e, 0x0f, 0x8b, 0x05, 0xc8, 0x88, 0xe5, 0x43, 0x35, 0xab, 0x06, 0x23, 0x32, 0x40, 0xe8, 0x31, 0xfa, 0x34, 0x37, 0xb8, 0xe5, 0x3b, 0x25, 0x35, 0x21, 0x6a, 0xbe, 0x81, 0xd0, 0x49, 0x47, 0x41, 0x11, 0xed, 0xa0, 0x31, 0x71, 0xa4, 0x4d, 0xe2, 0x37, 0x56, 0xae, 0xad, 0xb4, 0x1d, 0x61, 0xae, 0xdf, 0x63, 0x78, 0x45, 0x01, 0xfb, 0x0a, 0x67, 0xcf, 0xa6, 0x8c, 0x77, 0x58, 0xa5, 0x74, 0xe9, 0x99, 0xb1, 0x94, 0x38, 0x51, 0xd7, 0x80, 0x79, 0x51, 0x2b, 0x63, 0x61, 0x74, 0x80, 0x7e, 0x08, 0x22, 0xff, 0x21, 0xfe, 0x8b, 0xff, 0x5b, 0xdb, 0xd1, 0x13, 0xb2, 0x64, 0xe7, 0x29, 0x6a, 0xbc, 0xff, 0x7f, 0x53, 0x6f, 0xed, 0x69, 0x5a, 0xba, 0xcf, 0x6f, 0xb9, 0xa1, 0xf0, 0xad, 0x3f, 0x7a, 0x6c, 0x23, 0x73, 0x7c, 0xc9, 0xa1, 0x03, 0x7d, 0x42, 0xff, 0x21, 0x43, 0x01, 0x00, 0x01 };

        var key_buf: [512]u8 = undefined;
        const encoded_len = base64.url_safe_no_pad.Encoder.calcSize(pubkey_bytes.len);
        const encoded_buf = key_buf[0..encoded_len];
        _ = base64.url_safe_no_pad.Encoder.encode(encoded_buf, &pubkey_bytes);
        const public_key_b64 = encoded_buf;

        const auth_data_b64 = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg";
        const auth_data = try base64urlToBytes(allocator, auth_data_b64);
        defer allocator.free(auth_data);

        const client_data_json_b64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiLUFDRmp1MHpHQ2p3RlpUY0dYdk0zNzVJOGFSaHI5R3NIcnhUQWhVWlBONCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
        const client_data_json = try base64urlToBytes(allocator, client_data_json_b64);
        defer allocator.free(client_data_json);

        var client_data_hash: [32]u8 = undefined;
        sha256(client_data_json, &client_data_hash, .{});

        // Concatenate authenticator data and client data hash to form the signed data
        const signed_data_len = auth_data.len + client_data_hash.len;
        var signed_data = try allocator.alloc(u8, signed_data_len);
        defer allocator.free(signed_data);

        @memcpy(signed_data[0..auth_data.len], auth_data);
        @memcpy(signed_data[auth_data.len..], &client_data_hash);

        // Create a corrupted signature by changing a byte in the real signature
        const real_signature_b64 = "N8btf6SFzG5EkfaZ6YxEUp0y3t1laU7rL-bNpsE-NDCXxMgunDnEinbNX87bYDmLnSDU96MWHwBcF_3fWxjNFq9HhGY0JITv2m2Lui-Izx0LOB1PXxeXNtyXdUKWUDUhiC-ldEpwSe1cgAsYPb56E0P1y4G8RPylWgUjWgfDzYbSCJy4F2F5veTnA-2zR5que3V6iPamutUuTp9qgExMjRYCoOw_q5hY0kUJ0URKpXQ2zQDT0draG7G12lHAQrgt0e_EvSfbMDF1StuZBTSr9BJ0c7FIULf6osc4TPxKrSW9atL-ZWiL9IXrgQqv4aAH_C-LxYFLRDeAeWxyU_IW_Q";
        var real_signature = try base64urlToBytes(allocator, real_signature_b64);
        defer allocator.free(real_signature);

        // Corrupt the signature by changing a byte
        if (real_signature.len > 50) {
            real_signature[50] = real_signature[50] ^ 0xFF; // Flip all bits in this byte
        }

        // Verify the signature - should fail
        const verified_rs256 = try verifySignature(allocator, public_key_b64, real_signature, signed_data);
        try testing.expect(!verified_rs256);
    }
}

test "memory safety in signature verification" {
    const allocator = testing.allocator;

    // --- 1. Regular case - verify valid signature ---
    {
        // Use the same WebAuthn data from the ES256 test - known working data
        const public_key_b64 = "pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE";

        // Authentication data
        const auth_data_b64 = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";
        const auth_data = try base64urlToBytes(allocator, auth_data_b64);
        defer allocator.free(auth_data);

        // Client data JSON
        const client_data_json_b64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibGgwR1c2OEZKZW03NWxBNV9sRTZKTmU4dlo2ODdsdmhaQmtrY0RzUVB5byIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
        const client_data_json = try base64urlToBytes(allocator, client_data_json_b64);
        defer allocator.free(client_data_json);

        // Hash the client data JSON
        var client_data_hash: [32]u8 = undefined;
        sha256(client_data_json, &client_data_hash, .{});

        // Concatenate authenticator data and client data hash to form the signed data
        const signed_data_len = auth_data.len + client_data_hash.len;
        var signed_data = try allocator.alloc(u8, signed_data_len);
        defer allocator.free(signed_data);

        @memcpy(signed_data[0..auth_data.len], auth_data);
        @memcpy(signed_data[auth_data.len..], &client_data_hash);

        // Real signature from our test data
        const signature_b64 = "MEYCIQDQ-pXZQT9yjPsXT_m47W-iTFAIRgBVOCBhwl6kU--0RwIhAKcJJhxipw6tsIR0ULRgvQAhTaeIXk_V29wKOqbfP1oL";
        const signature = try base64urlToBytes(allocator, signature_b64);
        defer allocator.free(signature);

        // Verify the signature with normal case - should pass
        const verified = try verifySignature(allocator, public_key_b64, signature, signed_data);
        try testing.expect(verified);
    }

    // --- 2. Test with invalid CBOR ---
    {
        // Invalid CBOR test
        const invalid_cbor = "invalidCBORdataNotBase64";
        const dummy_sig = [_]u8{0} ** 64;
        const dummy_data = [_]u8{0} ** 32;

        // This should not crash, but return an error
        const result = verifySignature(allocator, invalid_cbor, &dummy_sig, &dummy_data);
        try testing.expectError(error.Malformed, result);
    }
}
