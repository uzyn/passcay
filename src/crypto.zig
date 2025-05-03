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

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/err.h");
});

/// Initialize OpenSSL libraries - must be called before any crypto operations
pub fn initOpenSSL() !void {
    // Initialize OpenSSL libraries with only the essential calls
    _ = c.OPENSSL_init_ssl(0, null);
}

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

/// Unwrap EC2 signature from ASN.1 DER format to raw format
/// Returns a pair of r and s values concatenated
fn unwrapEC2Signature(allocator: Allocator, signature: []const u8) ![]u8 {
    if (signature.len < 8) return VerifyError.InvalidSignature;
    if (signature[0] != 0x30) return VerifyError.InvalidSignature; // SEQUENCE

    const seq_len: usize = @as(usize, signature[1]);
    // Add 2 (for tag and length) but guard against overflow
    if (seq_len > signature.len or 2 > signature.len - seq_len) return VerifyError.InvalidSignature;

    var idx: usize = 2;

    if (idx >= signature.len) return VerifyError.InvalidSignature;
    if (signature[idx] != 0x02) return VerifyError.InvalidSignature; // INTEGER
    idx += 1;

    if (idx >= signature.len) return VerifyError.InvalidSignature;
    const r_len = signature[idx];
    idx += 1;

    if (idx + r_len > signature.len) return VerifyError.InvalidSignature;
    var r_start: usize = idx;
    var r_trimmed_len = r_len;

    while (r_trimmed_len > 0 and signature[r_start] == 0) {
        r_start += 1;
        r_trimmed_len -= 1;
    }

    idx += r_len;

    if (idx >= signature.len) return VerifyError.InvalidSignature;
    if (signature[idx] != 0x02) return VerifyError.InvalidSignature; // INTEGER
    idx += 1;

    if (idx >= signature.len) return VerifyError.InvalidSignature;
    const s_len = signature[idx];
    idx += 1;

    if (idx + s_len > signature.len) return VerifyError.InvalidSignature;
    var s_start: usize = idx;
    var s_trimmed_len = s_len;
    while (s_trimmed_len > 0 and signature[s_start] == 0) {
        s_start += 1;
        s_trimmed_len -= 1;
    }

    // P-256 curve always uses 32 bytes per component
    const component_len: usize = 32;

    const raw_sig = try allocator.alloc(u8, component_len * 2);
    errdefer allocator.free(raw_sig);
    @memset(raw_sig, 0);

    if (r_trimmed_len <= component_len) {
        if (r_trimmed_len > component_len) return VerifyError.InvalidSignature;
        const r_offset = component_len - r_trimmed_len;

        if (r_trimmed_len > 0 and r_start > signature.len - r_trimmed_len) return VerifyError.InvalidSignature;
        if (r_offset > component_len) return VerifyError.InvalidSignature;

        @memcpy(raw_sig[r_offset..component_len], signature[r_start .. r_start + r_trimmed_len]);
    } else {
        if (r_trimmed_len < component_len) return VerifyError.InvalidSignature;

        if (r_trimmed_len > signature.len - r_start) return VerifyError.InvalidSignature;
        if (r_start + r_trimmed_len - component_len > r_start + r_trimmed_len) return VerifyError.InvalidSignature;

        @memcpy(raw_sig[0..component_len], signature[r_start + r_trimmed_len - component_len .. r_start + r_trimmed_len]);
    }

    if (s_trimmed_len <= component_len) {
        if (s_trimmed_len > component_len) return VerifyError.InvalidSignature;
        const s_offset = component_len - s_trimmed_len;

        if (s_trimmed_len > 0 and s_start > signature.len - s_trimmed_len) return VerifyError.InvalidSignature;
        if (component_len + s_offset > raw_sig.len) return VerifyError.InvalidSignature;

        @memcpy(raw_sig[component_len + s_offset ..], signature[s_start .. s_start + s_trimmed_len]);
    } else {
        if (s_trimmed_len < component_len) return VerifyError.InvalidSignature;

        if (s_trimmed_len > signature.len - s_start) return VerifyError.InvalidSignature;
        if (s_start + s_trimmed_len - component_len > s_start + s_trimmed_len) return VerifyError.InvalidSignature;
        if (component_len * 2 > raw_sig.len) return VerifyError.InvalidSignature;

        @memcpy(raw_sig[component_len..], signature[s_start + s_trimmed_len - component_len .. s_start + s_trimmed_len]);
    }

    return raw_sig;
}

/// Verify a signature using ES256 algorithm (ECDSA with P-256 curve and SHA-256)
fn verifyES256(allocator: Allocator, public_key_bytes: []const u8, data: []const u8, signature: []const u8) !bool {
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

    const x_bytes_unwrapped = x_bytes.?;
    const y_bytes_unwrapped = y_bytes.?;

    // Create an OpenSSL EC_KEY
    const ec_key = c.EC_KEY_new_by_curve_name(c.NID_X9_62_prime256v1) orelse
        return VerifyError.LibraryError;
    defer c.EC_KEY_free(ec_key);

    // Set the x and y coordinates
    const ec_group = c.EC_KEY_get0_group(ec_key);
    const ec_point = c.EC_POINT_new(ec_group) orelse
        return VerifyError.LibraryError;
    defer c.EC_POINT_free(ec_point);

    // Convert x and y bytes to BIGNUM
    const bn_ctx = c.BN_CTX_new() orelse
        return VerifyError.LibraryError;
    defer c.BN_CTX_free(bn_ctx);

    const bn_x = c.BN_bin2bn(x_bytes_unwrapped.ptr, @intCast(x_bytes_unwrapped.len), null) orelse
        return VerifyError.LibraryError;
    defer c.BN_free(bn_x);

    const bn_y = c.BN_bin2bn(y_bytes_unwrapped.ptr, @intCast(y_bytes_unwrapped.len), null) orelse
        return VerifyError.LibraryError;
    defer c.BN_free(bn_y);

    if (c.EC_POINT_set_affine_coordinates(ec_group, ec_point, bn_x, bn_y, bn_ctx) != 1) {
        return VerifyError.InvalidPublicKey;
    }

    if (c.EC_KEY_set_public_key(ec_key, ec_point) != 1) {
        return VerifyError.InvalidPublicKey;
    }

    const raw_sig = try unwrapEC2Signature(allocator, signature);
    defer allocator.free(raw_sig);

    const sig = c.ECDSA_SIG_new() orelse
        return VerifyError.LibraryError;
    defer c.ECDSA_SIG_free(sig);

    if (raw_sig.len < 2) {
        return VerifyError.InvalidSignature;
    }

    const half_len = raw_sig.len / 2;

    var r_ptr: ?*c.BIGNUM = null;
    var s_ptr: ?*c.BIGNUM = null;

    r_ptr = c.BN_bin2bn(raw_sig.ptr, @intCast(half_len), null) orelse
        return VerifyError.LibraryError;
    errdefer if (r_ptr) |ptr| c.BN_free(ptr);

    s_ptr = c.BN_bin2bn(raw_sig.ptr + half_len, @intCast(half_len), null) orelse {
        if (r_ptr) |ptr| c.BN_free(ptr);
        return VerifyError.LibraryError;
    };
    errdefer if (s_ptr) |ptr| c.BN_free(ptr);

    if (r_ptr != null and s_ptr != null) {
        if (c.ECDSA_SIG_set0(sig, r_ptr.?, s_ptr.?) != 1) {
            c.BN_free(r_ptr.?);
            c.BN_free(s_ptr.?);
            return VerifyError.LibraryError;
        }
    } else {
        return VerifyError.LibraryError;
    }

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});

    const result = c.ECDSA_do_verify(
        &digest,
        @intCast(digest.len),
        sig,
        ec_key,
    );

    if (result == -1) {
        return VerifyError.LibraryError;
    }

    return result == 1;
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

    const n_bytes_unwrapped = n_bytes.?;
    const e_bytes_unwrapped = e_bytes.?;

    const rsa = c.RSA_new() orelse
        return VerifyError.LibraryError;
    defer c.RSA_free(rsa);

    var bn_n_ptr: ?*c.BIGNUM = null;
    var bn_e_ptr: ?*c.BIGNUM = null;

    bn_n_ptr = c.BN_bin2bn(n_bytes_unwrapped.ptr, @intCast(n_bytes_unwrapped.len), null) orelse
        return VerifyError.LibraryError;
    errdefer if (bn_n_ptr) |ptr| c.BN_free(ptr);

    bn_e_ptr = c.BN_bin2bn(e_bytes_unwrapped.ptr, @intCast(e_bytes_unwrapped.len), null) orelse {
        if (bn_n_ptr) |ptr| c.BN_free(ptr);
        return VerifyError.LibraryError;
    };
    errdefer if (bn_e_ptr) |ptr| c.BN_free(ptr);

    if (bn_n_ptr != null and bn_e_ptr != null) {
        if (c.RSA_set0_key(rsa, bn_n_ptr.?, bn_e_ptr.?, null) != 1) {
            c.BN_free(bn_n_ptr.?);
            c.BN_free(bn_e_ptr.?);
            return VerifyError.InvalidPublicKey;
        }
    } else {
        return VerifyError.LibraryError;
    }

    const pkey = c.EVP_PKEY_new() orelse
        return VerifyError.LibraryError;
    defer c.EVP_PKEY_free(pkey);

    if (c.EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        return VerifyError.LibraryError;
    }

    const ctx = c.EVP_MD_CTX_new() orelse
        return VerifyError.LibraryError;
    defer c.EVP_MD_CTX_free(ctx);

    if (c.EVP_DigestVerifyInit(ctx, null, c.EVP_sha256(), null, pkey) != 1) {
        return VerifyError.LibraryError;
    }

    if (c.EVP_DigestVerifyUpdate(ctx, data.ptr, data.len) != 1) {
        return VerifyError.LibraryError;
    }

    const result = c.EVP_DigestVerifyFinal(
        ctx,
        signature.ptr,
        signature.len,
    );

    if (result == -1) {
        return VerifyError.LibraryError;
    }

    return result == 1;
}

pub fn verifySignature(allocator: Allocator, public_key_base64url: []const u8, signature: []const u8, data: []const u8) !bool {
    try initOpenSSL();

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

    try initOpenSSL();

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

    try initOpenSSL();

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

    try initOpenSSL();

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

test "memory safety in OpenSSL integration" {
    const allocator = testing.allocator;

    try initOpenSSL();

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

    // --- 2. Error case - directly test the unwrapEC2Signature function ---
    {
        // Test with an empty signature
        {
            const empty_sig = [_]u8{};
            const result = unwrapEC2Signature(allocator, &empty_sig);
            try testing.expectError(error.InvalidSignature, result);
        }

        // Test with a signature that's too short
        {
            const short_sig = [_]u8{ 0x30, 0x02, 0x02, 0x00 };
            const result = unwrapEC2Signature(allocator, &short_sig);
            try testing.expectError(error.InvalidSignature, result);
        }

        // Test with a signature that has a wrong tag
        {
            // Not a SEQUENCE tag
            const wrong_tag_sig = [_]u8{ 0x31, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00 };
            const result = unwrapEC2Signature(allocator, &wrong_tag_sig);
            try testing.expectError(error.InvalidSignature, result);
        }

        // Test with a signature that has an unreasonable length
        {
            // Sequence length that's reasonable for testing (0x10 instead of 0xFF)
            const wrong_len_sig = [_]u8{ 0x30, 0x10, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
            const result = unwrapEC2Signature(allocator, &wrong_len_sig);
            try testing.expectError(error.InvalidSignature, result);
        }
    }

    // --- 3. Check robustness with direct testing of the ASN.1 DER unwrapper ---
    {
        // Create a minimal valid ASN.1 DER structure
        const min_der = [_]u8{
            0x30, 0x06, // SEQUENCE, length 6
            0x02, 0x01, 0x01, // INTEGER, length 1, value 1 (r)
            0x02, 0x01, 0x02, // INTEGER, length 1, value 2 (s)
        };

        // This should be handled without crashing
        if (unwrapEC2Signature(allocator, &min_der)) |sig| {
            defer allocator.free(sig);
            try testing.expect(sig.len == 64); // P256 = 32 bytes per component
        } else |err| {
            // Even if it fails, it shouldn't crash
            try testing.expectEqual(error.InvalidSignature, err);
        }
    }

    // --- 4. Test with invalid CBOR ---
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
