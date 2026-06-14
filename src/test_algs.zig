//! Per-algorithm signature verification tests for the COSE algorithm registry.
//!
//! EC and EdDSA vectors are generated deterministically in-test; the RSA family
//! (PSS and PKCS#1 with SHA-1/384) uses fixed vectors minted with OpenSSL so the
//! distinct hash/padding code paths are exercised against an external producer.
//! Each algorithm has a positive case and a tampered-signature negative case.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const passcay = @import("root.zig");
const crypto = passcay.crypto;

const List = std.array_list.Managed(u8);

// ---- minimal CBOR builders for COSE keys ----

fn appendHead(l: *List, major: u8, arg: u64) !void {
    if (arg < 24) {
        try l.append(major | @as(u8, @intCast(arg)));
    } else if (arg < 0x100) {
        try l.append(major | 0x18);
        try l.append(@intCast(arg));
    } else if (arg < 0x10000) {
        try l.append(major | 0x19);
        try l.append(@intCast(arg >> 8));
        try l.append(@intCast(arg & 0xFF));
    } else {
        try l.append(major | 0x1A);
        try l.append(@intCast(arg >> 24));
        try l.append(@intCast((arg >> 16) & 0xFF));
        try l.append(@intCast((arg >> 8) & 0xFF));
        try l.append(@intCast(arg & 0xFF));
    }
}

fn appendInt(l: *List, v: i64) !void {
    if (v >= 0) {
        try appendHead(l, 0x00, @intCast(v));
    } else {
        try appendHead(l, 0x20, @intCast(-1 - v));
    }
}

fn appendBstr(l: *List, bytes: []const u8) !void {
    try appendHead(l, 0x40, bytes.len);
    try l.appendSlice(bytes);
}

fn coseEc2(a: Allocator, alg: i64, crv: i64, x: []const u8, y: []const u8) ![]u8 {
    var l = List.init(a);
    try l.append(0xA5);
    try appendInt(&l, 1);
    try appendInt(&l, 2); // kty: EC2
    try appendInt(&l, 3);
    try appendInt(&l, alg);
    try appendInt(&l, -1);
    try appendInt(&l, crv);
    try appendInt(&l, -2);
    try appendBstr(&l, x);
    try appendInt(&l, -3);
    try appendBstr(&l, y);
    return l.toOwnedSlice();
}

fn coseOkp(a: Allocator, alg: i64, crv: i64, x: []const u8) ![]u8 {
    var l = List.init(a);
    try l.append(0xA4);
    try appendInt(&l, 1);
    try appendInt(&l, 1); // kty: OKP
    try appendInt(&l, 3);
    try appendInt(&l, alg);
    try appendInt(&l, -1);
    try appendInt(&l, crv);
    try appendInt(&l, -2);
    try appendBstr(&l, x);
    return l.toOwnedSlice();
}

fn coseRsa(a: Allocator, alg: i64, n: []const u8, e: []const u8) ![]u8 {
    var l = List.init(a);
    try l.append(0xA4);
    try appendInt(&l, 1);
    try appendInt(&l, 3); // kty: RSA
    try appendInt(&l, 3);
    try appendInt(&l, alg);
    try appendInt(&l, -1);
    try appendBstr(&l, n);
    try appendInt(&l, -2);
    try appendBstr(&l, e);
    return l.toOwnedSlice();
}

fn expectVerifyRoundTrip(a: Allocator, cose_key: []const u8, sig: []const u8, message: []const u8) !void {
    try testing.expect(try crypto.verifyWithCoseKey(a, cose_key, sig, message));

    const bad = try a.dupe(u8, sig);
    defer a.free(bad);
    bad[bad.len / 2] ^= 0xFF;
    try testing.expect(!try crypto.verifyWithCoseKey(a, cose_key, bad, message));
}

const msg = "passcay algorithm conformance message";

test "alg/EdDSA: Ed25519 (-8) round-trip" {
    const a = testing.allocator;
    const Ed = std.crypto.sign.Ed25519;
    const kp = try Ed.KeyPair.generateDeterministic(@splat(0x11));
    const sig = (try kp.sign(msg, null)).toBytes();

    const key = try coseOkp(a, -8, 6, &kp.public_key.toBytes()); // crv 6 = Ed25519
    defer a.free(key);
    try expectVerifyRoundTrip(a, key, &sig, msg);
}

test "alg/ES384: ECDSA P-384 (-35) round-trip" {
    const a = testing.allocator;
    const Ec = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    const kp = try Ec.KeyPair.generateDeterministic(@splat(0x22));
    const sec1 = kp.public_key.toUncompressedSec1(); // 0x04 || x(48) || y(48)

    var der_buf: [Ec.Signature.der_encoded_length_max]u8 = undefined;
    const der = (try kp.sign(msg, null)).toDer(&der_buf);

    const key = try coseEc2(a, -35, 2, sec1[1..49], sec1[49..97]); // crv 2 = P-384
    defer a.free(key);
    try expectVerifyRoundTrip(a, key, der, msg);
}

test "alg/ES256K: secp256k1 (-47) round-trip" {
    const a = testing.allocator;
    const Ec = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const kp = try Ec.KeyPair.generateDeterministic(@splat(0x33));
    const sec1 = kp.public_key.toUncompressedSec1();

    var der_buf: [Ec.Signature.der_encoded_length_max]u8 = undefined;
    const der = (try kp.sign(msg, null)).toDer(&der_buf);

    const key = try coseEc2(a, -47, 8, sec1[1..33], sec1[33..65]); // crv 8 = secp256k1
    defer a.free(key);
    try expectVerifyRoundTrip(a, key, der, msg);
}

// ---- RSA family: fixed OpenSSL vectors (one 2048-bit key, several schemes) ----

const rsa_msg = "passcay multi-RSA alg conformance test vector";
const rsa_n_b64 = "vrQsI9bPFaCjNo89JoSm_BRLspiJ5AKqVWFdL3r70YE8QfHT-3897QwjYzuHCNQvgbUIaom26ySV0uuxxYAd4guuu32q4Lp3jgnxRzt6mz_oIUI6FNFn7jvPQ0FjnDIh-hIQjFK8Uld9whNhy18f1UVf2ihBjd6iUSIXcnQ9fatQ7HgD3DIoHp0mDntglwm9Jud6y00iY6tjMIFmvics24VCzJ7Y3GQQvOHruJ1aHcO69d59SXRP35bYqyObxkyg9wgTmFRX2CxGj3-hzS9l_JyS6fqERleBAQLF8lqscOo5ifQzHgV-YHqFP2jZKuWPCLooPQ44jlZw1XrRtoXtyw";
const ps256_sig_b64 = "spAnmfcANsKJ8Pin2mF0fV9xTlmKcl4l2K7HjGgiKbL6-8Si41mKF-gj3zxUwz3dSM4AC2VFP099MI0Dsub8kMLLXEf4V8ubbaU8RODlGL97plGgCOHgltrDpcwqhGq9ml5PJJdLsyMk0fI2TPVEkfCMYS9bULh0BioMJAp-1A5IN8dk0pYaoOHSn0sgoFF-F3rFigyed8lQAwvNqP_0GvdMMQsaFnTDH8e24m4nOFmmUKP4dSbxgdulTWLmvv-Tq69cksRtxQ0tDJBBrcXA2CVmyYHdEL3_NKzxOx0JJmjo7iz6FO6vxfkAh1vRPeUvj2weIdVE4CEneSyA8hogrQ";
const rs384_sig_b64 = "FYlvmsIiraIm1qsoP62FFxoGX3LTlL6dIczGUcTXD7JyxRXZtrk0wzyNtReeFQzDl9QFm63U0mgv6wi1AwFqM0E9LpJz7TPZ8o6joss_WVtS0o03hP2S_GUIwvLVQC9LPLtxVJwObnjroExUXK_DJ5CQyX5ciIaONzyqKqp52K9TZM1o8gd01KcO_NNYsjDTSNpEU6KnGixoi8OfhmIOCXIr0ulbqzZDH98nFodHms6QIgl86eFFWZCJfHZTCesvOTdsqJ_rEKa_edMzTW8FydYLfs98ecg0iIQzIVFSLlpJ-WivP41Lua3ygkNR2T5uL4QsHigmOVVMH4WhXN0flw";
const rs1_sig_b64 = "SR72C693mMuwaiWJoKbQdMMiD0dxbsYcwQp7gJjxLjBxYEPRKAnQ8ZTNTMZtgRvp0XhexLnzAm64QhPRXrFCrBGp5MTtCk3QMUsrQLfm-vy92ti9t2CkuFXS2GgVbWY_3747QUJog_2M40ylgcn59HPxXa0bRJvP-lgjL9IIAt0yTkbhFBKZK6k7ueI7K5x4fqYJxfOazUX1yb98pD89gKScz4QLNiwzF95y86eJffL04lEbv9fUzU7Tya1biALEXwU1eCb7pJ6fz2ZNke-Fjy1xGYvPSs2mqOs_dIOG8a9TN3rjJoF3o1C7k9oJzX_KolnmMBJRc6JTPbOI-4WmPw";

fn rsaCase(alg: i64, sig_b64: []const u8) !void {
    const a = testing.allocator;
    const n = try passcay.util.decodeBase64Url(a, rsa_n_b64);
    defer a.free(n);
    const sig = try passcay.util.decodeBase64Url(a, sig_b64);
    defer a.free(sig);

    const key = try coseRsa(a, alg, n, &[_]u8{ 0x01, 0x00, 0x01 });
    defer a.free(key);
    try expectVerifyRoundTrip(a, key, sig, rsa_msg);
}

test "alg/PS256: RSASSA-PSS SHA-256 (-37) round-trip" {
    try rsaCase(-37, ps256_sig_b64);
}

test "alg/RS384: RSASSA-PKCS1 SHA-384 (-258) round-trip" {
    try rsaCase(-258, rs384_sig_b64);
}

test "alg/RS1: RSASSA-PKCS1 SHA-1 (-65535) round-trip" {
    try rsaCase(-65535, rs1_sig_b64);
}

test "alg/ES512: P-521 (-36) is reported unsupported (documented std gap)" {
    const a = testing.allocator;
    // A well-formed EC2 key labelled ES512 must be rejected as unsupported,
    // not silently mis-verified — P-521 is absent from std.crypto.
    const dummy: [66]u8 = @splat(0);
    const key = try coseEc2(a, -36, 3, &dummy, &dummy); // crv 3 = P-521
    defer a.free(key);
    const sig: [132]u8 = @splat(0);
    try testing.expectError(error.UnsupportedAlgorithm, crypto.verifyWithCoseKey(a, key, &sig, msg));
}
