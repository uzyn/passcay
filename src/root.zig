//! passcay - server-side WebAuthn (passkey) library for Zig
//! Zero dependency implementation supporting passkey-compatible authenticators.
const std = @import("std");
const testing = std.testing;

pub const types = @import("types.zig");
pub const challenge = @import("challenge.zig");
pub const auth = @import("auth.zig");
pub const register = @import("register.zig");
pub const util = @import("util.zig");
pub const crypto = @import("crypto.zig");
pub const cbor = @import("cbor.zig");
pub const alg = @import("alg.zig");
pub const attestation = @import("attestation/mod.zig");
pub const x509 = @import("x509/mod.zig");
pub const jws = @import("jws.zig");
pub const mds = @import("mds/mod.zig");

pub const WebAuthnError = types.WebAuthnError;
pub const CoseAlg = types.CoseAlg;
pub const AuthenticatorDataFlag = types.AuthenticatorDataFlag;
pub const UserVerificationPolicy = types.UserVerificationPolicy;

test "basic tests" {
    _ = types;
    _ = challenge;
    _ = auth;
    _ = register;
    _ = util;
    _ = crypto;
    _ = cbor;
}

comptime {
    if (@import("builtin").is_test) _ = @import("test_entry.zig");
}
