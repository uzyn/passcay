//! passcay - server-side WebAuthn (passkey) library for Zig
//! Zero dependency implementation supporting passkey-compatible authenticators.
//!
//! This file defines the public API for the passcay library. Only the functions
//! and types exported here are accessible to consumers of the library.

// Direct imports from each module
const challenge_mod = @import("challenge.zig");
const auth_mod = @import("auth.zig");
const register_mod = @import("register.zig");
const util_mod = @import("util.zig");
const types_mod = @import("types.zig");

// Public API - only expose the core verification functions
pub const challenge = struct {
    /// Generate a cryptographically secure 32-byte random challenge for WebAuthn operations
    /// Returns base64url-encoded string that can be sent to the client
    pub const generate = challenge_mod.generate;

    /// Generate a challenge with a specific size in bytes
    /// Returns base64url-encoded string that can be sent to the client
    pub const generateWithSize = challenge_mod.generateWithSize;

    /// Default challenge size in bytes
    pub const DEFAULT_CHALLENGE_SIZE = challenge_mod.DEFAULT_CHALLENGE_SIZE;
};

pub const auth = struct {
    /// Verify a WebAuthn authentication assertion
    ///
    /// Verifies an authentication assertion with customizable security checks.
    /// Always requires user presence. Sign count verification can be enabled
    /// for replay detection. Automatically detects ES256 or RS256 algorithm.
    ///
    /// Returns an AuthVerifyResult with the new sign count to store if verification succeeds.
    pub const verify = auth_mod.verify;

    /// Authentication verification input data
    pub const AuthVerifyInput = auth_mod.AuthVerifyInput;

    /// Verification expectations for WebAuthn authentication
    pub const AuthVerifyExpectations = auth_mod.AuthVerifyExpectations;

    /// Result of a successful authentication verification
    pub const AuthVerifyResult = auth_mod.AuthVerifyResult;
};

pub const register = struct {
    /// Verify a WebAuthn registration response
    ///
    /// Verifies a registration response with customizable security checks.
    /// Always requires "webauthn.create" type.
    /// Returns credential data to store if verification succeeds.
    pub const verify = register_mod.verify;

    /// Registration verification input data
    pub const RegVerifyInput = register_mod.RegVerifyInput;

    /// Verification expectations for WebAuthn registration
    pub const RegVerifyExpectations = register_mod.RegVerifyExpectations;

    /// Result of a successful registration verification
    pub const RegVerifyResult = register_mod.RegVerifyResult;

    /// Use the common WebAuthnError type from types module
    pub const RegistrationError = register_mod.RegistrationError;
};

// Utility functions needed for demos - minimal exposure
pub const util = struct {
    /// Base64URL decode a string to raw bytes
    pub const decodeBase64Url = util_mod.decodeBase64Url;

    /// Encode raw bytes to base64url string
    pub const encodeBase64Url = util_mod.encodeBase64Url;
};

// Common types needed for the public API
pub const WebAuthnError = types_mod.WebAuthnError;
pub const CoseAlg = types_mod.CoseAlg;
pub const AuthenticatorDataFlag = types_mod.AuthenticatorDataFlag;
pub const UserVerificationPolicy = types_mod.UserVerificationPolicy;
