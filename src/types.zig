//! Common WebAuthn types and structures
//!
//! Shared type definitions used across the WebAuthn implementation including
//! COSE keys, credentials, and error types.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const CoseAlg = enum(i32) {
    ES256 = -7, // ECDSA with SHA-256
    RS256 = -257, // RSASSA-PKCS1-v1_5 with SHA-256
    _,
};

pub const CoseKeyType = enum(i32) {
    OKP = 1, // Edwards curve
    EC2 = 2, // Elliptic curve with x,y coordinates
    RSA = 3, // RSA key
    _,
};

pub const CoseCurve = enum(i32) {
    P256 = 1, // NIST P-256 curve
    P384 = 2, // NIST P-384 curve
    P521 = 3, // NIST P-521 curve
    ED25519 = 6, // Edwards Ed25519 curve
    SECP256K1 = 8,
    _,
};

pub const CoseKey = enum(i32) {
    kty = 1, // Key type
    alg = 3, // Algorithm
    crv = -1, // Curve (for EC/OKP keys)
    x = -2, // X coordinate (for EC/OKP keys)
    y = -3, // Y coordinate (for EC keys)
    n = -1, // RSA modulus
    e = -2, // RSA exponent
    _,
};

pub const WebAuthnError = error{
    // Common errors
    InvalidAuthenticatorData,
    MissingAuthData,
    ChallengeMismatch,
    OriginMismatch,
    RpIdHashMismatch,
    VerificationFailed,
    UserPresenceFlagNotSet,
    UserVerificationRequired,
    SignatureCounterMismatch,

    // Credential-specific errors
    MissingCredentialId,
    MissingCredentialPublicKey,
    MissingAttestedCredentialData,
    MissingAAGUID,

    // Format errors
    InvalidClientDataType,
    InvalidAttestationFormat,
    InvalidRpIdHash,
    MissingUserPresenceFlag,
    MissingUserVerificationFlag,
    InvalidCoseKey,

    // Crypto errors
    SignatureVerificationFailed,
};

pub const VerifyError = error{
    InvalidPublicKey,
    InvalidSignature,
    UnsupportedAlgorithm,
    UnsupportedKeyType,
    UnsupportedCurve,
    MissingKeyComponent,
    Base64DecodingFailed,
    AllocationFailed,
    VerificationFailed,
    LibraryError,
    CBORParsingFailed,
    InvalidKeyFormat,
    InvalidCharacter,
};

/// Flag values for AuthenticatorData
pub const AuthenticatorDataFlag = enum(u8) {
    /// User Present (UP) - user has interacted with the authenticator
    userPresent = 0x01,
    /// User Verified (UV) - user has been verified by the authenticator
    userVerified = 0x04,
    /// Attested credential data included
    attestedCredentialData = 0x40,
};

/// Verification policy for user verification
pub const UserVerificationPolicy = enum {
    /// User verification is required (e.g. PIN, biometric)
    required,
    /// User verification is preferred but not required
    preferred,
    /// User verification is discouraged
    discouraged,
};

/// Parsed client data JSON structure
pub const ClientData = struct {
    type: []const u8,
    challenge: []const u8,
    origin: []const u8,

    /// Free all allocated memory in the ClientData structure
    pub fn deinit(self: *const ClientData, allocator: Allocator) void {
        allocator.free(self.type);
        allocator.free(self.challenge);
        allocator.free(self.origin);
    }
};

pub const AuthenticatorData = struct {
    rp_id_hash: []const u8,
    flags: u8,
    sign_count: u32,
    attested_credential_data: []const u8,

    owned: bool = false,

    pub fn deinit(self: *const AuthenticatorData, allocator: Allocator) void {
        if (self.owned) {
            allocator.free(self.rp_id_hash);
            if (self.attested_credential_data.len > 0) {
                allocator.free(self.attested_credential_data);
            }
        }
    }
};

pub const ClientDataJson = struct {
    type: []const u8,
    challenge: []const u8,
    origin: []const u8,
    crossOrigin: ?bool = false,
};

pub const CredentialAuthData = struct {
    rp_id_hash: []const u8,
    flags: u8,
    sign_count: u32,
    credential_id: ?[]const u8,
    credential_public_key: ?[]const u8,
    aaguid: ?[]const u8,

    pub fn deinit(self: *const CredentialAuthData, allocator: Allocator) void {
        allocator.free(self.rp_id_hash);

        if (self.credential_id != null) {
            allocator.free(self.credential_id.?);
        }

        if (self.credential_public_key != null) {
            allocator.free(self.credential_public_key.?);
        }

        if (self.aaguid != null) {
            allocator.free(self.aaguid.?);
        }
    }
};

pub const PublicKey = struct {
    bytes: []const u8,
    algorithm: CoseAlg,

    pub fn parse(allocator: Allocator, key_bytes: []const u8, alg: CoseAlg) !PublicKey {
        const bytes_copy = try allocator.dupe(u8, key_bytes);
        return PublicKey{
            .bytes = bytes_copy,
            .algorithm = alg,
        };
    }

    pub fn deinit(self: PublicKey, allocator: Allocator) void {
        allocator.free(self.bytes);
    }
};
