//! Attestation statement verification.
//!
//! Dispatches an attestation object's `fmt` to the matching verifier and
//! enforces the relying party's attestation policy. Attestation verification
//! is opt-in: callers that pass no policy to `register.verify` skip this layer
//! entirely (privacy-preserving "none"/passkey usage is unaffected).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const none_fmt = @import("none.zig");
const packed_fmt = @import("packed_fmt.zig");
const fido_u2f = @import("fido_u2f.zig");
const tpm_fmt = @import("tpm.zig");
pub const mds = @import("../mds/mod.zig");

/// WebAuthn attestation trust types (§6.5.3).
pub const AttestationType = enum {
    none,
    self,
    basic,
    attca,
    anonca,
};

/// Inputs an attestation-format verifier needs.
pub const VerifyParams = struct {
    /// Attestation format identifier (e.g. "none", "packed").
    fmt: []const u8,
    /// Raw CBOR bytes of the attestation statement (attStmt) map.
    att_stmt: []const u8,
    /// Raw authenticator data bytes (the message base, with clientDataHash).
    auth_data: []const u8,
    /// SHA-256 of the clientDataJSON.
    client_data_hash: []const u8,
    /// Raw CBOR bytes of the credential public key (COSE_Key).
    credential_public_key: []const u8,
    /// Authenticator AAGUID (16 bytes).
    aaguid: []const u8,
    /// Credential ID (needed by fido-u2f verification data).
    credential_id: []const u8 = &.{},
};

pub const Result = struct {
    /// Attestation trust type determined from the statement's structure.
    /// IMPORTANT: `.basic`/`.attca` mean the attestation signature and chain are
    /// *format-valid*, not that the chain is anchored to a trusted root —
    /// root-of-trust is only enforced when `Policy.roots` or `Policy.mds` is
    /// supplied. Do not treat the type alone as proof of a trusted authenticator.
    type: AttestationType,
};

/// Relying party attestation policy.
pub const Policy = struct {
    /// If non-null, only these attestation formats are accepted.
    allowed_formats: ?[]const []const u8 = null,
    /// Whether "none" attestation (no cryptographic proof) is acceptable.
    allow_none: bool = true,
    /// Whether self attestation is acceptable.
    allow_self: bool = true,
    /// Trust anchors (raw DER root certificates) for full attestation chains.
    /// Empty accepts a self-signed chain top (dev/test); production should
    /// supply roots, typically from the FIDO metadata service.
    roots: []const []const u8 = &.{},
    /// Verification instant (Unix seconds) for certificate time validity.
    /// null SKIPS expiry / not-yet-valid checks (each link is verified at its
    /// own notBefore) — convenient for borrowed/expired test vectors, but a
    /// production caller enabling attestation should pass the current time so
    /// expired attestation certificates are rejected.
    now_sec: ?i64 = null,
    /// FIDO metadata store. When set, full attestation resolves trust anchors
    /// and status reports by AAGUID (overriding `roots`); the AAGUID must be
    /// present in the store and not flagged compromised.
    mds: ?*const mds.Store = null,
};

pub const Error = error{
    UnsupportedAttestationFormat,
    AttestationFormatNotAllowed,
    AttestationTypeNotAllowed,
    InvalidAttestationStatement,
    AttestationSignatureInvalid,
    AttestationAlgorithmMismatch,
    AttestationChainUntrusted,
    AttestationAaguidMismatch,
    AttestationAaguidUnknown,
    AttestationAuthenticatorCompromised,
    AttestationCertInvalid,
    AttestationNotImplemented,
};

/// Resolve trust anchors for a full-attestation chain, applying MDS status
/// gating when a metadata store is configured.
pub fn resolveAnchors(policy: Policy, aaguid: []const u8) ![]const []const u8 {
    if (policy.mds) |store| {
        const entry = store.lookup(aaguid) orelse return Error.AttestationAaguidUnknown;
        mds.Store.checkStatus(entry) catch return Error.AttestationAuthenticatorCompromised;
        return entry.roots;
    }
    return policy.roots;
}

/// Verify an attestation statement against a policy.
pub fn verify(allocator: Allocator, params: VerifyParams, policy: Policy) !Result {
    if (policy.allowed_formats) |list| {
        var allowed = false;
        for (list) |f| {
            if (mem.eql(u8, f, params.fmt)) {
                allowed = true;
                break;
            }
        }
        if (!allowed) return Error.AttestationFormatNotAllowed;
    }

    const result = if (mem.eql(u8, params.fmt, "none"))
        try none_fmt.verify(allocator, params)
    else if (mem.eql(u8, params.fmt, "packed"))
        try packed_fmt.verify(allocator, params, policy)
    else if (mem.eql(u8, params.fmt, "fido-u2f"))
        try fido_u2f.verify(allocator, params, policy)
    else if (mem.eql(u8, params.fmt, "tpm"))
        try tpm_fmt.verify(allocator, params, policy)
    else
        return Error.UnsupportedAttestationFormat;

    switch (result.type) {
        .none => if (!policy.allow_none) return Error.AttestationTypeNotAllowed,
        .self => if (!policy.allow_self) return Error.AttestationTypeNotAllowed,
        else => {},
    }

    // When metadata is configured, the produced attestation type must be one of
    // the authenticator model's declared attestationTypes (FIDO MDS). This
    // rejects, e.g., a full attestation from a model that only does surrogate/
    // self attestation.
    if (policy.mds) |store| {
        const aaguid = params.aaguid;
        switch (result.type) {
            // A packed/fido-u2f x5c chain is "Basic OR AttCA" (WebAuthn §6.5.3):
            // the on-wire format is identical and we do not distinguish the two,
            // so accept if the model's metadata permits either.
            .basic => if (!store.attestationTypeAllowed(aaguid, .basic_full) and
                !store.attestationTypeAllowed(aaguid, .attca))
                return Error.AttestationTypeNotAllowed,
            .self => if (!store.attestationTypeAllowed(aaguid, .basic_surrogate))
                return Error.AttestationTypeNotAllowed,
            .attca => if (!store.attestationTypeAllowed(aaguid, .attca))
                return Error.AttestationTypeNotAllowed,
            .anonca => if (!store.attestationTypeAllowed(aaguid, .anonca))
                return Error.AttestationTypeNotAllowed,
            .none => {},
        }
    }

    return result;
}
