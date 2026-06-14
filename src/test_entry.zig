//! Test entry point for passcay
//! This file ensures all tests from all modules are run

// Import all modules for testing
test {
    // Types and core modules
    _ = @import("types.zig");
    _ = @import("challenge.zig");
    _ = @import("auth.zig");
    _ = @import("register.zig");

    // Utility modules
    _ = @import("util.zig");
    _ = @import("crypto.zig");
    _ = @import("cbor.zig");
    _ = @import("alg.zig");

    // Attestation verification
    _ = @import("attestation/mod.zig");
    _ = @import("attestation/none.zig");
    _ = @import("attestation/packed_fmt.zig");
    _ = @import("attestation/fido_u2f.zig");
    _ = @import("attestation/tpm.zig");

    // X.509 / ASN.1, JWS, MDS
    _ = @import("x509/mod.zig");
    _ = @import("x509/asn1.zig");
    _ = @import("x509/crl.zig");
    _ = @import("jws.zig");
    _ = @import("mds/mod.zig");

    // Public API
    _ = @import("public.zig");

    // Real WebAuthn data tests
    _ = @import("test_actual_case.zig");

    // Conformance harness (Layer A) and shared vectors
    _ = @import("test_data.zig");
    _ = @import("test_conformance.zig");
    _ = @import("test_algs.zig");
}
