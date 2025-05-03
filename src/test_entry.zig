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

    // Public API
    _ = @import("public.zig");

    // Real WebAuthn data tests
    _ = @import("test_actual_case.zig");
}
