# FIDO2 Conformance Test Server

This is a minimal implementation of a FIDO2 conformance test server that implements the required API for FIDO2 conformance testing. It uses the Passcay library for server-side WebAuthn operations.

It implements [FIDO2: Conformance testing server API](https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Server/Conformance-Test-API.md)

## Overview

This project implements a complete HTTP server using Karl Seguin's http.zig library to create a FIDO2 conformance test server. It demonstrates how to use the Passcay library for FIDO2 operations and provides a working HTTP API that conforms to the FIDO2 conformance testing requirements.

The implementation supports both ES256 (ECDSA with P-256) and RS256 (RSA-PKCS1-v1_5 with SHA-256) signature algorithms for WebAuthn operations.

## Features

- Complete HTTP server implementation with all required FIDO2 endpoints
- In-memory storage for user credentials and challenges
- Support for both ES256 and RS256 verification
- Built-in verification tests for both algorithms
- Comprehensive error handling and JSON responses
- Challenge generation and verification
- Base64URL encoding utilities

## HTTP API Endpoints

The server implements the following endpoints required by the FIDO2 conformance test suite:

### Registration (Attestation)

- `POST /attestation/options` - Get options for WebAuthn credential creation
- `POST /attestation/result` - Register a new credential with attestation

### Authentication (Assertion)

- `POST /assertion/options` - Get options for WebAuthn credential verification
- `POST /assertion/result` - Verify an existing credential

## Building and Running

To build and run the server:

```bash
# Navigate to the conformance directory
cd conformance

# Build the server
zig build

# Run the server
zig build run
```

The server will:
1. Run verification tests for ES256 and RS256 to ensure the Passcay library is working correctly
2. Start an HTTP server on port 8080 (configurable in main.zig)
3. Accept requests on all the required FIDO2 endpoints

## Test Data

The implementation includes test data for both ES256 and RS256:

## Usage with Conformance Tools

The FIDO2 conformance test tool can be configured to use the following URLs:

- Registration:
  - Options URL: `http://localhost:8080/attestation/options`
  - Result URL: `http://localhost:8080/attestation/result`

- Authentication:
  - Options URL: `http://localhost:8080/assertion/options`
  - Result URL: `http://localhost:8080/assertion/result`

## Security Considerations

This implementation is intended for testing purposes only.
