# Passcay
[![Tests](https://github.com/uzyn/passcay/actions/workflows/test.yml/badge.svg)](https://github.com/uzyn/passcay/actions/workflows/test.yml)
[![Latest release](https://img.shields.io/github/v/tag/uzyn/passcay?label=release&sort=semver)](https://github.com/uzyn/passcay/tags)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16-f7a41d.svg)](https://ziglang.org)
[![WebAuthn / FIDO2](https://img.shields.io/badge/WebAuthn-FIDO2-6f42c1.svg)](https://www.w3.org/TR/webauthn/)
[![FIDO2 Server Conformance](https://img.shields.io/badge/FIDO2%20Server-conformant-2ea44f.svg)](https://fidoalliance.org/certification/functional-certification/conformance/)

![Passcay Logo](docs/passcay-logo.png)


**Minimal**, **fast** and **secure** Passkey (WebAuthn) relying party (RP) library for Zig.

Zig version support:
1. v3.x - Supports Zig v0.16. First version with no system dependencies (OpenSSL is no longer required).
2. v2.x - Supports Zig v0.15
3. v1.x - Supports Zig v0.14

## Features

- Passkey WebAuthn registration & authentication (login)
- **FIDO2 conformant** — passes the [official FIDO Alliance FIDO2 Server conformance test suite](https://fidoalliance.org/certification/functional-certification/conformance/) (100%)
- **Attestation-less by default** — privacy-preserving and recommended for passkeys (does not affect security)
- **Optional attestation verification** (opt-in): `none`, `packed` (full + self), `fido-u2f`, and `tpm` — covering platform authenticators like **Windows Hello** (TPM) and roaming security keys — with real X.509 certificate-chain validation
- **FIDO Metadata Service (MDS3)** integration: anchor attestation chains by AAGUID, gate on authenticator status reports, and reject BLOBs signed by a CRL-revoked certificate
- **Broad COSE algorithm support** — ES256/384, secp256k1, Ed25519, RS256/384/512, RS1, PS256/384/512 (see table below)
- Secure challenge generation
- No system dependencies — pure `std.crypto`, builds and cross-compiles anywhere Zig runs

### Supported algorithms

| COSE alg | Algorithm | Status |
|---|---|---|
| `-7` | ES256 (ECDSA P-256) | ✅ |
| `-35` | ES384 (ECDSA P-384) | ✅ |
| `-47` | ES256K (ECDSA secp256k1) | ✅ |
| `-8` | EdDSA (Ed25519) | ✅ |
| `-257` / `-258` / `-259` | RS256 / RS384 / RS512 (RSASSA-PKCS1-v1_5) | ✅ |
| `-37` / `-38` / `-39` | PS256 / PS384 / PS512 (RSASSA-PSS) | ✅ |
| `-65535` | RS1 (RSASSA-PKCS1-v1_5 SHA-1, legacy) | ✅ |

ES256 and RS256 cover virtually all passkey authenticators today; the others broaden coverage for FIDO2 and non-passkey deployments.

## Dependencies

No system dependencies. Cryptographic verification uses Zig's standard library (`std.crypto`), so Passcay builds and cross-compiles anywhere Zig runs, including Windows and macOS.

### Installation

Add `passcay` to your Zig project (`build.zig.zon`) dependencies:

```sh
zig fetch --save git+https://github.com/uzyn/passcay.git

# or load a specific version
zig fetch --save git+https://github.com/uzyn/passcay.git#3.1.0
```

And update your `build.zig` to load `passcay`:

```zig
const passcay = b.dependency("passcay", .{
    .optimize = optimize,
    .target = target,
});
exe.root_module.addImport("passcay", passcay.module("passcay"));
```

## Build & Test

```sh
zig build
zig build test --summary all
```

## Usage

### Registration

```zig
const passcay = @import("passcay");

const input = passcay.register.RegVerifyInput{
     .attestation_object = attestation_object,
     .client_data_json = client_data_json,
};

const expectations = passcay.register.RegVerifyExpectations{
     .challenge = challenge,
     .origin = "https://example.com",
     .rp_id = "example.com",
     .require_user_verification = true,
};

const reg = try passcay.register.verify(allocator, input, expectations);

// Save reg.credential_id, reg.public_key, and reg.sign_count
// to database for authentication
```

Store the following in database for authentication:
- `reg.credential_id`
- `reg.public_key`
- `reg.sign_count` (usually starts at 0)

### Attestation verification (optional)

By default Passcay is attestation-less (recommended for passkeys). To cryptographically verify the attestation statement, pass an `attestation` policy:

```zig
const reg = try passcay.register.verify(allocator, input, .{
    .challenge = challenge,
    .origin = "https://example.com",
    .rp_id = "example.com",
    .require_user_verification = true,
    .attestation = .{}, // verify the attestation statement (none / packed / fido-u2f / tpm)
});
// reg.attestation_type -> .none, .self, .basic, .attca, ...
```

For full (x5c) attestation, supply trust anchors directly with `.roots`, or a FIDO
Metadata Service store with `.mds` to anchor chains by AAGUID and enforce status reports:

```zig
.attestation = .{ .mds = &metadata_store }, // passcay.mds.Store
```

### Authentication

```zig
const challenge = try passcay.challenge.generate(io, allocator);
// Pass challenge to client-side for authentication

const input = passcay.auth.AuthVerifyInput{
    .authenticator_data = authenticator_data,
    .client_data_json = client_data_json,
    .signature = signature,
};

const expectations = passcay.auth.AuthVerifyExpectations{
    .public_key = user_public_key, // Retrieve public_key from database, given credential_id from navigator.credentials.get
    .challenge = challenge,
    .origin = "https://example.com",
    .rp_id = "example.com",
    .require_user_verification = true,
    .enable_sign_count_check = true,
    .known_sign_count = stored_sign_count,
};

const auth = try passcay.auth.verify(allocator, input, expectations);
```

Update the stored sign count with `auth.recommended_sign_count`:

### Client-Side (JavaScript)

```javascript
// Registration
const regOptions = {
    challenge: base64UrlDecode(challenge),
    rp: {
        name: "Example",
        id: "example.com", // Must match your domain without protocol/port
    },
    user: { name: username },
    pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256 (Most widely supported)
        { type: "public-key", alg: -257 }, // RS256
    ],
    authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required", // or "preferred"
    },
    attestation: "none", // Fast & privacy-preserving auth without security compromise
};

const credential = await navigator.credentials.create({ publicKey: regOptions });
console.log('Credential details:', credential);
// Pass credential to server for verification: passcay.register.verify

// Authentication
const authOptions = {
  challenge: base64UrlDecode(challenge),
  rpId: 'example.com',
  userVerification: 'preferred',
};
const assertion = await navigator.credentials.get({ publicKey: authOptions });
console.log('Assertion details:', assertion);
// Retrieve public_key from assertion_id that's returned
// Pass assertion to server for verification: passcay.auth.verify
```


<details>

<summary>JavaScript utils for base64url <-> ArrayBuffer</summary>

```javascript
// Convert base64url <-> ArrayBuffer
function base64UrlToBuffer(b64url) {
  const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}
function bufferToBase64Url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

</details>

## Docs

Reference implementations for integrating Passcay into your application:

- `docs/register.md` - Registration flow with challenge generation
- `docs/login.md` - Authentication flow with verification
- `conformance/` - FIDO2 Server Conformance implementation built on Passcay (real verification; offline replay harness)

## See also

For passkey authenticator implementations and library for Zig, check out [Zig-Sec/keylib](https://github.com/Zig-Sec/keylib).


 ## Spec references

- [W3C WebAuthn](https://www.w3.org/TR/webauthn/)
- [FIDO2 Client to Authenticator Protocol (CTAP)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 [U-Zyn Chua](https://uzyn.com).
