# passcay

[![Tests](https://github.com/uzyn/passcay/actions/workflows/test.yml/badge.svg)](https://github.com/uzyn/passcay/actions/workflows/test.yml)


**Minimal**, **fast** and **secure** Passkey (WebAuthn) relying party (RP) library for Zig.

## Features

- Passkey WebAuthn registration
- Passkey WebAuthn authentication/verification (login)
- Attestation-less passkey usage (privacy-preserving, does not affect security)
- Cryptographic signature verification. Supports both ES256 & RS256, covering 100% of all Passkey authenticators today.
- Secure challenge generation

## Dependencies

Compiles and tested on both Zig stable 0.14+ and nightly (0.15+).

Dynamically linked to system's OpenSSL for crypto verification.

Works on Linux and macOS. Not yet on Windows.

### Installation

Add `passcay` to your `build.zig.zon` dependencies:

```zig
.dependencies = .{
    .passcay = .{
        .url = "https://github.com/uzyn/passcay/archive/main.tar.gz",
        // Optionally pin to a specific commit hash
    },
},
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
     .client_data_json   = client_data_json,
};

const expectations = passcay.register.RegVerifyExpectations{
     .challenge               = challenge,
     .origin                  = "https://example.com",
     .rp_id                   = "example.com",
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

### Authentication

```zig
const challenge = try passcay.challenge.generate(allocator);
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

## Demo

Reference implementations for integrating passcay into your application:

- `demo/register.md` - Registration flow with challenge generation
- `demo/login.md` - Authentication flow with verification

## See also

For passkey authenticator implementations and library for Zig, check out [Zig-Sec/keylib](https://github.com/Zig-Sec/keylib).


 ## Spec references

- [W3C WebAuthn](https://www.w3.org/TR/webauthn/)
- [FIDO2 Client to Authenticator Protocol (CTAP)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 [U-Zyn Chua](https://uzyn.com).
