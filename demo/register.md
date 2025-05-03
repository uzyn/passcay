# Passkey Registration Demo

This guide demonstrates how to:
1. Generate a registration challenge
2. Verify a registration response
3. Save the required credential data for future authentication

## What to save in your database
- **credential_id**: String identifier for the credential (base64url encoded)
- **public_key**: The credential's public key (base64url encoded)
- **sign_count**: The initial sign count (usually starts at 0)
    - Most authenticators (e.g. from Apple, Microsoft, Google) will not be incrementing this value.
    - For those that does, this can help to detect cloning of authenticators.

These values are returned in `RegVerifyResult` when verification succeeds.

## Step 1: Generate a registration challenge

**Server-side (Zig):**

Generate challenge and pass it to client-side code.

```zig
const std = @import("std");
const passcay = @import("passcay");

// Create an allocator
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
defer arena.deinit();
const allocator = arena.allocator();

// Generate a cryptographically secure random challenge for this registration attempt
// Store this challenge in your session or database temporarily to verify the response
// IMPORTANT: This challenge must be unique for each registration attempt to prevent replay attacks
const challenge = try passcay.challenge.generate(allocator);
defer allocator.free(challenge);
```

## Step 2: Configure registration options for the client

**Client-side (JavaScript):**

```javascript
// Configure registration options using the challenge from the server
const registrationOptions = {
    challenge: base64UrlDecode(challenge),
    rp: {
        name: "Your App Name",
        id: "yourdomain.com"    // Must match your domain
    },
    user: {
        id: new TextEncoder().encode(user_id_or_username),  // Convert to ArrayBuffer
        name: "username@example.com",
        displayName: "User's Display Name"
    },
    pubKeyCredParams: [
        { alg: -7, type: "public-key" },   // ES256 (most widely supported)
        { alg: -257, type: "public-key" }  // RS256
    ],
    timeout: 60000,
    attestation: "none",  // Default for privacy with no security downsides
    authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        requireResidentKey: false,
    },
};

// Trigger passkey registration
const credential = await navigator.credentials.create({ publicKey: registrationOptions });
```

Upon successful Passkey registration, the JavaScript `credential` object will contain:
* `id`: The credential ID (base64url encoded)
* `rawId`: The raw ID of the credential (base64url encoded)
* `response`: The response object containing attestation data:
    * **`response.attestationObject`: The attestation object (base64url encoded)**
    * **`response.clientDataJSON`: The client data JSON (base64url encoded)**

You'll only be needing `attestationObject` and `clientDataJSON` for the server-side verification at Step 3.


## Step 3: Verify registration response on the server

**Server-side (Zig):**

Verify the registration response with the challenge generated in Step 1.

```zig
// Input from the above JavaScript `credential`.
const reg_input = passcay.register.RegVerifyInput{
    .attestation_object = response.attestationObject,  // Base64URL encoded
    .client_data_json = response.clientDataJSON,       // Base64URL encoded
};

// Verify against these known expectations
// It is important to verify the challenge and origin to prevent replay attacks.
const reg_expectations = passcay.register.RegVerifyExpectations{
    .challenge = challenge_from_session,  // The challenge generated in Step 1
    .origin = "https://yourdomain.com",   // Origin of your web app
    .rp_id = "yourdomain.com",            // RP ID for your domain
    .require_user_verification = true,    // Whether user verification is required
};

// Perform verification. It returns error if verification fails.
const result = try passcay.register.verify(allocator, reg_input, reg_expectations);
defer result.deinit(allocator);  // Clean up resources when done
```

Upon successful verification, and thus registration, the `result` contains these fields that you should store in database for future authentication:
- `credential_id`: (base64url string)
- `public_key`: (base64url string)
- `sign_count`: (u32) usually starts at 0, _may not be incremented, safe to ignore_
- `aaguid`: (base64url string) _may not be useful, safe to ignore_ as many authenticators anonymize this

Link the above to the user in database.
