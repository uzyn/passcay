# Passkey Authentication Demo

This guide demonstrates how to:
1. Generate an authentication challenge
2. Verify an authentication response
3. Optionally update the sign count to prevent replay attacks for authenticators that support it

## Step 1: Generate an authentication challenge

**Server-side (Zig):**

Generate challenge and pass it to client-side code.

```zig
const std = @import("std");
const passcay = @import("passcay");

// Create an allocator
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
defer arena.deinit();
const allocator = arena.allocator();

// Generate a cryptographically secure random challenge
// Store this challenge in your session or database temporarily to verify the response
// IMPORTANT: This challenge must be unique for each authentication attempt to prevent replay attacks
const challenge = try passcay.challenge.generate(allocator);
defer allocator.free(challenge);
```

## Step 2: Configure authentication options for the client

**Client-side (JavaScript):**

```javascript
// Configure authentication options using the challenge from the server
const authOptions = {
    challenge: base64UrlDecode(challenge), // Convert from base64url to ArrayBuffer
    rpId: "yourdomain.com",
    timeout: 60000,
    userVerification: "preferred",
    // Optional but recommended: List of allowed credentials if you want to restrict which credentials can be used
    allowCredentials: [
        {
            id: base64UrlDecode(credential_id_from_database),
            type: "public-key"
        }
    ]
};

// Trigger passkey authentication
const assertion = await navigator.credentials.get({ publicKey: authOptions });
```

Upon successful Passkey authentication, the JavaScript `assertion` object will contain:
* `id`: The credential ID used for the authentication
* `rawId`: The raw ID of the credential (ArrayBuffer)
* `response`: The response object containing assertion data:
    * `response.authenticatorData`: The authenticator data (base64url encoded)
    * `response.clientDataJSON`: The client data JSON (base64url encoded)
    * `response.signature`: The signature (base64url encoded)

## Step 3: Verify authentication response on the server

**Server-side (Zig):**

Verify the authentication response with the challenge generated in Step 1.

```zig
// Look up the user's credentials using the credential ID from the response
// to retrieve the public and optionally the sign count
const credential_id = assertion.id;
const user_credential = findCredentialByIdInDatabase(credential_id);

// Set up the authentication input from the above JavaScript `assertion`
const auth_input = passcay.auth.AuthVerifyInput{
    .authenticator_data = assertion.response.authenticatorData,
    .client_data_json = assertion.response.clientDataJSON,
    .signature = assertion.response.signature,
};

// Set up the authentication expectations
// It is important to verify the challenge and origin to prevent replay attacks.
const auth_expectations = passcay.auth.AuthVerifyExpectations{
    .public_key = user_credential.public_key,
    .challenge = challenge_from_session,       // The challenge generated in Step 1
    .origin = "https://yourdomain.com",        // Origin of your web app, or null to skip origin check
    .rp_id = "yourdomain.com",                 // RP ID for your domain, or null to skip RP ID check
    .require_user_verification = true,         // Whether user verification is required
    .require_user_presence = true,             // Whether user presence is required
    .enable_sign_count_check = true,           // Enable sign count checking if applicable
    .known_sign_count = user_credential.sign_count,  // Current sign count from database
};

// Perform verification. It returns error if verification fails
const auth_result = try passcay.auth.verify(allocator, auth_input, auth_expectations);
defer auth_result.deinit(allocator);

// Upon successful verification, optionally, update the sign count in your database if applicable
// Note: Many authenticators do not increment sign count, this is normal
user_credential.sign_count = auth_result.recommended_sign_count;
```

Once verification succeeds, the user has been successfully authenticated with their passkey.
