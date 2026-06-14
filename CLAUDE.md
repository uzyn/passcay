# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Test Commands
- Build: `zig build`
- Run tests: `zig build test --summary all`
- Format code: `zig fmt src/ demo/ conformance/src/`
- Build conformance server: `cd conformance && zig build`
- Run conformance server: `cd conformance && zig build run`

## Code Style Guidelines
- **Formatting**: Follow standard Zig style. Use `zig fmt` to enforce.
- **Naming**: Use snake_case for functions, variables; CamelCase for structs/enums.
- **Memory Management**: Always use defer/errdefer for resource cleanup.
- **Error Handling**: Use proper error unions and propagate errors with `try`.
- **Types**: Prefer explicit type annotations for parameters and return values.
- **Imports**: Group standard library imports first, then local modules.
- **Security**: Always validate all WebAuthn security parameters.
- **Tests**: Write thorough tests for all public functions.
- **Documentation**: Document all public functions with //! style comments.
- Avoid excessive comments, especially when the code is self-explanatory.

## API and Documentation
- **Public API**: All public functions are exposed through `src/public.zig`. Don't expose internal implementation details.
- **README**: Ensure the README.md is up to date with build instructions and usage examples. Keep it very concise, omit unnecessary details.
- **Demo files**: The `demo/` directory contains reference implementation files, not executable demos.
- **Conformance**: The `conformance/` directory contains a FIDO2 conformance test server implementation that uses the Passcay library. It is not part of the core Passcay library.

## Finishing
- When finished, run `zig build test --summary all` to ensure all tests pass.
- Run `zig fmt .` to format the code.
- Do not git commit.

## Valid data for testing - ES256

### Register start, sent by server to client
```json
{
    "challenge": "uLjJNKj5cio95Tg1XflYB5oHBprHnGF_Aqu16zx-7iw",
    "rp": {
        "name": "Passkeys Tutorial",
        "id": "localhost"
    },
    "user": {
        "id": "9c1aea50-c813-4380-9141-9e7b8365bbe4",
        "name": "asdf3",
        "displayName": "asdf3"
    },
    "pubKeyCredParams": [
        {
            "alg": -7,
            "type": "public-key"
        },
        {
            "alg": -257,
            "type": "public-key"
        }
    ],
    "timeout": 60000,
    "attestation": "direct",
    "excludeCredentials": [],
    "authenticatorSelection": {
        "residentKey": "preferred",
        "requireResidentKey": false
    },
    "extensions": {
        "credProps": true
    }
}
```

### Register end (sent by client to server: valid):
```json
{
    "id": "y0wYdkdk9SkLcNEA-4HEsAVtIz8",
    "rawId": "y0wYdkdk9SkLcNEA-4HEsAVtIz8",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFMtMGHZHZPUpC3DRAPuBxLAFbSM_pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidUxqSk5LajVjaW85NVRnMVhmbFlCNW9IQnBySG5HRl9BcXUxNnp4LTdpdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
        "transports": ["internal","hybrid"],
        "publicKeyAlgorithm": -7,
        "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM0PGXp2OZlMSEp_DUHmOJJ1wVSxMq7I-mSz7iNOkDloXmgAS9SDCNgTqjSw_Mvobbt3vabeUzb7I8Aw5qOZigQ",
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFMtMGHZHZPUpC3DRAPuBxLAFbSM_pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks-4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2-yPAMOajmYoE"
    },
    "type": "public-key",
    "clientExtensionResults": {},
    "authenticatorAttachment": "platform"
}
```

Decoded public key of `y0wYdkdk9SkLcNEA+4HEsAVtIz8`:
`pQECAyYgASFYIDNDxl6djmZTEhKfw1B5jiSdcFUsTKuyPpks+4jTpA5aIlggF5oAEvUgwjYE6o0sPzL6G27d72m3lM2+yPAMOajmYoE=`

### Login start (sent by server to client):
```json
{
    "challenge": "lh0GW68FJem75lA5_lE6JNe8vZ687lvhZBkkcDsQPyo",
    "allowCredentials": [],
    "timeout": 60000,
    "userVerification": "required",
    "rpId": "localhost"
}
```

### Login end (sent by client to server: valid):
```json
{
    "id": "y0wYdkdk9SkLcNEA-4HEsAVtIz8",
    "rawId": "y0wYdkdk9SkLcNEA-4HEsAVtIz8",
    "response": {
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibGgwR1c2OEZKZW03NWxBNV9sRTZKTmU4dlo2ODdsdmhaQmtrY0RzUVB5byIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
        "signature": "MEYCIQDQ-pXZQT9yjPsXT_m47W-iTFAIRgBVOCBhwl6kU--0RwIhAKcJJhxipw6tsIR0ULRgvQAhTaeIXk_V29wKOqbfP1oL",
        "userHandle": "9c1aea50-c813-4380-9141-9e7b8365bbe4"
    },
    "type": "public-key",
    "clientExtensionResults": {},
    "authenticatorAttachment": "platform"
}
```

## Valid data for testing - RS256

### Register start, sent by server to client
```json
{
    "challenge": "eMus3_7g5zf7Fbus7K4RCWkt0YFQ5GgsRbSubJUR_PE",
    "rp": {
        "name": "Passkeys Tutorial",
        "id": "localhost"
    },
    "user": {
        "id": "e5b322ca-7e2d-4b6e-9804-89619a69c054",
        "name": "rs256user",
        "displayName": "rs256user"
    },
    "pubKeyCredParams": [
        {
            "alg": -257,
            "type": "public-key"
        }
    ],
    "timeout": 60000,
    "attestation": "direct",
    "excludeCredentials": [],
    "authenticatorSelection": {
        "residentKey": "preferred",
        "requireResidentKey": false
    },
    "extensions": {
        "credProps": true
    }
}
```

### Register end (sent by client to server: valid):
```json
{
    "id": "8vMZlx5qZNvXU5yVvZMO1L2a7XWtyuGIbSEuqXvHX2g",
    "rawId": "8vMZlx5qZNvXU5yVvZMO1L2a7XWtyuGIbSEuqXvHX2g",
    "response": {
        "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhANi2Rs4zP-xa0ULIjj-K5Nb5RuExpsk9MiPqlJFOkohfAiEAh8LjO3_PObScDmCqDiwn-F7X7ID9OGnxTbt1Y7fd-phjeDVjgVkB2TCCAdUwggF6oAMCAQICAQEwCgYIKoZIzj0EAwIwYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTAeFw0xNzA3MTQwMjQwMDBaFw00NTA0MTcxNDMyNTJaMGAxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhDaHJvbWl1bTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNYX5lyVCOZLzFZzrIKmeZ2jwURmgsJYxGP__fWN_S-j5sN4tT15XEpN_7QZnt14YvI6uvAgO0uJEboFaZlOEBoyUwIzAMBgNVHRMBAf8EAjAAMBMGCysGAQQBguUcAgEBBAQDAgQQMAoGCCqGSM49BAMCA0kAMEYCIQCoysbqyPSPfDIE0TqsIkmnqDqluhTv6Ry7TQJ__KhFXwIhAJX8x8JcVCPdeXnUJqeklXNsHzqRGNiUh8LWTkIwihAkaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQECAwQFBgcIAQIDBAUGBwgAIPLzGZceamTb11Oclb2TDtS9mu11rcrhiG0hLql7x19opAEDAzkBACBZAQDPaaESfnFzHsCujgVbzjpgDuvZBvuV3gIlOMrNRSmVb-zZYNFRN3Rse14jz5QpAXU4qSvkccj1q_tEzvEUCVxXcUNU55PmL3GvmjO8RO0OUM1ALpCTqFWcvR74PqXyTsUzvWMjBrSv2egr-d8PhWFX4zeQZi1B2O0jKAEGCxqIwxH7ZA3cwS4PiwXIiOVDNasGIzJA6DH6NDe45TslNSFqvoHQSUdBEe2gMXGkTeI3Vq6ttB1hrt9jeEUB-wpnz6aMd1ildOmZsZQ4UdeAeVErY2F0gH4IIv8h_ov_W9vRE7Jk5ylqvP9_U2_taVq6z2-5ofCtP3psI3N8yaEDfUL_IUMBAAE",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZU11czNfN2c1emY3RmJ1czdLNFJDV2t0MFlGUTVHZ3NSYlN1YkpVUl9QRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
        "transports": ["nfc"],
        "publicKeyAlgorithm": -257,
        "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz2mhEn5xcx7Aro4FW846YA7r2Qb7ld4CJTjKzUUplW_s2WDRUTd0bHteI8-UKQF1OKkr5HHI9av7RM7xFAlcV3FDVOeT5i9xr5ozvETtDlDNQC6Qk6hVnL0e-D6l8k7FM71jIwa0r9noK_nfD4VhV-M3kGYtQdjtIygBBgsaiMMR-2QN3MEuD4sFyIjlQzWrBiMyQOgx-jQ3uOU7JTUhar6B0ElHQRHtoDFxpE3iN1aurbQdYa7fY3hFAfsKZ8-mjHdYpXTpmbGUOFHXgHlRK2NhdIB-CCL_If6L_1vb0ROyZOcparz_f1Nv7Wlaus9vuaHwrT96bCNzfMmhA31C_wIDAQAB",
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQECAwQFBgcIAQIDBAUGBwgAIPLzGZceamTb11Oclb2TDtS9mu11rcrhiG0hLql7x19opAEDAzkBACBZAQDPaaESfnFzHsCujgVbzjpgDuvZBvuV3gIlOMrNRSmVb-zZYNFRN3Rse14jz5QpAXU4qSvkccj1q_tEzvEUCVxXcUNU55PmL3GvmjO8RO0OUM1ALpCTqFWcvR74PqXyTsUzvWMjBrSv2egr-d8PhWFX4zeQZi1B2O0jKAEGCxqIwxH7ZA3cwS4PiwXIiOVDNasGIzJA6DH6NDe45TslNSFqvoHQSUdBEe2gMXGkTeI3Vq6ttB1hrt9jeEUB-wpnz6aMd1ildOmZsZQ4UdeAeVErY2F0gH4IIv8h_ov_W9vRE7Jk5ylqvP9_U2_taVq6z2-5ofCtP3psI3N8yaEDfUL_IUMBAAE"
    },
    "type": "public-key",
    "clientExtensionResults": {
        "credProps": {
            "rk": true
        }
    },
    "authenticatorAttachment": "cross-platform"
}
```

Decoded public key of `8vMZlx5qZNvXU5yVvZMO1L2a7XWtyuGIbSEuqXvHX2g`:
`pAEDAzkBACBZAQDPaaESfnFzHsCujgVbzjpgDuvZBvuV3gIlOMrNRSmVb+zZYNFRN3Rse14jz5QpAXU4qSvkccj1q/tEzvEUCVxXcUNU55PmL3GvmjO8RO0OUM1ALpCTqFWcvR74PqXyTsUzvWMjBrSv2egr+d8PhWFX4zeQZi1B2O0jKAEGCxqIwxH7ZA3cwS4PiwXIiOVDNasGIzJA6DH6NDe45TslNSFqvoHQSUdBEe2gMXGkTeI3Vq6ttB1hrt9jeEUB+wpnz6aMd1ildOmZsZQ4UdeAeVErY2F0gH4IIv8h/ov/W9vRE7Jk5ylqvP9/U2/taVq6z2+5ofCtP3psI3N8yaEDfUL/IUMBAAE=`

### Login start (sent by server to client):
```json
{
    "challenge": "-ACFju0zGCjwFZTcGXvM375I8aRhr9GsHrxTAhUZPN4",
    "allowCredentials": [],
    "timeout": 60000,
    "userVerification": "required",
    "rpId": "localhost"
}
```

### Login end (sent by client to server: valid):
```json
{
    "id": "8vMZlx5qZNvXU5yVvZMO1L2a7XWtyuGIbSEuqXvHX2g",
    "rawId": "8vMZlx5qZNvXU5yVvZMO1L2a7XWtyuGIbSEuqXvHX2g",
    "response": {
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiLUFDRmp1MHpHQ2p3RlpUY0dYdk0zNzVJOGFSaHI5R3NIcnhUQWhVWlBONCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
        "signature": "N8btf6SFzG5EkfaZ6YxEUp0y3t1laU7rL-bNpsE-NDCXxMgunDnEinbNX87bYDmLnSDU96MWHwBcF_3fWxjNFq9HhGY0JITv2m2Lui-Izx0LOB1PXxeXNtyXdUKWUDUhiC-ldEpwSe1cgAsYPb56E0P1y4G8RPylWgUjWgfDzYbSCJy4F2F5veTnA-2zR5que3V6iPamutUuTp9qgExMjRYCoOw_q5hY0kUJ0URKpXQ2zQDT0draG7G12lHAQrgt0e_EvSfbMDF1StuZBTSr9BJ0c7FIULf6osc4TPxKrSW9atL-ZWiL9IXrgQqv4aAH_C-LxYFLRDeAeWxyU_IW_Q",
        "userHandle": "e5b322ca-7e2d-4b6e-9804-89619a69c054"
    },
    "type": "public-key",
    "clientExtensionResults": {},
    "authenticatorAttachment": "cross-platform"
}
```
