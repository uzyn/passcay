# Passcay FIDO2 Conformance Server

A FIDO2 Server Conformance implementation built on the [Passcay](..) library. It
performs **real** attestation and assertion verification — there are no
test-pattern bypasses. The verification logic lives in the library; this project
is the HTTP shell plus an offline replay harness.

## Layout

- `src/server.zig` — the four conformance endpoints as transport-agnostic
  functions over Passcay. Maps library outcomes to the `{status, errorMessage}`
  envelope. In-memory challenge + credential store with anti-replay.
- `src/main.zig` — thin httpz HTTP shell wiring the endpoints to routes.
- `test/replay.zig` — **autonomous** Layer-B harness: recorded
  options→result transcripts (real WebAuthn vectors) driven straight through the
  handlers, asserting the response envelope. No sockets, no FIDO tool.

## Endpoints (FIDO2 Server Conformance Test API)

- `POST /attestation/options` · `POST /attestation/result`
- `POST /assertion/options` · `POST /assertion/result`

## Build & test (offline, no FIDO tool)

```sh
zig build test     # run the replay harness (real register→assert round-trips)
zig build          # build the HTTP server (conformance-server)
zig build run      # start the server on http://localhost:8080
```

### Server flags

```
--metadata <dir>   load MDS3 metadata statements (*.json) as attestation trust anchors
--mds-root <cert>  trust anchor (PEM/DER) for verifying live MDS3 blob signatures
--mds-endpoint <url>  fetch + verify a signed MDS3 blob at startup (repeatable;
                      requires --mds-root). Bad-signature/cert blobs are rejected.
--origin <url>     expected origin (default http://localhost:8080)
--rp-id <id>       expected RP ID (default localhost)
--port <n>         listen port (default 8080)
--now <unix_secs>  pin certificate time validity; pass `--now $(date +%s)` so
                   expired-certificate negative tests are rejected
--verbose          log every request body + response (for debugging tool runs)
```

The replay harness exercises ES256 (none) registration + assertion, fido-u2f
full attestation, and negative cases (unknown challenge, wrong origin, tampered
signature) — all via `zig build test`, no human involvement.

## Running the official FIDO Conformance Tool (the one human-gated step)

Full certification requires the FIDO Alliance desktop tool, which is gated:

1. Request access via the FIDO Alliance Test Tool Access Request form and install
   the desktop application.
2. In the tool, **Download Server Metadata**, unzip the statements to a folder
   (e.g. `./mds`), and start the server with it loaded:
   ```sh
   zig build run -- --metadata ./mds --now $(date +%s)
   ```
3. Point the tool at `http://localhost:8080`, select Server Tests, and run.

Everything up to step 3 is verifiable offline; step 3 needs the gated tool.

## Status

Implemented & verified: `none`, `packed` (full + self), `fido-u2f`; algorithms
ES256/384, secp256k1, Ed25519, RS256/384/512, RS1, PS256; X.509 chain
validation; MDS3 metadata (AAGUID trust anchors + status gating).

Deferred (follow-on): `tpm`, `android-key`, `android-safetynet`, `apple`, and
ES512/P-521 (absent from Zig std).
