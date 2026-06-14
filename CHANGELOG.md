# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-06-03

**No more OpenSSL system library needed — Windows and macOS are now supported.**

### Removed
- OpenSSL dependency; signatures are now verified with `std.crypto` (#4, @uzyn)
  - As a result, Windows and macOS are now supported

### Changed
- Zig 0.16.0 stable support (#3, thanks @chpill)
- Zig 0.17.0-dev nightly support (`zig-0.17.0-dev.657`)
- Bump zbor to 0.21.2 for Zig 0.17-dev compatibility
- CI now also tests on macOS and Windows

### Security
- Use `io.randomSecure` for improved challenge generation (#5, @uzyn)

### Fixed
- Reject of `clientDataJSON` when it carries extra fields (#6, @uzyn)
- `parseCoseKey` crash on Zig 0.16.0

## [2.0.0] - 2025-09-06

### Changed
- Zig 0.15.1 support (#2)
- Set minimum Zig version to 0.14.0

### Added
- Documentation on the sign-count allowance feature

## [1.0.0] - 2025-05-04

Initial public release.

### Added
- WebAuthn / passkey registration and authentication verification for Zig
- ES256 and RS256 credential support
- Compatible with Zig 0.14

[Unreleased]: https://github.com/uzyn/passcay/compare/3.0.0...HEAD
[3.0.0]: https://github.com/uzyn/passcay/compare/2.0.0...3.0.0
[2.0.0]: https://github.com/uzyn/passcay/compare/1.0.0...2.0.0
[1.0.0]: https://github.com/uzyn/passcay/releases/tag/1.0.0
