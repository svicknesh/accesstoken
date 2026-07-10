# Changelog
All notable changes to this project will be documented in this file.


## [Unreleased]

### Fixed
- `IsChecksumOK` no longer panics on malformed, truncated, or otherwise invalid token input; it now returns `false`.
- `Generate` now returns an error for an invalid (non-positive) random-byte length instead of panicking.
- `IsChecksumOK` now rejects non-canonical base62 token representations (e.g. truncated or extended variants that happen to decode to the same underlying bytes), accepting only the exact canonical encoding of a valid payload.

### Changed
- Documentation clarified that CRC32 checksum validation provides non-cryptographic corruption detection only, not tamper resistance or authenticity, and must not replace a database/revocation/expiry/authorization check.

### Improved
- Added table-driven unit tests and a fuzz test (`FuzzIsChecksumOK`) covering malformed, truncated, and non-canonical token input.
- Added a GitHub Actions CI workflow running formatting, `vet`, `build`, and `test` (including race detection) checks.

## [1.0.0] - 2021-12-01 Vicknesh Suppramaniam

### Added
- Initial code creation.
