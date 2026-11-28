# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] 

## Added
- Simplify authpf activation in case of no/out-dated token but credentials exists.
So `authpf activate` logs in from the credentials file when the config file holds no token, then continues with the activation. No additional 

## Fixed
- The bearer token in `config.yaml` and `credentials.yaml` is no longer readable by group and by others. That file gets (0600) permissions now.
- Text from the authpf-api server can no longer reach the terminal as control sequences. Every character a terminal would act on instead of print is shown as `␣`, so an endpoint the user does not trust cannot change the window title, clear the screen, write the clipboard, or fabricate lines that look like this tool's own output. 
- A server-mode `user` command no longer follows a link given to `-c/--config-path`. That path is now used only when it is a regular file.
- `authpf status --all` no longer crashes when the authpf-api server reports an anchor as `null`. Such an anchor is listed without a status and is not counted as active. Without `--all` a `null` entry is skipped instead of ending the search for a live anchor
- `auth token` no longer panics on a stored token shorter than the 10 characters it shows
- A response larger than 8 MB is refused rather than buffered whole
- `auth status` no longer reports `token status: expired` when the server accepts the token but the client clock is ahead or behind
- A token that cannot be parsed locally no longer aborts `auth status` before the server was asked
- `authpf status` no longer calculates a meaningless remaining lifetime when the server sends no `server_time`
- `user create`, `user modify` and `user delete` no longer save a server configuration that the authpf-api server refuses to load. The rules the server enforces on `rbac.users` are now checked against the result of the change before anything is written.
- `--version` no longer waits up to 30 seconds for the server (1s timeout now).
- A server-mode `user` command no longer rewrites the access-control settings of accounts it was never asked about. Comments, anchors and key order are still normalised by the rewrite, as before.
- Status lines no longer lead with a symbol the terminal in front of the user may not have. The ✅, ❌ and ⚠ marks are dropped in favour of the words that already stand in those sentences when the locale names a codeset older than Unicode (`LANG=C`, `en_US.ISO-8859-1`), when a Windows console runs on a code page other than 65001, or when `AUTHPF_CLI_PLAIN` is set.

## Changed
- `auth login -p` asks for the password instead of taking it as a value. Password now reads once, with the terminal echo turned off. 
- A failing command is reported once, by the tool itself instead of twice with a usage dump.
- Token validity is decided by the server alone. Expiry in `auth login` and `auth status` is calculated on the server clock (HTTP `Date` header), anchor expiry in `authpf status` on `server_time`
- `auth login` now shows the token validity and its remaining lifetime
- A token the server rejects now reports `token rejected by server, please run auth login`
- `auth status` now exits with 1 when no token is stored. 

## [0.3.1] - 2026-03-24

### ⚠️ Breaking Changes

- API Version 1.2 (authpf-api version >= 0.3.0 supported)
  Please update authpf-api server first

### Fixed
- Git Workflow

## [0.3.0] - 2026-03-16

### ⚠️ Breaking Changes

- API Version 1.2 (authpf-api version >= 0.3.0 supported)
  Please update authpf-api server first

### Changed
- Use pkg/config from authpf-api to get in sync with server versions
- Refactorings
- Github Workflow

### Fixed
- Bugs
- Manpage

## [0.2.2] - 2026-02-06

### Changed
- Version handling. Use of `--version` will printout the CLI and Server application and API versions.

## [0.2.1] - 2026-02-04

### Added
- Manpage

### Fixed
- Bugs

## [0.2.0] - 2026-01-29

### Added
- Unittests
- API Version check

### Changed
- Password hashing
- Improved logging
- Improved parameter handling

### Fixed
- Lot of bugs

## [0.1.0] - 2025-12-01

### Added
- Initial release


[unreleased]: https://github.com/scd-systems/authpf-api-cli/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/scd-systems/authpf-api-cli/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/scd-systems/authpf-api-cli/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/scd-systems/authpf-api-cli/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/scd-systems/authpf-api-cli/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/scd-systems/authpf-api-cli/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scd-systems/authpf-api-cli/releases/tag/v0.1.0
