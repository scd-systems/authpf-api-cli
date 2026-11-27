# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] 

## Added
- Simplify authpf activation in case of no/out-dated token but credentials exists.
So `authpf activate` logs in from the credentials file when the config file holds no token, then continues with the activation. No additional 

## Fixed
- The bearer token in `config.yaml` and `credentials.yaml` is no longer readable by group or by others. That file gets (0600) permissions now.
- Text from the authpf-api server can no longer reach the terminal as control sequences. Every character a terminal would act on instead of print is shown as `␣`, so an endpoint the user does not trust cannot change the window title, clear the screen, write the clipboard, or fabricate lines that look like this tool's own output. Applies to anchor data, anchor names and to error messages built from a response body, whose length is now capped at 512 characters
- A server-mode `user` command no longer follows a link given to `-c/--config-path`. That path is now used only when it is a regular file, so a planted symlink can no longer make the tool read or overwrite a file the operator never named, and a fifo in that position is refused at once instead of blocking the command until some writer turns up. The config itself is still rewritten in place, so its owner, its mode and its inode are untouched
- `authpf status --all` no longer crashes when the authpf-api server reports an anchor as `null`. Such an anchor is listed without a status and is not counted as active. Without `--all` a `null` entry is skipped instead of ending the search for a live anchor
- `auth token` no longer panics on a stored token shorter than the 10 characters it shows
- A response larger than 8 MB is refused rather than buffered whole
- `auth status` no longer reports `token status: expired` when the server accepts the token but the client clock is ahead or behind
- A token that cannot be parsed locally no longer aborts `auth status` before the server was asked
- `authpf status` no longer calculates a meaningless remaining lifetime when the server sends no `server_time`
- `user create`, `user modify` and `user delete` no longer save a server configuration that the authpf-api server refuses to load. The rules the server enforces on `rbac.users` are now checked against the result of the change before anything is written: a user name outside `[a-zA-Z0-9_-]` or longer than 255 characters, a role that no role in the file defines (an empty one included), a `userId` that is negative or that a second user already uses, and the deletion of the last remaining user. Every one of those used to be saved and reported as success, after which the server would not start again and the firewall control plane stayed down. A refused change writes nothing, so the file on disk stays one the server can still read, and the error names the field in the words the server itself uses. The password field is deliberately not checked, since the tool always writes a bcrypt hash of its own
- `--version` no longer waits up to 30 seconds for the server. It waits one second and, when the server is slow or unreachable, prints the version of this tool with a `server_note` saying what happened, and still exits 0. `--version` also reads `--config` now, which it had ignored until it was answered, so it asks the server of the file the user named instead of the default one
- A server-mode `user` command no longer rewrites the access-control settings of accounts it was never asked about. `rbac` was rebuilt from the three fields this tool edits - `password`, `role`, `userId` - so every `user create`, `user modify` and `user delete` wrote `userIp`, `macros` and `pfTable` out of **every** user in the server config, dropped any key it does not model (under `rbac:` or under a role), and injected an empty `roles:` section into a file that declared none. Those three fields are firewall settings: the server builds `-D user_ip=` and the pf-table entry from `userIp`, passes `macros` as `-D` definitions for that user's rules file, and picks the pf table with `pfTable`. One documented password rotation therefore moved every other account onto the global table, unpinned its anchor and unloaded its rules with pf macro defaults - and exited 0, because the server validates the shape of a config, not what it used to hold. The section is now overlaid on the file's own parsed contents, so only the keys a command edits are written; a `userId` the command leaves unset is still removed, so an account cannot keep an id the tool decided it does not have. A config whose keys yaml reads as non-strings - a user named `1001`, or a `2024:` note under `rbac:` - is carried the same way instead of being rebuilt from scratch. Comments, anchors and key order are still normalised by the rewrite, as before

## Changed
- **Breaking:** `auth login -p` asks for the password instead of taking it as a value. A password written on the command line sits in the process argument vector, where every user logged in on that host can read it out of `/proc/<pid>/cmdline` for as long as the process runs, and the same string then stays in the shell history, in the CI job log and in anything that records `execve` arguments. `-p` now reads the password once, with the terminal echo turned off, the way the server's own password prompt does; what goes on the wire is unchanged, still the SHA-256 of what was typed. A stdin that is not a terminal - behind a pipe, in a CI job - is refused at once with a pointer to `AUTHPF_API_PASSWORD`, which stays the non-interactive path and, unlike a command line value, is readable by its owning user and root only. `auth login` now refuses a left-over argument without printing it, so an `auth login -p secret` written out of habit fails instead of answering with the secret in the error text. `user create` and `user modify` still take `-p <value>`
- A failing command is reported once, by the tool itself instead of twice with a usage dump. The `❌ Error: ` prefix and the exit codes are unchanged
- Token validity is decided by the server alone. Expiry in `auth login` and `auth status` is calculated on the server clock (HTTP `Date` header), anchor expiry in `authpf status` on `server_time`
- `auth login` now shows the token validity and its remaining lifetime
- A token the server rejects now reports `token rejected by server, please run auth login`
- `auth status` now exits with 1 when no token is stored, instead of printing `Authentication Status: ❌ Not authenticated` and exiting with 0. The message is now `not authenticated, please run auth login`, so scripts that matched the old text need adjustment


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
