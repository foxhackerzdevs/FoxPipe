# Changelog

All notable changes to FoxPipe are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [2.1.0]

### Added
- `--password-file <path>` — reads the password from a file instead of argv. Recommended for scripts, cron jobs, and CI, where an interactive prompt isn't usable and `-p` would otherwise leak the password into shell history and `ps`.

### Changed
- `-p`/`--password` now prints a warning to stderr. Still supported for quick manual use; `--password-file` or the interactive prompt (the default when neither flag is given) are recommended instead.
- Per-chunk AES-GCM nonces are now a deterministic per-session counter (0, 1, 2, ...) instead of random. Not a fix for a live vulnerability — with a fresh session key per connection, random 96-bit nonces were already far below the collision-risk threshold at any realistic transfer size (NIST SP 800-38D). The change removes the need to reason about that bound at all: uniqueness is now guaranteed, not probabilistic. **No wire format change** — the nonce is still sent per chunk, so this only affects how the sender generates it.

### Fixed
- `TOOL_VERSION` and the module docstring header now match the package version exactly (previously `"2.0"` while the package was `2.0.x`).

### Docs
- Usage examples now lead with the interactive password prompt / `--password-file`, with a new "Scripted / Non-Interactive Use" section.
- Security Model and Design Notes updated to describe the counter-based nonce and the rationale for the change.

---

## [2.0.1]

Packaging and documentation only. No protocol or functional changes; wire-compatible with 2.0.0.

### Fixed
- Removed a stray leftover comment in `pyproject.toml`.

### Docs
- Added a portfolio link.
- Added a Mermaid sequence diagram of the v2 handshake (SPAKE2 → X25519 → HKDF → HMAC confirmation → AES-GCM stream), visualizing what the Security Model section already specified.

---

## [2.0.0]

Major release: replaces the v1 handshake entirely. **Not wire-compatible with v1** — both sides must be on v2. A version mismatch fails cleanly with an explicit error rather than silently downgrading.

### Changed
- Handshake is now a **SPAKE2 password-authenticated key exchange** combined with an **ephemeral X25519 key exchange**, deriving the session key via HKDF-SHA256. This provides forward secrecy: a future password leak cannot decrypt previously captured sessions.
- Added explicit **key confirmation** (HMAC-SHA256 tag exchange) before any data streams — a wrong password is now caught at the handshake, with zero bytes streamed, instead of surfacing later as a failed AES-GCM decrypt.

### Removed
- The v1 Scrypt-derived-key handshake, which sent its salt in cleartext and used the same static password-derived key to both authenticate and encrypt every session (no forward secrecy, vulnerable to offline dictionary attacks).

### Notes
- The random `session_id` sent on the wire is retained but is no longer cryptographically load-bearing — every connection already gets a fresh, unique session key from the PAKE + X25519 exchange. Kept as informational metadata only.

[2.1.0]: https://github.com/foxhackerzdevs/FoxPipe/releases/tag/v2.1.0
[2.0.1]: https://github.com/foxhackerzdevs/FoxPipe/releases/tag/v2.0.1
[2.0.0]: https://github.com/foxhackerzdevs/FoxPipe/releases/tag/v2.0.0
