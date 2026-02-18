# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-18

### Added
- Stable CLI surface for `list`, `set`, `remove`, `export`, `backup`, and `restore`.
- Cross-context record inspection across Windows, WSL, and Linux runtime modes.
- Native Linux support (`linux:bashrc`, `linux:etc_environment`) with deterministic fallback behavior.
- WSL bridge discovery fallback for Linux/WSL runtimes.
- Diff preview, automatic backups, restore support, and audit logging.
- Export flows for JSON/CSV/table with masked-by-default secret behavior.
- CI release workflow to build `env-inspector.exe` and attach checksumed release assets.

### Changed
- Platform context handling now uses runtime-aware defaults instead of Windows-only assumptions.
- Effective value resolver now applies strict context isolation and Linux precedence rules.

### Security
- Secret-like values remain masked by default in UI and export surfaces.
- Audit logging redacts secret diffs for secret operations.
- Runtime state and local audit/backups are excluded from version control.
