# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- No changes yet.

### Changed

- No changes yet.

## [2.0.0] - 2026-03-04

### Added

- **Phase 3: KPI Instrumentation**
  - Weekly KPI digest workflow (`.github/workflows/kpi-weekly-digest.yml`) tracking lead time, cycle time, rework rate, queue failure rate, and evidence completeness.
  - Branch protection policy documentation (`.github/BRANCH_PROTECTION.md`) with human approval requirements and status checks.
  - Escaped regression tracking labels and reporting cadence.
  - New labels: `kpi-digest` and `escaped-regression` in label sync workflow.
- **Phase 4: Fleet Baseline Lite Packaging**
  - Comprehensive baseline export guide (`.github/FLEET_BASELINE_LITE.md`) documenting reusable components for multi-repo adoption.
  - Export checklist for AGENTS.md, agent_task.yml, PR template, workflows, and agent profiles.
  - Documentation of repo-specific overlay exceptions for env-inspector.
- GUI MVC package (`env_inspector_gui`) with controller/view/dialog separation and reusable UI helper modules.
- PR validation workflow (`.github/workflows/ci.yml`) running compile + pytest on Ubuntu and Windows (Python 3.12).
- Details panel actions: Copy Name, Copy Value, Copy Name=Value, Copy Source Path, Open Source.

### Changed

- Context switch now performs a full refresh with busy indicator and temporary action disable/enable cycle.
- Table columns are sortable and sort state persists across refreshes and app restarts.
- Set/Remove workflows always show a diff preview before apply; Preview buttons were removed from main mutate row.
- Diff preview dialog now uses per-target tabs, monospace text, and colored diff line tags.
- Secret handling is consistent across filter/search, copy, and load flows when secrets are hidden.
- Status bar now includes visible counts, active context, and last refresh time.
- Snyk workflow policy now classifies scan outcomes (`quota_exhausted`, `vulns_found`, `clean`, `runtime_error`) and records machine-readable decision metadata in `artifacts/snyk-oss-mode.json`.
- Snyk quota exhaustion (`Code test limit reached` / `SNYK-CLI-0000`) is treated as non-blocking by policy; non-quota vulnerability/runtime failures remain blocking.
- Quality API scripts now use fixed-host HTTPS request helpers and strict identifier validation to avoid user-influenced URL sink flows.

## [1.0.0] - 2026-02-18

### Added (1.0.0)

- Stable CLI surface for `list`, `set`, `remove`, `export`, `backup`, and `restore`.
- Cross-context record inspection across Windows, WSL, and Linux runtime modes.
- Native Linux support (`linux:bashrc`, `linux:etc_environment`) with deterministic fallback behavior.
- WSL bridge discovery fallback for Linux/WSL runtimes.
- Diff preview, automatic backups, restore support, and audit logging.
- Export flows for JSON/CSV/table with masked-by-default secret behavior.
- CI release workflow to build `env-inspector.exe` and attach checksumed release assets.

### Changed (1.0.0)

- Platform context handling now uses runtime-aware defaults instead of Windows-only assumptions.
- Effective value resolver now applies strict context isolation and Linux precedence rules.

### Security

- Secret-like values remain masked by default in UI and export surfaces.
- Audit logging redacts secret diffs for secret operations.
- Runtime state and local audit/backups are excluded from version control.
