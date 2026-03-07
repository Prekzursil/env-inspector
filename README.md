# Env Inspector

[![Release](https://img.shields.io/github/v/release/Prekzursil/env-inspector?display_name=tag)](https://github.com/Prekzursil/env-inspector/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/Prekzursil/env-inspector/env-inspector-exe-release.yml?label=exe-build)](https://github.com/Prekzursil/env-inspector/actions/workflows/env-inspector-exe-release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Desktop + CLI utility for inspecting and editing environment variables across Windows, WSL, and Linux contexts.

## Project status

- Maintenance mode (starting with v2.0.0): critical fixes and hotfixes only.

## Why this tool exists

Environment values often live in multiple places at once: process env, shell profiles, registry, `.env` files, and WSL distro files. Env Inspector gives one view across those sources and a safer write flow with previews, backups, and audit logging.

## Quickstart

### Run from source

Windows:

```bat
start-env-inspector.bat
```

Linux:

```bash
./start-env-inspector.sh
```

### Basic CLI sanity check

```bash
python env_inspector.py list --output json --root .
```

## Capabilities

### Read and inspect

- Unified inventory across process, Windows registry, PowerShell profile, Linux shell files, WSL shell files, and local/WSL dotenv files.
- Context switcher (`windows`, `linux`, `wsl:<distro>`) with immediate refresh.
- Effective value preview for the selected key.
- Sortable table columns with persistent sort state.
- Filter and secret-only view support.

### Edit with safety

- Set/remove operations always preview diffs before apply.
- Tabbed diff previews for multi-target edits.
- Automatic backups before writes.
- Restore flow for previous backups.
- Audit logging in `.env-inspector-state/audit.log`.

### Secret-aware UX

- Secret-like values are masked by default.
- Hidden secret copy/load actions require explicit confirmation for raw value use.
- Hidden-secret search uses masked representation instead of raw secret text.

### Operator-focused GUI quality

- Right-side details panel for selected row metadata and actions.
- Source path actions: copy path and open local file-backed sources.
- Busy indicator and status line with visible counts, context, and last refresh timestamp.
- Keyboard shortcuts:
  - `Ctrl+F` focuses filter
  - `F5` refreshes data
  - `Esc` clears filter field
  - `Ctrl+C` in table copies selected value using secret policy

## UI state and local artifacts

Env Inspector stores runtime state under `./.env-inspector-state/`:

- `config.json` for UI state (window geometry, context, filters, targets, sort, WSL scan controls)
- `backups/` for auto-generated write backups
- `audit.log` for operation history

## CLI examples

```bash
python env_inspector.py list --output json
python env_inspector.py export --output csv --root .
python env_inspector.py set --key API_TOKEN --value xyz --target dotenv:/path/to/.env
python env_inspector.py set --key API_TOKEN --value xyz --target dotenv:/path/to/.env --root /path/to
python env_inspector.py remove --key API_TOKEN --target wsl:Ubuntu:bashrc
python env_inspector.py backup
python env_inspector.py restore --backup /path/to/file.backup.json
```

Linux-target examples:

```bash
python env_inspector.py list --context linux --output table --root .
python env_inspector.py set --key MY_TEST_VAR --value hello --target linux:bashrc
python env_inspector.py remove --key MY_TEST_VAR --target linux:bashrc
python env_inspector.py set --key MY_TEST_VAR --value hello --target linux:etc_environment
python env_inspector.py remove --key MY_TEST_VAR --target linux:etc_environment
```

If `sudo -n` is unavailable, `linux:etc_environment` writes fail explicitly by design.

## Build and verify

### Build portable Windows EXE

```powershell
.\build-windows-exe.ps1
```

Expected output:

```text
dist/env-inspector.exe
```

### Verify from source

```bash
make verify
bash scripts/verify
```

### Enforce owned production coverage gate locally

```bash
python3 -m pytest -q -s \
  --cov=env_inspector \
  --cov=env_inspector_core.service \
  --cov=env_inspector_core.service_listing \
  --cov=env_inspector_core.service_ops \
  --cov=env_inspector_core.service_privileged \
  --cov=env_inspector_core.service_restore \
  --cov=env_inspector_core.service_paths \
  --cov=scripts.quality.assert_coverage_100 \
  --cov=scripts.quality.check_sentry_zero \
  --cov-report=xml:coverage/python-coverage.xml
python3 scripts/quality/assert_coverage_100.py \
  --xml "python=coverage/python-coverage.xml" \
  --require-source env_inspector.py \
  --require-source env_inspector_core/service.py \
  --require-source env_inspector_core/service_listing.py \
  --require-source env_inspector_core/service_ops.py \
  --require-source env_inspector_core/service_privileged.py \
  --require-source env_inspector_core/service_restore.py \
  --require-source env_inspector_core/service_paths.py \
  --require-source scripts/quality/assert_coverage_100.py \
  --require-source scripts/quality/check_sentry_zero.py \
  --min-percent 100
```

### Verify EXE

```powershell
.\dist\env-inspector.exe list --output json --root .
```

### Get test EXE from GitHub Actions

1. Open Actions and run `.github/workflows/env-inspector-exe-release.yml` on your branch.
2. Download the `env-inspector-exe` artifact from the run summary.
3. Push a `v*` tag when you want the workflow to publish or update the GitHub release entry.
4. Verify checksum with `env-inspector.exe.sha256` before testing.

## CI, reviews, and merges

- Pull requests are expected to pass all required repository checks before merge.
- Branch policy includes strict quality gates, including zero-open issue contexts and 100% coverage gate enforcement.
- `Semgrep Zero` is the required static security gate for repository code and workflow content.
- Semgrep artifacts are emitted under `semgrep-zero/` as JSON and SARIF for inspection.
- Keep changes scoped and include evidence from deterministic local verification commands.
- Update docs (`README.md`, `CHANGELOG.md`) when behavior changes.

## Releases and artifacts

Repository: `https://github.com/Prekzursil/env-inspector`

Release page: `https://github.com/Prekzursil/env-inspector/releases`

Release assets:

- `env-inspector.exe`
- `env-inspector.exe.sha256`

Checksum verification (PowerShell):

```powershell
Get-FileHash .\env-inspector.exe -Algorithm SHA256
```

Workflow responsible for EXE artifact/release publishing:

- `.github/workflows/env-inspector-exe-release.yml`
