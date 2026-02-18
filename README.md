# Env Inspector (Windows EXE + Source Mode)

[![Release](https://img.shields.io/github/v/release/Prekzursil/env-inspector?display_name=tag)](https://github.com/Prekzursil/env-inspector/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/Prekzursil/env-inspector/env-inspector-exe-release.yml?label=build)](https://github.com/Prekzursil/env-inspector/actions/workflows/env-inspector-exe-release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Local desktop app for inspecting and managing environment variables and token-like values across Windows and WSL.

## Releases

- Repository: `https://github.com/Prekzursil/env-inspector`
- Download page: `https://github.com/Prekzursil/env-inspector/releases`
- Release assets:
  - `env-inspector.exe`
  - `env-inspector.exe.sha256`

Checksum verification (PowerShell):

```powershell
Get-FileHash .\env-inspector.exe -Algorithm SHA256
```

## Features

- GUI + CLI entrypoint from the same script (`env_inspector.py`).
- CLI subcommands:
  - `list`
  - `set`
  - `remove`
  - `export`
  - `backup`
  - `restore`
- Source coverage:
  - Process environment
  - Windows User/Machine persistent env (registry)
  - PowerShell profile entries
  - WSL `~/.bashrc` exports
  - WSL `/etc/environment`
  - Editable `.env` / `.env.*` files on Windows paths
  - Optional WSL filesystem `.env` scan/edit per distro + path
- Secret-like values masked by default (with reveal toggle).
- Context-aware view (`windows` or `wsl:<distro>`) with effective-value preview.
- Multi-target set/remove operations with diff preview before apply.
- Automatic backups + restore and audit logging:
  - Backups: `./.env-inspector-state/backups`
  - Audit log: `./.env-inspector-state/audit.log`

## Security / behavior notes

- Secrets are masked by default in UI and exports unless explicitly revealed.
- File/target content is backed up before write operations.
- Local `dotenv:` writes are restricted to approved roots (`cwd` by default, plus explicit `--root` overrides).
- `/etc/environment` writes try root-mode first and then sudo fallback.
- Existing open shell sessions may need restart to pick up changed values.

## Repository Governance

- Default branch: `main`
- Baseline protection policy:
  - force pushes disabled
  - branch deletion disabled
  - linear history required
- Required reviews/check gates are intentionally left off for solo-maintainer velocity.

## Source setup and launch

### Prerequisites

The application requires Python 3.x (no external runtime dependencies for core functionality).

For development and verification, install pytest:

```bash
pip install pytest
```

### Launch from source

#### Windows

```bat
start-env-inspector.bat
```

#### Linux

```bash
./start-env-inspector.sh
```

### Deterministic verification

Run the canonical verification command to validate the setup:

```bash
make verify
```

This command performs:
- Python syntax compilation check for all `.py` files
- Full test suite execution via pytest

Expected baseline: 38+ passing tests. Pre-existing test failures in `test_wsl_privilege.py` are environment-specific and do not impact core functionality on non-Windows systems.

## Linux operations

List Linux-context records:

```bash
python env_inspector.py list --context linux --output table --root .
```

Set/remove in local `~/.bashrc`:

```bash
python env_inspector.py set --key MY_TEST_VAR --value hello --target linux:bashrc
python env_inspector.py remove --key MY_TEST_VAR --target linux:bashrc
```

Set/remove in local `/etc/environment` (uses direct write, then `sudo -n` fallback):

```bash
python env_inspector.py set --key MY_TEST_VAR --value hello --target linux:etc_environment
python env_inspector.py remove --key MY_TEST_VAR --target linux:etc_environment
```

If `sudo -n` is unavailable (no cached credentials/passwordless sudo), the command fails with an explicit remediation error instead of silently succeeding.

## CLI usage examples

```bash
python env_inspector.py list --output json
python env_inspector.py export --output csv --root .
python env_inspector.py set --key API_TOKEN --value xyz --target dotenv:/path/to/.env
python env_inspector.py set --key API_TOKEN --value xyz --target dotenv:/path/to/.env --root /path/to
python env_inspector.py remove --key API_TOKEN --target wsl:Ubuntu:bashrc
python env_inspector.py backup
python env_inspector.py restore --backup /path/to/file.backup.json
```

## Build portable Windows EXE locally

```powershell
.\build-windows-exe.ps1
```

Output:

```text
dist/env-inspector.exe
```

## Reliability verification checklist

### Source mode verification

```bash
python env_inspector.py list --output json --root .
python env_inspector.py export --output csv --root .
```

Manual checks:

1. Launch GUI (`start-env-inspector.bat` on Windows).
2. Confirm context dropdown includes Windows and available WSL distros.
3. Confirm rows appear from expected sources.
4. For a test key, run Set with diff preview and verify backup file is created.
5. Remove the key and verify operation log entry is appended.
6. Restore from a backup and confirm key/value returns.

### EXE verification

After build, run:

```powershell
.\dist\env-inspector.exe list --output json --root .
```

Manual checks (same as source mode):

1. GUI launches.
2. Read operations work across selected sources.
3. Set/remove with diff preview works.
4. Backup/restore flow works.
5. Export JSON/CSV works with masked secrets by default.

### Linux verification

```bash
python env_inspector.py list --context linux --output table --root .
python env_inspector.py set --key __ENV_INSPECTOR_TEST__ --value 1 --target linux:bashrc
python env_inspector.py remove --key __ENV_INSPECTOR_TEST__ --target linux:bashrc
```

Optional privilege-path check:

```bash
python env_inspector.py set --key __ENV_INSPECTOR_TEST__ --value 1 --target linux:etc_environment
python env_inspector.py remove --key __ENV_INSPECTOR_TEST__ --target linux:etc_environment
```

Known limitation: when `sudo -n` cannot authenticate non-interactively, `/etc/environment` writes fail by design with a clear error message.

## CI / release artifact

Workflow: `.github/workflows/env-inspector-exe-release.yml`

- Builds `dist/env-inspector.exe` on `windows-latest`
- Uploads workflow artifact `env-inspector-exe`
- On tag push (`v*`) or manual dispatch with `tag` input, attaches EXE to GitHub Release
