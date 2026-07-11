# AGENTS.md

## Project purpose

Env Inspector is a maintenance-mode Python desktop and CLI utility for inspecting and safely editing environment variables across Windows, WSL, and Linux. It reads process, registry, shell-profile, and dotenv sources, and protects writes with previews, backups, audit logs, and secret masking. The project runs directly from source and uses PyInstaller only for its portable Windows executable.

## Directory layout

- `env_inspector.py` — source entry point for the GUI and CLI.
- `env_inspector_core/` — CLI handling, models, parsing, providers, path policy, storage, rendering, and service operations.
- `env_inspector_gui/` — desktop views, dialogs, controllers, state, table, path-action, and secret-policy logic.
- `tests/` — pytest unit, integration, platform, GUI, security, and quality-tool tests.
- `scripts/` — the verification wrapper, coverage conversion, security helpers, and repository quality checks.
- `docs/` and `release-notes/` — quality documentation, planning records, baselines, and release notes.
- `.github/workflows/` — CI, quality, security, and Windows executable release automation.
- `dist/` — packaged Windows executable artifacts.

## Commands

Run commands from the repository root. Python 3.10+ is required.

### Run from source

Linux:

```bash
./start-env-inspector.sh
```

Windows:

```bat
start-env-inspector.bat
```

CLI sanity check:

```bash
python env_inspector.py list --output json --root .
```

### Build the Windows executable

There is no wheel build; the checked-in build path is the PowerShell PyInstaller script:

```powershell
.\build-windows-exe.ps1
```

It produces `dist/env-inspector.exe`. Verify the built executable with:

```powershell
.\dist\env-inspector.exe list --output json --root .
```

### Lint and type-check

The pre-commit entry point runs Ruff lint fixes, Ruff formatting, and gitleaks:

```bash
pre-commit run --all-files
```

Run the configured type checker with:

```bash
basedpyright
```

### Compile, test, and verify

```bash
make compile
make test
make verify
```

`make verify` is the canonical verification command and runs the compile check followed by pytest. The equivalent checked-in wrapper is:

```bash
bash scripts/verify
```

## Change discipline

- Keep changes small, evidence-backed, and task-focused.
- Do not commit secrets, `.env-inspector-state/`, caches, or other local runtime artifacts.
- Treat missing external quality statuses as policy drift before changing project code.
