# Contributing

Thanks for contributing to Env Inspector.

## Requirements

- Python 3.10+ (`python3` on Linux/macOS, `py -3` or `python` on Windows).
- Git.
- Optional: PyInstaller for local EXE builds (installed via `requirements-build.txt`).

## Local Development

### Run from source

Linux:

```bash
./start-env-inspector.sh
```

Windows:

```bat
start-env-inspector.bat
```

CLI example:

```bash
python env_inspector.py list --output json --root .
```

## Testing and Verification

Run the full suite before opening a PR:

```bash
python3 -m py_compile env_inspector.py env_inspector_core/*.py tests/*.py
pytest -q -s
```

On Windows, you can run equivalent commands with `py -3`.

## Build Windows EXE

```powershell
.\build-windows-exe.ps1
```

Output artifact:

```text
dist/env-inspector.exe
```

## Pull Requests

- Keep changes scoped and focused.
- Include tests for behavioral changes.
- Update docs (`README.md` and `CHANGELOG.md`) when behavior or interfaces change.
- Avoid committing runtime state (`.env-inspector-state/`) or local caches.

## Versioning and Releases

- Use semantic tags (`vX.Y.Z`).
- Tag pushes matching `v*` trigger the release workflow.
- Release assets are published automatically from CI.
