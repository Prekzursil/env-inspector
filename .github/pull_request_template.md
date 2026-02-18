## Summary

- What changed:
- Why:

## Verification

- [ ] `python3 -m py_compile env_inspector.py env_inspector_core/*.py tests/*.py`
- [ ] `pytest -q -s`
- [ ] Manual validation (if required for GUI/WSL/elevation paths)

## Scope Check

- [ ] No runtime state files committed (`.env-inspector-state/`)
- [ ] No secrets or tokens included in code/docs/logs
- [ ] Docs updated (`README.md` / `CHANGELOG.md`) when behavior changed
