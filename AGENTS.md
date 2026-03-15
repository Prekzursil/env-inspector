# AGENTS.md

## Operating Model

This repository uses shared `quality-zero-platform` wrapper workflows for strict-zero quality automation.
Keep changes evidence-backed, small, and task-focused.

## Canonical Verification Command

Run this command before claiming completion:

```bash
make verify
```

## Scope Guardrails

- Keep the aggregate gate PR-focused.
- Do not commit secrets or local runtime artifacts.
- Prefer tests/docs updates together with behavior changes.
- Treat missing external statuses as policy drift before code changes.
