---
name: ci-config-move-or-update
description: Workflow command scaffold for ci-config-move-or-update in env-inspector.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /ci-config-move-or-update

Use this workflow when working on **ci-config-move-or-update** in `env-inspector`.

## Goal

Moves or updates CI configuration files to correct locations or to adjust scanning/coverage behavior.

## Common Files

- `.guardrails.yml`
- `.guardrails/config.yml`
- `codecov.yml`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Move or update CI config files (e.g., .guardrails.yml to .guardrails/config.yml, update codecov.yml).
- Adjust config content to scope scanning or ignore non-source files.
- Commit with a message referencing CI, config, or ignore.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.
