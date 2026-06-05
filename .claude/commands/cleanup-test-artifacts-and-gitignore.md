---
name: cleanup-test-artifacts-and-gitignore
description: Workflow command scaffold for cleanup-test-artifacts-and-gitignore in env-inspector.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /cleanup-test-artifacts-and-gitignore

Use this workflow when working on **cleanup-test-artifacts-and-gitignore** in `env-inspector`.

## Goal

Removes accidentally committed or generated test artifacts and updates .gitignore to prevent future inclusion.

## Common Files

- `.gitignore`
- `.tmp/pytest-of-root/pytest-*/*`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Identify and remove .tmp/pytest-of-root/pytest-\* test artifact directories and files from the repository.
- Update .gitignore to include new patterns for artifacts (e.g., .venv/, coverage outputs, .tmp/).
- Commit with a message referencing cleanup or untracking artifacts.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.
