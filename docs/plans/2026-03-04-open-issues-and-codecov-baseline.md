# Open Issues and Codecov Baseline (2026-03-04)

## Scope

- Branch for remediation: `fix/open-issues-and-codecov-100`.
- Baseline branch tip on `main`: `82e458440dc4e76a0dfdff40d6ee49fff94d156f`.

## Open GitHub Issues Snapshot

- `#16` Dependency/Release stewardship digest - 2026-03-02
- `#15` Branch protection audit findings - 2026-03-02
- `#14` Weekly release stewardship checklist (2026-03-02)
- `#13` Weekly KPI Digest - 2026-03-02
- `#12` Dependency/Release stewardship digest - 2026-02-23
- `#11` Branch protection audit findings - 2026-02-23
- `#10` Weekly release stewardship checklist (2026-02-23)
- `#9` Weekly KPI Digest - 2026-02-23

## Codecov Patch Failure Snapshot

- Commit: `82e458440dc4e76a0dfdff40d6ee49fff94d156f`
- Context: `codecov/patch`
- State: `failure`
- Description: `94.59% of diff hit (target 100.00%)`
- Target URL: `https://app.codecov.io/gh/Prekzursil/env-inspector/commit/82e458440dc4e76a0dfdff40d6ee49fff94d156f`

## Local Baseline Diff-Cover Evidence (Pre-fix)

```text
Diff Coverage
Diff: 890449c...HEAD, staged and unstaged changes
env_inspector_core/service.py (94.6%): Missing lines 278,280
Total:   37 lines
Missing: 2 lines
Coverage: 94%
```

## Notes

- Open code-scanning alerts on `refs/heads/main` were already `0` at baseline capture.
- Required branch-protection checks on `main` were green at baseline capture.
