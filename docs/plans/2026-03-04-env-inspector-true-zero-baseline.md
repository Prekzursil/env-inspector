# Env Inspector True-Zero Baseline (2026-03-04)

Timestamp (UTC): 2026-03-04T11:20:00Z Branch: `fix/true-zero-provider-parity-v2`
(from `origin/main`)

## Required branch-protection contexts (`main`)

Source:
`gh api repos/Prekzursil/env-inspector/branches/main/protection/required_status_checks`

- Coverage 100 Gate
- Codecov Analytics
- Quality Zero Gate
- SonarCloud Code Analysis
- Codacy Static Code Analysis
- DeepScan
- Snyk Zero
- Sentry Zero
- Sonar Zero
- Codacy Zero
- DeepScan Zero

## GitHub code-scanning (`main`)

Source:

```bash
gh api "repos/Prekzursil/env-inspector/code-scanning/alerts?
state=open&ref=refs/heads/main&per_page=100" --jq 'length'
```

- Open alerts: `0`

## Current mismatch evidence (checks vs provider truth)

### Codacy Zero workflow history

Source:

```bash
gh run list --repo Prekzursil/env-inspector \
  --workflow codacy-zero.yml --limit 5
```

Recent runs are failing (example run `22666345031`) and report provider issue
totals in artifacts/logs.

### Sonar Zero workflow history

Source:

```bash
gh run list --repo Prekzursil/env-inspector \
  --workflow sonar-zero.yml --limit 5
```

Recent runs alternate pass/fail as branch-level findings change (example latest
success `22666345050`).

### Snyk Zero workflow history

Source:
`gh run list --repo Prekzursil/env-inspector --workflow snyk-zero.yml --limit 5`
`gh run view --repo Prekzursil/env-inspector 22666345049 --log`

Observed policy behavior in logs/artifact:

- `oss_outcome`: `quota_exhausted`
- `code_outcome`: `clean`
- `decision`: `fail`
- `decision_reason`: `quota_exhausted_manual_retest_required`

Operator action currently required when quota is hit:

- Open the project in Snyk
- Click **Retest now**
- Re-run `Snyk Zero`

## Notes

- Local machine currently has no provider API tokens set (`SONAR_TOKEN`,
  `CODACY_API_TOKEN`, `SNYK_TOKEN`, `DEEPSCAN_API_TOKEN` all missing), so
  provider-truth validation is confirmed through CI runs and artifacts.
- Unrelated local dirt in parent workspace exists and is intentionally
  untouched.
