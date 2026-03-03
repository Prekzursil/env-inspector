# Snyk Delta Report (PR #20)

## Scope

Compare Snyk findings shown in the screenshot against current `release/squash-post-v1.0.0` remediation changes and required-check policy.

Evidence sources:

- Snyk Zero run logs: `gh run view 22621939381 --log`
- PR checks: `gh pr checks 20`, `gh pr checks 20 --required`
- Branch protection contexts: `gh api repos/Prekzursil/env-inspector/branches/main/protection/required_status_checks`

## Finding Delta

| Screenshot Finding | Current Location | Status | Evidence |
| --- | --- | --- | --- |
| Path Traversal (`Finding ID: 2c12b409-ffa6-4bb1-942c-ce96773e2cec`) | `env_inspector.py` (`--print-secrets` path flow) | Replaced by equivalent flow | `_legacy_print_secrets` now revalidates root with `resolve_scan_root` before read path usage. |
| SSRF (`Finding ID: 5217f1e2-ccb4-481a-99e1-ca5e5773dd9e`) | `scripts/quality/check_codacy_zero.py` | Replaced by equivalent flow | Request path now built from validated identifiers + fixed host (`api.codacy.com`) via `request_json_https`. |
| SSRF (`Finding ID: 183bb1b3-334f-469b-a058-9f9f1ccabd02`) | `scripts/quality/check_codacy_zero.py` | Replaced by equivalent flow | Provider/owner/repo path segments use strict identifier validation and fixed-host request helper. |
| SSRF (`Finding ID: 833a3a90-ad42-4e64-92ab-d17506f6081e`) | `scripts/quality/check_deepscan_zero.py` | Replaced by equivalent flow | Open-issues URL is split/validated once, then requested through fixed-host helper; no raw URL sink call. |
| SSRF (`Finding ID: 208152f2-8c29-403c-a73d-6769125a1c85`) | `scripts/quality/check_sentry_zero.py` | Replaced by equivalent flow | Sentry requests now use fixed host (`sentry.io`) and validated org/project identifiers. |
| SSRF (`Finding ID: 12b4ef45-d8ca-4e4e-b2ad-147071289681`) | `scripts/quality/check_sentry_zero.py` | Replaced by equivalent flow | Project issue request URL now assembled from validated slugs only. |
| Use of SHA1 (`CWE-916`) from screenshot | `env_inspector_core/storage.py` | Patched | SHA1-based target slug path generation was removed; backups now use timestamp+sequence with root-bound normalization. |

## Quota and Gating Policy Delta

### Previous behavior

- `Snyk Zero` tolerated failures in non-strict mode without explicit classification output.
- External Snyk app status (`code/snyk (prekzursil1993)`) could remain red with `Code test limit reached`.

### Current behavior (implemented)

- `Snyk Zero` now classifies scan outcomes:
  - `quota_exhausted`
  - `vulns_found`
  - `clean`
  - `runtime_error`
  - `skipped`
- New machine-readable artifact: `artifacts/snyk-oss-mode.json` with:
  - `quota_detected`
  - `findings_detected`
  - `oss_outcome`
  - `code_outcome`
  - `decision`
  - `decision_reason`
- Policy decision implemented:
  - If quota exhaustion is detected (`Code test limit reached` / `SNYK-CLI-0000` / `403 Forbidden`) => **pass**.
  - Otherwise findings/runtime errors determine pass/fail.

## Required Check Safeguard Evidence

`main` required contexts currently include `Snyk Zero` but do **not** include external `code/snyk (...)`:

- `Coverage 100 Gate`
- `Codecov Analytics`
- `Quality Zero Gate`
- `SonarCloud Code Analysis`
- `Codacy Static Code Analysis`
- `DeepScan`
- `Snyk Zero`
- `Sentry Zero`
- `Sonar Zero`
- `Codacy Zero`
- `DeepScan Zero`

Implication: `code/snyk (prekzursil1993)` is external informational status unless branch policy is changed.

## Snyk-side Integration Control

Requested control path: disable Snyk app PR status publishing (`code/snyk (...)`) for this repository while keeping workflow-based `Snyk Zero` as required.

Repository code/workflow changes are complete in this PR. Snyk UI integration toggle is a provider-side setting and must be applied in Snyk project integration settings.
