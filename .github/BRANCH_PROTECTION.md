# Branch Protection Policy

## Overview

This document defines the branch protection requirements for the `env-inspector`
repository to ensure code quality, security, and proper review processes.

## Main Branch Protection

The `main` branch MUST enforce the following protections:

### Required Reviews

- **Minimum:** At least 1 human approval required before merge
- **Dismiss stale reviews:** When new commits are pushed
- **Code owners review:** Required (see `.github/CODEOWNERS`)

### Required Status Checks

The following checks MUST pass before merge:

- `make verify` (compile + test)
- Any configured CI/CD workflows that validate:
  - Code compilation
  - Unit tests
  - Security scanning (if configured)

### Additional Protections

- **Require branches to be up to date:** Yes (ensure merge with latest main)
- **Include administrators:** Yes (protections apply to all)
- **Restrict who can push:** Only maintainers with write access
- **Allow force pushes:** No
- **Allow deletions:** No

## Development Workflow

### Pre-Merge Checklist

Before requesting merge, ensure:

1. ✅ PR description follows template (Summary, Risk, Evidence, Rollback, Scope
   Guard)
2. ✅ At least 1 human approval obtained
3. ✅ All required status checks passing
4. ✅ `make verify` executed and results documented in PR
5. ✅ Risk level labeled (`risk:low`, `risk:medium`, `risk:high`)
6. ✅ Rollback steps documented for medium/high risk changes

### Agent Tasks

For agent-driven work:

- Agent creates PR with all required sections
- Agent reports progress with commit messages
- Agent DOES NOT merge PRs
- Human maintainer performs final review and merge

## Risk-Based Gates

### Low Risk (`risk:low`)

- Standard review (1 approval)
- Required checks must pass

### Medium Risk (`risk:medium`)

- Standard review + extra scrutiny on rollback plan
- Verification evidence mandatory

### High Risk (`risk:high`)

- Multiple reviewer approval recommended (though 1 required)
- Rollback steps MUST be explicit and tested
- Consider feature flag or phased rollout

## Escaped Regression Tracking

**Definition:** A regression is "escaped" if it reaches production/main and is
discovered post-merge.

**Tracking Signal:**

- Issues labeled `bug` + `escaped-regression`
- Opened within 7 days of related PR merge

**Reporting:**

- Weekly via KPI digest
- Immediate notification for critical regressions

**Root Cause Analysis:** When escaped regressions occur:

1. Label the issue `bug` + `escaped-regression`
2. Link to the causative PR
3. Document why existing checks didn't catch it
4. Update test coverage or verification steps
5. Review and strengthen branch protection if needed

## Configuration Commands

### Via GitHub CLI

```bash
# Enable branch protection with required reviews
gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --field required_status_checks[strict]=true \
  --field required_status_checks[contexts][]=verify \
  --field required_pull_request_reviews[required_approving_review_count]=1 \
  --field required_pull_request_reviews[dismiss_stale_reviews]=true \
  --field enforce_admins=true \
  --field restrictions=null
```

### Via GitHub Web UI

1. Go to **Settings** > **Branches**
2. Add rule for `main` branch
3. Enable:
   - Require a pull request before merging
   - Require approvals: 1
   - Dismiss stale pull request approvals when new commits are pushed
   - Require status checks to pass before merging
   - Require branches to be up to date before merging
   - Do not allow bypassing the above settings

## Validation

To verify branch protection is correctly configured:

```bash
# Check current protection status
gh api repos/:owner/:repo/branches/main/protection \
  | jq '.required_pull_request_reviews, .required_status_checks'
```

Expected output should show:

- `required_approving_review_count: 1`
- `dismiss_stale_reviews: true`
- Required status checks configured

## Maintenance

- **Review Frequency:** Quarterly or after major workflow changes
- **Owner:** Repository maintainers
- **Updates:** Document in CHANGELOG.md when policy changes
