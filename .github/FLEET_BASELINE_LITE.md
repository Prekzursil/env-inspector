# Fleet Baseline Lite - Reusable Bundle Export

## Overview

This checklist documents the reusable baseline components that can be exported and adapted for other repositories following the evidence-first, zero-external-API-cost workflow model.

## Core Components

### 1. Agent Operating Guide

**File:** `AGENTS.md`

- [x] Operating model (evidence-first, zero-external-API-cost)
- [x] Risk policy (risk labels, merge gates)
- [x] Canonical verification command
- [x] Scope guardrails
- [x] Agent queue contract

**Reuse Instructions:**

1. Copy `AGENTS.md` to target repository root
2. Update verification command to match target repo's build/test system
3. Adjust scope guardrails for repo-specific constraints

**Customization Points:**

- Verification command (e.g., `npm test`, `mvn verify`, `cargo test`)
- Runtime state exclusions (e.g., `.env-inspector-state/` → `.app-state/`)
- Tech stack specific guardrails

---

### 2. Agent Task Issue Template

**File:** `.github/ISSUE_TEMPLATE/agent_task.yml`

- [x] Structured task packet fields
- [x] Problem statement, current/target behavior
- [x] Non-goals section
- [x] Risk level dropdown
- [x] Primary area categorization
- [x] Acceptance criteria
- [x] Evidence command list

**Reuse Instructions:**

1. Copy to `.github/ISSUE_TEMPLATE/agent_task.yml` in target repo
2. Update `primary_area` options to match target repo domains
3. Update default evidence command value

**Customization Points:**

- Primary area options (frontend, backend, infra, etc.)
- Default evidence commands
- Additional domain-specific fields

---

### 3. PR Template

**File:** `.github/pull_request_template.md`

- [x] Summary section
- [x] Risk assessment with regression surface
- [x] Evidence checklist with verification command
- [x] Rollback steps
- [x] Scope guard checklist
- [x] Linked issues

**Reuse Instructions:**

1. Copy to `.github/pull_request_template.md` in target repo
2. Update verification command reference
3. Adjust scope guard checklist for repo specifics

**Customization Points:**

- Evidence command references
- Scope guard items (security, runtime state, secrets)
- Risk assessment prompts

---

### 4. Agent Label Sync Workflow

**File:** `.github/workflows/agent-label-sync.yml`

- [x] Agent state labels (ready, in-progress, blocked)
- [x] Risk level labels (low, medium, high)
- [x] Area labels (frontend, backend, infra, docs, security, release)
- [x] Workflow dispatch trigger

**Reuse Instructions:**

1. Copy to `.github/workflows/agent-label-sync.yml` in target repo
2. Add/remove area labels to match target repo structure
3. Run workflow to create labels: `gh workflow run agent-label-sync.yml`

**Customization Points:**

- Area labels (add domain-specific categories)
- Label colors and descriptions
- Additional workflow-specific labels

---

### 5. Agent Task Queue Workflow

**File:** `.github/workflows/agent-task-queue.yml`

- [x] Triggered by `agent:ready` label on issues
- [x] Builds task packet from issue
- [x] Notifies @copilot with execution contract
- [x] Adds `agent:in-progress` label
- [x] References verification command

**Reuse Instructions:**

1. Copy to `.github/workflows/agent-task-queue.yml` in target repo
2. Update `VERIFY_COMMAND` env var to match target repo
3. Adjust task packet template if needed

**Customization Points:**

- Verification command
- Task packet template
- Agent notification format
- Additional context from issue metadata

---

### 6. Agent Profiles

**Files:** `.github/agents/*.agent.md`

- [x] `test-specialist.agent.md` - Deterministic test focus
- [x] `docs-gardener.agent.md` - Documentation alignment
- [x] `security-sheriff.agent.md` - Security hardening
- [x] `release-assistant.agent.md` - Release preparation
- [x] `triage.agent.md` - Issue-to-implementation packets
- [x] `ui-polish.agent.md` - UX improvements

**Reuse Instructions:**

1. Copy relevant agent profiles to `.github/agents/` in target repo
2. Update verification command references
3. Adjust agent descriptions for repo context
4. Create additional domain-specific agents as needed

**Customization Points:**

- Agent-specific tools and permissions
- Verification command references
- Domain knowledge and context
- Tech stack specific instructions

---

## Supporting Workflows

### 7. KPI Weekly Digest (New in Phase 3)

**File:** `.github/workflows/kpi-weekly-digest.yml`

- [x] Lead time tracking
- [x] Cycle time tracking
- [x] Rework rate calculation
- [x] Queue failure rate monitoring
- [x] Evidence completeness tracking
- [x] Escaped regression reporting

**Reuse Instructions:**

1. Copy to `.github/workflows/kpi-weekly-digest.yml` in target repo
2. Adjust KPI thresholds if needed
3. Schedule may be customized (default: Monday 9 AM UTC)

**Customization Points:**

- KPI calculation logic (org-specific definitions)
- Reporting thresholds
- Schedule frequency
- Additional metrics

---

### 8. Branch Protection Policy (New in Phase 3)

**File:** `.github/BRANCH_PROTECTION.md`

- [x] Required review count
- [x] Required status checks
- [x] Additional protections
- [x] Risk-based gate definitions
- [x] Escaped regression tracking
- [x] Configuration commands

**Reuse Instructions:**

1. Copy to `.github/BRANCH_PROTECTION.md` in target repo
2. Update required status checks
3. Adjust review requirements if needed
4. Apply configuration via GitHub CLI or UI

**Customization Points:**

- Number of required approvals
- Required status check names
- Risk level definitions
- Escaped regression criteria

---

## Repo-Specific Overlay Exceptions

### env-inspector Specifics (NOT in baseline)

The following are specific to this repository and should NOT be exported:

- `.env-inspector-state/` exclusion (app-specific runtime state)
- Windows EXE release workflow (`env-inspector-exe-release.yml`)
- `env_inspector.py` and `env_inspector_core` module structure
- PyInstaller build configuration
- WSL environment inspection logic

### General Principles for Overlays

When adapting baseline to new repos:

1. **Preserve core workflow:** agent queue, label sync, PR template
2. **Customize verification:** Match target repo's build/test toolchain
3. **Adjust area labels:** Reflect actual codebase domains
4. **Add domain agents:** Create repo-specific agent profiles
5. **Respect tech stack:** Python → `pytest`, Node → `npm test`, etc.

---

## Export Checklist

Use this checklist when setting up a new repository with Fleet Baseline Lite:

- [ ] Copy `AGENTS.md` and update verification command
- [ ] Copy `.github/ISSUE_TEMPLATE/agent_task.yml` and customize areas
- [ ] Copy `.github/pull_request_template.md` and update references
- [ ] Copy `.github/workflows/agent-label-sync.yml` and adjust labels
- [ ] Copy `.github/workflows/agent-task-queue.yml` and set verify command
- [ ] Copy relevant agent profiles from `.github/agents/*.agent.md`
- [ ] Copy `.github/workflows/kpi-weekly-digest.yml` (optional but recommended)
- [ ] Copy `.github/BRANCH_PROTECTION.md` and configure branch rules
- [ ] Run label sync workflow: `gh workflow run agent-label-sync.yml`
- [ ] Configure branch protection via GitHub UI or CLI
- [ ] Test agent queue with a sample issue
- [ ] Document repo-specific overlays in local `BASELINE_EXCEPTIONS.md`

---

## Validation

After export and customization:

1. **Test agent queue:**
   - Create test issue with `agent:ready` label
   - Verify workflow triggers and @copilot is notified
   - Verify task packet is correctly formatted

2. **Verify labels:**
   - Run label sync workflow
   - Check all expected labels exist with correct colors

3. **Test PR flow:**
   - Open sample PR
   - Verify template renders correctly
   - Verify required checks are enforced

4. **Validate verification:**
   - Run canonical verification command
   - Verify exit code and output are sensible

---

## Maintenance

- **Review Frequency:** After each phase rollout or significant workflow change
- **Version Control:** Tag baseline exports with semantic version (e.g., `baseline-lite-v1.0`)
- **Updates:** Document changes in repository CHANGELOG.md
- **Feedback Loop:** Collect improvement suggestions from new repo implementations

---

**Last Updated:** 2026-02-18  
**Baseline Version:** 1.0 (Phase 3/4 complete)
