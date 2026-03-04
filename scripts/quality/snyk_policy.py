from __future__ import absolute_import

import re
from typing import Dict

SnykOutcome = str

_QUOTA_PATTERNS = (
    re.compile(r"code test limit reached", re.IGNORECASE),
    re.compile(r"SNYK-CLI-0000", re.IGNORECASE),
    re.compile(r"status:\s*403\s+forbidden", re.IGNORECASE),
)

_FINDING_PATTERNS = (
    re.compile(r"^\s*✗\s+\[", re.MULTILINE),
    re.compile(r"open issues:\s*(\d+)", re.IGNORECASE),
    re.compile(r"total issues:\s*(\d+)", re.IGNORECASE),
)


def detect_quota_exhausted(log_text: str) -> bool:
    text = log_text or ""
    return any(pattern.search(text) is not None for pattern in _QUOTA_PATTERNS)


def detect_findings(log_text: str) -> bool:
    text = log_text or ""
    if _FINDING_PATTERNS[0].search(text):
        return True
    for pattern in _FINDING_PATTERNS[1:]:
        match = pattern.search(text)
        if match and int(match.group(1)) > 0:
            return True
    return False


def classify_scan(*, executed: bool, exit_code: int | None, log_text: str) -> SnykOutcome:
    if not executed:
        return "skipped"

    quota = detect_quota_exhausted(log_text)
    findings = detect_findings(log_text)

    if quota and findings:
        return "quota_with_findings"
    if quota:
        return "quota_exhausted"
    if findings:
        return "vulns_found"
    if int(exit_code or 0) == 0:
        return "clean"
    return "runtime_error"


def _decision_flags(oss_outcome: SnykOutcome, code_outcome: SnykOutcome) -> tuple[bool, bool, bool]:
    outcomes = {oss_outcome, code_outcome}
    quota_detected = bool(outcomes & {"quota_exhausted", "quota_with_findings"})
    findings_detected = bool(outcomes & {"vulns_found", "quota_with_findings"})
    runtime_error_detected = "runtime_error" in outcomes
    return quota_detected, findings_detected, runtime_error_detected


def _decision_tuple(
    *,
    quota_detected: bool,
    findings_detected: bool,
    runtime_error_detected: bool,
) -> tuple[str, str, bool]:
    if findings_detected and quota_detected:
        return "fail", "findings_detected_with_quota_exhaustion", True
    if findings_detected:
        return "fail", "vulnerabilities_detected", False
    if quota_detected:
        return "fail", "quota_exhausted_manual_retest_required", True
    if runtime_error_detected:
        return "fail", "inconclusive_scan_result_manual_retest_required", True
    return "pass", "clean_or_skipped", False


def _manual_retest_instruction(*, required: bool, project_url: str) -> str:
    if not required:
        return ""
    destination = project_url or "the Snyk project page"
    return f"Open {destination}, click 'Retest now', then rerun the Snyk Zero workflow."


def decide_policy(
    *,
    oss_outcome: SnykOutcome,
    code_outcome: SnykOutcome,
    project_url: str = "",
) -> Dict[str, object]:
    quota_detected, findings_detected, runtime_error_detected = _decision_flags(oss_outcome, code_outcome)
    decision, decision_reason, manual_retest_required = _decision_tuple(
        quota_detected=quota_detected,
        findings_detected=findings_detected,
        runtime_error_detected=runtime_error_detected,
    )

    clean_project_url = (project_url or "").strip()
    manual_retest_instruction = _manual_retest_instruction(
        required=manual_retest_required,
        project_url=clean_project_url,
    )

    return {
        "quota_detected": quota_detected,
        "findings_detected": findings_detected,
        "runtime_error_detected": runtime_error_detected,
        "decision": decision,
        "decision_reason": decision_reason,
        "manual_retest_required": manual_retest_required,
        "manual_retest_instruction": manual_retest_instruction,
        "project_url": clean_project_url,
    }
