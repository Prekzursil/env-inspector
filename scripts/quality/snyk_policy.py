from __future__ import annotations

import re

SnykOutcome = str

_QUOTA_PATTERNS = (
    re.compile(r"code test limit reached", re.IGNORECASE),
    re.compile(r"SNYK-CLI-0000", re.IGNORECASE),
    re.compile(r"status:\s*403\s+forbidden", re.IGNORECASE),
)

_FINDING_PATTERNS = (
    re.compile(r"^\s*✗\s+\[", re.MULTILINE),
    re.compile(r"open issues:\s*([0-9]+)", re.IGNORECASE),
    re.compile(r"total issues:\s*([0-9]+)", re.IGNORECASE),
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

    if quota:
        return "quota_exhausted"
    if findings:
        return "vulns_found"
    if int(exit_code or 0) == 0:
        return "clean"
    return "runtime_error"


def decide_policy(*, oss_outcome: SnykOutcome, code_outcome: SnykOutcome) -> dict[str, object]:
    outcomes = {oss_outcome, code_outcome}
    quota_detected = "quota_exhausted" in outcomes
    findings_detected = "vulns_found" in outcomes
    runtime_error_detected = "runtime_error" in outcomes

    if quota_detected:
        decision = "pass"
        decision_reason = "quota_exhausted_override"
    elif findings_detected:
        decision = "fail"
        decision_reason = "vulnerabilities_detected"
    elif runtime_error_detected:
        decision = "fail"
        decision_reason = "runtime_error_without_quota"
    else:
        decision = "pass"
        decision_reason = "clean_or_skipped"

    return {
        "quota_detected": quota_detected,
        "findings_detected": findings_detected,
        "runtime_error_detected": runtime_error_detected,
        "decision": decision,
        "decision_reason": decision_reason,
    }
