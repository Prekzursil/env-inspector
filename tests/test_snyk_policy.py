from __future__ import annotations

from scripts.quality.snyk_policy import classify_scan, decide_policy, detect_findings, detect_quota_exhausted


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _require_equal(actual, expected, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def test_require_helpers_raise_on_failures():
    try:
        _require(False, "boom")
    except AssertionError:
        pass
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("_require did not raise")

    try:
        _require_equal("a", "b", "label")
    except AssertionError:
        pass
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("_require_equal did not raise")


def test_detect_quota_exhausted_markers():
    log = "ERROR Forbidden (SNYK-CLI-0000)\nCode test limit reached\nStatus: 403 Forbidden"
    _require(detect_quota_exhausted(log) is True, "quota markers were not detected")


def test_detect_findings_markers():
    _require(detect_findings("✗ [MEDIUM] Server-Side Request Forgery (SSRF)") is True, "severity marker")
    _require(detect_findings("Open issues: 6 [ 0 HIGH  6 MEDIUM  0 LOW ]") is True, "open issues marker")
    _require(detect_findings("Total issues: 2") is True, "total issues marker")
    _require(detect_findings("Open issues: 0") is False, "clean marker")


def test_classify_scan_skipped_and_clean():
    _require_equal(classify_scan(executed=False, exit_code=None, log_text=""), "skipped", "skipped outcome")
    _require_equal(classify_scan(executed=True, exit_code=0, log_text="No issues found."), "clean", "clean outcome")


def test_classify_scan_vulns_and_runtime_and_quota():
    _require_equal(classify_scan(executed=True, exit_code=1, log_text="✗ [MEDIUM] Finding"), "vulns_found", "vuln outcome")
    _require_equal(
        classify_scan(executed=True, exit_code=1, log_text="unexpected transport reset"),
        "runtime_error",
        "runtime outcome",
    )
    _require_equal(
        classify_scan(
            executed=True,
            exit_code=1,
            log_text="✗ [MEDIUM] Finding\nERROR Forbidden (SNYK-CLI-0000)",
        ),
        "quota_with_findings",
        "quota and findings outcome",
    )


def test_decide_policy_paths():
    quota_and_findings = decide_policy(oss_outcome="quota_exhausted", code_outcome="vulns_found")
    _require_equal(quota_and_findings["decision"], "fail", "quota+findings decision")
    _require_equal(
        quota_and_findings["decision_reason"],
        "findings_detected_with_quota_exhaustion",
        "quota+findings reason",
    )
    _require(quota_and_findings["findings_detected"] is True, "findings_detected flag")
    _require(quota_and_findings["manual_retest_required"] is True, "manual_retest_required flag")

    vuln_fail = decide_policy(oss_outcome="vulns_found", code_outcome="clean")
    _require_equal(vuln_fail["decision"], "fail", "vuln decision")
    _require_equal(vuln_fail["decision_reason"], "vulnerabilities_detected", "vuln reason")

    runtime_fail = decide_policy(oss_outcome="runtime_error", code_outcome="clean")
    _require_equal(runtime_fail["decision"], "fail", "runtime decision")
    _require_equal(runtime_fail["decision_reason"], "inconclusive_scan_result_manual_retest_required", "runtime reason")

    clean_pass = decide_policy(oss_outcome="clean", code_outcome="skipped")
    _require_equal(clean_pass["decision"], "pass", "clean decision")
    _require_equal(clean_pass["decision_reason"], "clean_or_skipped", "clean reason")
