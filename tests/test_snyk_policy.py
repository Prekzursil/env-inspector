from __future__ import annotations

from scripts.quality.snyk_policy import classify_scan, decide_policy, detect_findings, detect_quota_exhausted


def _expect_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _expect_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def test_detect_quota_exhausted_markers():
    log = "ERROR Forbidden (SNYK-CLI-0000)\nCode test limit reached\nStatus: 403 Forbidden"
    _expect_true(detect_quota_exhausted(log) is True, "quota markers should be detected")


def test_detect_findings_markers():
    _expect_true(detect_findings("✗ [MEDIUM] Server-Side Request Forgery (SSRF)") is True, "finding marker not detected")
    _expect_true(detect_findings("Open issues: 6 [ 0 HIGH  6 MEDIUM  0 LOW ]") is True, "open-issues marker not detected")
    _expect_true(detect_findings("Total issues: 2") is True, "total-issues marker not detected")
    _expect_true(detect_findings("Open issues: 0") is False, "zero open issues should not be treated as findings")


def test_classify_scan_skipped_and_clean():
    _expect_equal(classify_scan(executed=False, exit_code=None, log_text=""), "skipped", "skipped classification")
    _expect_equal(classify_scan(executed=True, exit_code=0, log_text="No issues found."), "clean", "clean classification")


def test_classify_scan_vulns_and_runtime_and_quota():
    _expect_equal(
        classify_scan(executed=True, exit_code=1, log_text="✗ [MEDIUM] Finding"),
        "vulns_found",
        "vulnerability classification",
    )
    _expect_equal(
        classify_scan(executed=True, exit_code=1, log_text="unexpected transport reset"),
        "runtime_error",
        "runtime classification",
    )
    _expect_equal(
        classify_scan(
            executed=True,
            exit_code=1,
            log_text="✗ [MEDIUM] Finding\nERROR Forbidden (SNYK-CLI-0000)",
        ),
        "quota_with_findings",
        "quota+finding classification",
    )


def test_decide_policy_paths():
    quota_with_findings = decide_policy(
        oss_outcome="quota_exhausted",
        code_outcome="vulns_found",
        project_url="https://app.snyk.io/org/example/project/abc",
    )
    _expect_equal(quota_with_findings["decision"], "fail", "quota_with_findings decision")
    _expect_equal(
        quota_with_findings["decision_reason"],
        "findings_detected_with_quota_exhaustion",
        "quota_with_findings reason",
    )
    _expect_true(quota_with_findings["manual_retest_required"] is True, "quota_with_findings retest requirement")
    _expect_true(
        "Retest now" in str(quota_with_findings["manual_retest_instruction"]),
        "manual retest instruction should mention Retest now",
    )
    _expect_equal(
        quota_with_findings["project_url"],
        "https://app.snyk.io/org/example/project/abc",
        "project URL propagation",
    )

    quota_only = decide_policy(oss_outcome="quota_exhausted", code_outcome="clean")
    _expect_equal(quota_only["decision"], "fail", "quota_only decision")
    _expect_equal(
        quota_only["decision_reason"],
        "quota_exhausted_manual_retest_required",
        "quota_only reason",
    )
    _expect_true(quota_only["manual_retest_required"] is True, "quota_only retest requirement")

    vuln_fail = decide_policy(oss_outcome="vulns_found", code_outcome="clean")
    _expect_equal(vuln_fail["decision"], "fail", "vuln decision")
    _expect_equal(vuln_fail["decision_reason"], "vulnerabilities_detected", "vuln reason")
    _expect_true(vuln_fail["manual_retest_required"] is False, "vuln should not require manual retest")

    runtime_fail = decide_policy(oss_outcome="runtime_error", code_outcome="clean")
    _expect_equal(runtime_fail["decision"], "fail", "runtime decision")
    _expect_equal(
        runtime_fail["decision_reason"],
        "inconclusive_scan_result_manual_retest_required",
        "runtime reason",
    )
    _expect_true(runtime_fail["manual_retest_required"] is True, "runtime should require manual retest")

    clean_pass = decide_policy(oss_outcome="clean", code_outcome="skipped")
    _expect_equal(clean_pass["decision"], "pass", "clean decision")
    _expect_equal(clean_pass["decision_reason"], "clean_or_skipped", "clean reason")
    _expect_true(clean_pass["manual_retest_required"] is False, "clean should not require manual retest")
