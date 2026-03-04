from __future__ import absolute_import

from scripts.quality.snyk_policy import classify_scan, decide_policy, detect_findings, detect_quota_exhausted


def test_detect_quota_exhausted_markers():
    log = "ERROR Forbidden (SNYK-CLI-0000)\nCode test limit reached\nStatus: 403 Forbidden"
    assert detect_quota_exhausted(log) is True


def test_detect_findings_markers():
    assert detect_findings("✗ [MEDIUM] Server-Side Request Forgery (SSRF)") is True
    assert detect_findings("Open issues: 6 [ 0 HIGH  6 MEDIUM  0 LOW ]") is True
    assert detect_findings("Total issues: 2") is True
    assert detect_findings("Open issues: 0") is False


def test_classify_scan_skipped_and_clean():
    assert classify_scan(executed=False, exit_code=None, log_text="") == "skipped"
    assert classify_scan(executed=True, exit_code=0, log_text="No issues found.") == "clean"


def test_classify_scan_vulns_and_runtime_and_quota():
    assert classify_scan(executed=True, exit_code=1, log_text="✗ [MEDIUM] Finding") == "vulns_found"
    assert classify_scan(executed=True, exit_code=1, log_text="unexpected transport reset") == "runtime_error"
    assert (
        classify_scan(
            executed=True,
            exit_code=1,
            log_text="✗ [MEDIUM] Finding\nERROR Forbidden (SNYK-CLI-0000)",
        )
        == "quota_with_findings"
    )


def test_decide_policy_paths():
    quota_with_findings = decide_policy(
        oss_outcome="quota_exhausted",
        code_outcome="vulns_found",
        project_url="https://app.snyk.io/org/demo/projects?search=env-inspector",
    )
    assert quota_with_findings["decision"] == "fail"
    assert quota_with_findings["decision_reason"] == "findings_detected_with_quota_exhaustion"
    assert quota_with_findings["findings_detected"] is True
    assert quota_with_findings["manual_retest_required"] is True

    vuln_fail = decide_policy(oss_outcome="vulns_found", code_outcome="clean")
    assert vuln_fail["decision"] == "fail"
    assert vuln_fail["decision_reason"] == "vulnerabilities_detected"
    assert vuln_fail["manual_retest_required"] is False

    runtime_fail = decide_policy(oss_outcome="runtime_error", code_outcome="clean")
    assert runtime_fail["decision"] == "fail"
    assert runtime_fail["decision_reason"] == "inconclusive_scan_result_manual_retest_required"
    assert runtime_fail["manual_retest_required"] is True

    clean_pass = decide_policy(oss_outcome="clean", code_outcome="skipped")
    assert clean_pass["decision"] == "pass"
    assert clean_pass["decision_reason"] == "clean_or_skipped"
    assert clean_pass["manual_retest_instruction"] == ""
