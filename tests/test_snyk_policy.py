from __future__ import annotations

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


def test_classify_scan_vulns_runtime_and_quota_combinations():
    assert classify_scan(executed=True, exit_code=1, log_text="✗ [MEDIUM] Finding") == "vulns_found"
    assert classify_scan(executed=True, exit_code=1, log_text="unexpected transport reset") == "runtime_error"
    assert classify_scan(executed=True, exit_code=1, log_text="ERROR Forbidden (SNYK-CLI-0000)") == "quota_exhausted"
    assert (
        classify_scan(
            executed=True,
            exit_code=1,
            log_text="✗ [MEDIUM] Finding\nERROR Forbidden (SNYK-CLI-0000)",
        )
        == "quota_with_findings"
    )


def test_decide_policy_fail_closed_and_manual_retest_paths():
    project_url = "https://app.snyk.io/org/example/project/123"

    findings_and_quota = decide_policy(
        oss_outcome="quota_with_findings",
        code_outcome="clean",
        project_url=project_url,
    )
    assert findings_and_quota["decision"] == "fail"
    assert findings_and_quota["decision_reason"] == "findings_detected_with_quota_exhaustion"
    assert findings_and_quota["manual_retest_required"] is True
    assert findings_and_quota["project_url"] == project_url
    assert "Retest now" in findings_and_quota["manual_retest_instruction"]

    quota_only = decide_policy(oss_outcome="quota_exhausted", code_outcome="clean", project_url=project_url)
    assert quota_only["decision"] == "fail"
    assert quota_only["decision_reason"] == "quota_exhausted_manual_retest_required"
    assert quota_only["manual_retest_required"] is True

    runtime_only = decide_policy(oss_outcome="runtime_error", code_outcome="skipped", project_url=project_url)
    assert runtime_only["decision"] == "fail"
    assert runtime_only["decision_reason"] == "inconclusive_scan_result_manual_retest_required"
    assert runtime_only["manual_retest_required"] is True

    findings_only = decide_policy(oss_outcome="vulns_found", code_outcome="clean", project_url=project_url)
    assert findings_only["decision"] == "fail"
    assert findings_only["decision_reason"] == "vulnerabilities_detected"
    assert findings_only["manual_retest_required"] is False

    clean_pass = decide_policy(oss_outcome="clean", code_outcome="skipped", project_url=project_url)
    assert clean_pass["decision"] == "pass"
    assert clean_pass["decision_reason"] == "clean_or_skipped"
    assert clean_pass["manual_retest_required"] is False
