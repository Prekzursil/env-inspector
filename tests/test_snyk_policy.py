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


def test_classify_scan_vulns_and_runtime_and_quota():
    assert classify_scan(executed=True, exit_code=1, log_text="✗ [MEDIUM] Finding") == "vulns_found"
    assert classify_scan(executed=True, exit_code=1, log_text="unexpected transport reset") == "runtime_error"
    assert (
        classify_scan(
            executed=True,
            exit_code=1,
            log_text="✗ [MEDIUM] Finding\nERROR Forbidden (SNYK-CLI-0000)",
        )
        == "quota_exhausted"
    )


def test_decide_policy_paths():
    findings_and_quota = decide_policy(oss_outcome="quota_exhausted", code_outcome="vulns_found")
    assert findings_and_quota["decision"] == "fail"
    assert findings_and_quota["decision_reason"] == "vulnerabilities_detected"
    assert findings_and_quota["findings_detected"] is True
    assert findings_and_quota["manual_retest_required"] is True

    quota_fail = decide_policy(oss_outcome="quota_exhausted", code_outcome="clean")
    assert quota_fail["decision"] == "fail"
    assert quota_fail["decision_reason"] == "quota_or_inconclusive_requires_manual_retest"
    assert quota_fail["manual_retest_required"] is True

    runtime_fail = decide_policy(oss_outcome="runtime_error", code_outcome="clean")
    assert runtime_fail["decision"] == "fail"
    assert runtime_fail["decision_reason"] == "runtime_error"

    clean_pass = decide_policy(oss_outcome="clean", code_outcome="clean")
    assert clean_pass["decision"] == "pass"
    assert clean_pass["decision_reason"] == "clean"

    skipped_fail = decide_policy(oss_outcome="skipped", code_outcome="clean")
    assert skipped_fail["decision"] == "fail"
    assert skipped_fail["decision_reason"] == "inconclusive_non_clean_outcome"
    assert skipped_fail["manual_retest_required"] is True
