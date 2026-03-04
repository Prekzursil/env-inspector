from __future__ import annotations

import pytest

from scripts.quality.snyk_policy import classify_scan, decide_policy, detect_findings, detect_quota_exhausted


def test_detect_quota_exhausted_markers():
    log = "ERROR Forbidden (SNYK-CLI-0000)\nCode test limit reached\nStatus: 403 Forbidden"
    ensure(detect_quota_exhausted(log) is True)


def test_detect_findings_markers():
    ensure(detect_findings('✗ [MEDIUM] Server-Side Request Forgery (SSRF)') is True)
    ensure(detect_findings('Open issues: 6 [ 0 HIGH  6 MEDIUM  0 LOW ]') is True)
    ensure(detect_findings('Total issues: 2') is True)
    ensure(detect_findings('Open issues: 0') is False)


def test_classify_scan_skipped_and_clean():
    ensure(classify_scan(executed=False, exit_code=None, log_text='') == 'skipped')
    ensure(classify_scan(executed=True, exit_code=0, log_text='No issues found.') == 'clean')


def test_classify_scan_vulns_and_runtime_and_quota():
    ensure(classify_scan(executed=True, exit_code=1, log_text='✗ [MEDIUM] Finding') == 'vulns_found')
    ensure(classify_scan(executed=True, exit_code=1, log_text='unexpected transport reset') == 'runtime_error')
    ensure(
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
        project_url="https://app.snyk.io/org/example/project/abc",
    )
    ensure(quota_with_findings['decision'] == 'fail')
    ensure(quota_with_findings['decision_reason'] == 'findings_detected_with_quota_exhaustion')
    ensure(quota_with_findings['manual_retest_required'] is True)
    ensure('Retest now' in quota_with_findings['manual_retest_instruction'])
    ensure(quota_with_findings['project_url'] == 'https://app.snyk.io/org/example/project/abc')

    quota_only = decide_policy(oss_outcome="quota_exhausted", code_outcome="clean")
    ensure(quota_only['decision'] == 'fail')
    ensure(quota_only['decision_reason'] == 'quota_exhausted_manual_retest_required')
    ensure(quota_only['manual_retest_required'] is True)

    vuln_fail = decide_policy(oss_outcome="vulns_found", code_outcome="clean")
    ensure(vuln_fail['decision'] == 'fail')
    ensure(vuln_fail['decision_reason'] == 'vulnerabilities_detected')
    ensure(vuln_fail['manual_retest_required'] is False)

    runtime_fail = decide_policy(oss_outcome="runtime_error", code_outcome="clean")
    ensure(runtime_fail['decision'] == 'fail')
    ensure(runtime_fail['decision_reason'] == 'inconclusive_scan_result_manual_retest_required')
    ensure(runtime_fail['manual_retest_required'] is True)

    clean_pass = decide_policy(oss_outcome="clean", code_outcome="skipped")
    ensure(clean_pass['decision'] == 'pass')
    ensure(clean_pass['decision_reason'] == 'clean_or_skipped')
    ensure(clean_pass['manual_retest_required'] is False)


def test_ensure_helper_raises():
    with pytest.raises(AssertionError, match="boom"):
        ensure(False, "boom")
