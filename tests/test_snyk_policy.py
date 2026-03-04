from __future__ import absolute_import

import unittest

from scripts.quality.snyk_policy import classify_scan, decide_policy, detect_findings, detect_quota_exhausted


def _case() -> unittest.TestCase:
    return unittest.TestCase()


def test_detect_quota_exhausted_markers():
    log = "ERROR Forbidden (SNYK-CLI-0000)\nCode test limit reached\nStatus: 403 Forbidden"
    _case().assertTrue(detect_quota_exhausted(log))


def test_detect_findings_markers():
    case = _case()
    case.assertTrue(detect_findings("✗ [MEDIUM] Server-Side Request Forgery (SSRF)"))
    case.assertTrue(detect_findings("Open issues: 6 [ 0 HIGH  6 MEDIUM  0 LOW ]"))
    case.assertTrue(detect_findings("Total issues: 2"))
    case.assertFalse(detect_findings("Open issues: 0"))


def test_classify_scan_skipped_and_clean():
    case = _case()
    case.assertEqual(classify_scan(executed=False, exit_code=None, log_text=""), "skipped")
    case.assertEqual(classify_scan(executed=True, exit_code=0, log_text="No issues found."), "clean")


def test_classify_scan_vulns_and_runtime_and_quota():
    case = _case()
    case.assertEqual(classify_scan(executed=True, exit_code=1, log_text="✗ [MEDIUM] Finding"), "vulns_found")
    case.assertEqual(classify_scan(executed=True, exit_code=1, log_text="unexpected transport reset"), "runtime_error")
    case.assertEqual(
        classify_scan(
            executed=True,
            exit_code=1,
            log_text="✗ [MEDIUM] Finding\nERROR Forbidden (SNYK-CLI-0000)",
        ),
        "quota_with_findings",
    )


def test_decide_policy_paths():
    case = _case()
    quota_with_findings = decide_policy(
        oss_outcome="quota_exhausted",
        code_outcome="vulns_found",
        project_url="https://app.snyk.io/org/demo/projects?search=env-inspector",
    )
    case.assertEqual(quota_with_findings["decision"], "fail")
    case.assertEqual(quota_with_findings["decision_reason"], "findings_detected_with_quota_exhaustion")
    case.assertTrue(quota_with_findings["findings_detected"])
    case.assertTrue(quota_with_findings["manual_retest_required"])

    vuln_fail = decide_policy(oss_outcome="vulns_found", code_outcome="clean")
    case.assertEqual(vuln_fail["decision"], "fail")
    case.assertEqual(vuln_fail["decision_reason"], "vulnerabilities_detected")
    case.assertFalse(vuln_fail["manual_retest_required"])

    runtime_fail = decide_policy(oss_outcome="runtime_error", code_outcome="clean")
    case.assertEqual(runtime_fail["decision"], "fail")
    case.assertEqual(runtime_fail["decision_reason"], "inconclusive_scan_result_manual_retest_required")
    case.assertTrue(runtime_fail["manual_retest_required"])

    clean_pass = decide_policy(oss_outcome="clean", code_outcome="skipped")
    case.assertEqual(clean_pass["decision"], "pass")
    case.assertEqual(clean_pass["decision_reason"], "clean_or_skipped")
    case.assertEqual(clean_pass["manual_retest_instruction"], "")
