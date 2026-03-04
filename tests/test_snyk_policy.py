from __future__ import absolute_import

import unittest

from scripts.quality.snyk_policy import classify_scan, decide_policy, detect_findings, detect_quota_exhausted


class TestSnykPolicy(unittest.TestCase):
    def test_detect_quota_exhausted_markers(self) -> None:
        log = "ERROR Forbidden (SNYK-CLI-0000)\nCode test limit reached\nStatus: 403 Forbidden"
        self.assertTrue(detect_quota_exhausted(log))

    def test_detect_findings_markers(self) -> None:
        self.assertTrue(detect_findings("✗ [MEDIUM] Server-Side Request Forgery (SSRF)"))
        self.assertTrue(detect_findings("Open issues: 6 [ 0 HIGH  6 MEDIUM  0 LOW ]"))
        self.assertTrue(detect_findings("Total issues: 2"))
        self.assertFalse(detect_findings("Open issues: 0"))

    def test_classify_scan_skipped_and_clean(self) -> None:
        self.assertEqual(classify_scan(executed=False, exit_code=None, log_text=""), "skipped")
        self.assertEqual(classify_scan(executed=True, exit_code=0, log_text="No issues found."), "clean")

    def test_classify_scan_vulns_and_runtime_and_quota(self) -> None:
        self.assertEqual(classify_scan(executed=True, exit_code=1, log_text="✗ [MEDIUM] Finding"), "vulns_found")
        self.assertEqual(
            classify_scan(executed=True, exit_code=1, log_text="unexpected transport reset"),
            "runtime_error",
        )
        self.assertEqual(
            classify_scan(
                executed=True,
                exit_code=1,
                log_text="✗ [MEDIUM] Finding\nERROR Forbidden (SNYK-CLI-0000)",
            ),
            "quota_exhausted",
        )

    def test_decide_policy_paths(self) -> None:
        findings_and_quota = decide_policy(oss_outcome="quota_exhausted", code_outcome="vulns_found")
        self.assertEqual(findings_and_quota["decision"], "fail")
        self.assertEqual(findings_and_quota["decision_reason"], "vulnerabilities_detected")
        self.assertTrue(findings_and_quota["findings_detected"])
        self.assertTrue(findings_and_quota["manual_retest_required"])

        quota_fail = decide_policy(oss_outcome="quota_exhausted", code_outcome="clean")
        self.assertEqual(quota_fail["decision"], "fail")
        self.assertEqual(quota_fail["decision_reason"], "quota_or_inconclusive_requires_manual_retest")
        self.assertTrue(quota_fail["manual_retest_required"])

        runtime_fail = decide_policy(oss_outcome="runtime_error", code_outcome="clean")
        self.assertEqual(runtime_fail["decision"], "fail")
        self.assertEqual(runtime_fail["decision_reason"], "runtime_error")

        clean_pass = decide_policy(oss_outcome="clean", code_outcome="clean")
        self.assertEqual(clean_pass["decision"], "pass")
        self.assertEqual(clean_pass["decision_reason"], "clean")

        skipped_fail = decide_policy(oss_outcome="skipped", code_outcome="clean")
        self.assertEqual(skipped_fail["decision"], "fail")
        self.assertEqual(skipped_fail["decision_reason"], "inconclusive_non_clean_outcome")
        self.assertTrue(skipped_fail["manual_retest_required"])