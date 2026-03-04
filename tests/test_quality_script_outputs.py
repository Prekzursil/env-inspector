from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

from scripts.quality import assert_coverage_100 as coverage_mod
from scripts.quality import check_codacy_zero as codacy_mod
from scripts.quality import check_deepscan_zero as deepscan_mod
from scripts.quality import check_sentry_zero as sentry_mod


def test_parse_coverage_xml_reads_standard_attributes(tmp_path: Path):
    xml_path = tmp_path / "coverage.xml"
    xml_path.write_text('<coverage lines-valid="2" lines-covered="1"/>\n', encoding="utf-8")

    stats = coverage_mod.parse_coverage_xml("python", xml_path)

    ensure(stats.total == 2)
    ensure(stats.covered == 1)


def test_parse_lcov_reads_totals(tmp_path: Path):
    lcov_path = tmp_path / "coverage.lcov"
    lcov_path.write_text("LF:2\nLH:1\n", encoding="utf-8")

    stats = coverage_mod.parse_lcov("python", lcov_path)

    ensure(stats.total == 2)
    ensure(stats.covered == 1)


def test_assert_coverage_main_writes_outputs(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    xml_path = tmp_path / "coverage.xml"
    xml_path.write_text('<coverage lines-valid="1" lines-covered="1"/>\n', encoding="utf-8")

    args = SimpleNamespace(
        xml=[f"python={xml_path}"],
        lcov=[],
        min_percent=100.0,
        out_json="reports/coverage.json",
        out_md="reports/coverage.md",
    )
    monkeypatch.setattr(coverage_mod, "_parse_args", lambda: args)

    rc = coverage_mod.main()

    ensure(rc == 0)
    ensure((tmp_path / 'reports' / 'coverage.json').exists())
    ensure((tmp_path / 'reports' / 'coverage.md').exists())


def test_codacy_main_writes_outputs_without_token(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CODACY_API_TOKEN", raising=False)
    args = SimpleNamespace(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="",
        out_json="reports/codacy.json",
        out_md="reports/codacy.md",
    )
    monkeypatch.setattr(codacy_mod, "_parse_args", lambda: args)

    rc = codacy_mod.main()

    ensure(rc == 1)
    ensure((tmp_path / 'reports' / 'codacy.json').exists())
    ensure((tmp_path / 'reports' / 'codacy.md').exists())


def test_deepscan_main_writes_outputs_without_inputs(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DEEPSCAN_API_TOKEN", raising=False)
    monkeypatch.delenv("DEEPSCAN_OPEN_ISSUES_URL", raising=False)
    args = SimpleNamespace(
        token="",
        out_json="reports/deepscan.json",
        out_md="reports/deepscan.md",
    )
    monkeypatch.setattr(deepscan_mod, "_parse_args", lambda: args)

    rc = deepscan_mod.main()

    ensure(rc == 1)
    ensure((tmp_path / 'reports' / 'deepscan.json').exists())
    ensure((tmp_path / 'reports' / 'deepscan.md').exists())


def test_sentry_main_writes_outputs_in_skipped_mode(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SENTRY_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("SENTRY_ORG", raising=False)
    monkeypatch.delenv("SENTRY_PROJECT_BACKEND", raising=False)
    monkeypatch.delenv("SENTRY_PROJECT_WEB", raising=False)
    args = SimpleNamespace(
        org="",
        project=[],
        token="",
        out_json="reports/sentry.json",
        out_md="reports/sentry.md",
    )
    monkeypatch.setattr(sentry_mod, "_parse_args", lambda: args)

    rc = sentry_mod.main()

    ensure(rc == 0)
    ensure((tmp_path / 'reports' / 'sentry.json').exists())
    ensure((tmp_path / 'reports' / 'sentry.md').exists())
