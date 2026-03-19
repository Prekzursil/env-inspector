from __future__ import absolute_import, division

from pathlib import Path
from types import SimpleNamespace
import runpy
import sys
from typing import Dict

import pytest

import env_inspector
import env_inspector_core.cli as cli_module
import env_inspector_core.service as service_module
import env_inspector_core.service_listing as service_listing_module
import env_inspector_core.service_privileged as service_privileged_module
from env_inspector_core.models import EnvRecord, OperationResult
from env_inspector_core.service_ops import OperationResultInput, operation_result
from env_inspector_core.path_policy import PathPolicyError
from env_inspector_core.service import EnvInspectorService
from scripts.quality import assert_coverage_100 as coverage_mod
from scripts.quality import check_sentry_zero as sentry_mod

from tests.assertions import ensure


def _record(
    source_type: str,
    source_path: str,
    *,
    context: str = "linux",
    source_id: str = "fixture",
) -> EnvRecord:
    return EnvRecord(
        source_type=source_type,
        source_id=source_id,
        source_path=source_path,
        context=context,
        name="API_TOKEN",
        value="value",
        is_secret=False,
        is_persistent=True,
        is_mutable=True,
        precedence_rank=1,
        writable=True,
        requires_privilege=False,
    )


def _result(target: str, *, success: bool = True) -> OperationResult:
    return OperationResult(
        operation_id=f"op-{target}",
        target=target,
        action="set",
        success=success,
        backup_path=None,
        diff_preview="",
        error_message=None if success else "failed",
        value_masked=None,
    )


def _write_cobertura_xml(path: Path, filename: str, *, hits: str = "1") -> None:
    path.write_text(
        "<coverage>\n"
        '  <packages><package name="."><classes>'
        f'<class name="fixture" filename="{filename}" line-rate="1">'
        f'<lines><line number="1" hits="{hits}" /></lines>'
        "</class>"
        "</classes></package></packages>\n"
        "</coverage>\n",
        encoding="utf-8",
    )


def test_main_gui_mode_runs_app_with_resolved_root(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(env_inspector, "_parse_gui_args", lambda _argv: SimpleNamespace(root=".", print_secrets=False))
    monkeypatch.setattr(env_inspector, "resolve_scan_root", lambda _root: workspace)

    captured: Dict[str, object] = {}

    class _FakeApp:
        def __init__(self, root: Path) -> None:
            captured["root"] = root

        @staticmethod
        def run() -> None:
            captured["ran"] = True

    monkeypatch.setattr(env_inspector, "EnvInspectorApp", _FakeApp)
    monkeypatch.setattr(env_inspector.sys, "argv", ["env_inspector.py"])

    ensure(env_inspector.main() == 0)
    ensure(captured == {"root": workspace, "ran": True})


def test_main_gui_mode_rejects_invalid_root(tmp_path: Path, monkeypatch, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(env_inspector, "_parse_gui_args", lambda _argv: SimpleNamespace(root="bad", print_secrets=False))

    def _raise_invalid_root(_root: str) -> Path:
        raise PathPolicyError("bad root")

    monkeypatch.setattr(env_inspector, "resolve_scan_root", _raise_invalid_root)
    monkeypatch.setattr(env_inspector.sys, "argv", ["env_inspector.py"])

    ensure(env_inspector.main() == 2)
    ensure("Invalid --root: bad root" in capsys.readouterr().err)


def test_entrypoint_script_main_invokes_sys_exit(monkeypatch):
    monkeypatch.setattr(cli_module, "run_cli", lambda _argv: 0)
    monkeypatch.setattr(sys, "argv", ["env_inspector.py", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(Path(env_inspector.__file__)), run_name="__main__")

    ensure(exc_info.value.code == 0)


def _service_with_broken_registry(tmp_path: Path, monkeypatch) -> EnvInspectorService:
    monkeypatch.setattr(service_module, "is_windows", lambda: True)

    class _BrokenProvider:
        def __init__(self) -> None:
            raise RuntimeError("registry unavailable")

    monkeypatch.setattr(service_module, "WindowsRegistryProvider", _BrokenProvider)
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    ensure(svc.win_provider is None)
    return svc


def test_service_wrapper_owned_target_branches(tmp_path: Path, monkeypatch):
    svc = _service_with_broken_registry(tmp_path, monkeypatch)
    svc.wsl = type("NoWsl", (), {"available": lambda self: False})()  # type: ignore[assignment]
    ensure(svc._bridge_distros() == [])
    resolved = svc.resolve_effective("API_TOKEN", "linux", [_record("dotenv", ".env")])
    ensure(resolved is not None)
    ensure(resolved.name == "API_TOKEN")
    ensure(svc._powershell_target_for_path(r"C:\Program Files\PowerShell\7\profile.ps1") == "powershell:all_users")
    with pytest.raises(RuntimeError, match="Unsupported PowerShell target"):
        svc._powershell_profile_path("powershell:unsupported")

    profile = tmp_path / "profile.ps1"
    monkeypatch.setattr(EnvInspectorService, "_powershell_profile_path", lambda _self, _target: profile)
    path_out, roots, requires_privilege = svc._powershell_target_path_and_roots("powershell:current_user")
    ensure(path_out == profile.resolve(strict=False))
    ensure(roots == [Path.home().resolve(strict=False)])
    ensure(requires_privilege is False)

    monkeypatch.setattr(svc, "_registry_write", lambda *args, **kwargs: ("before", "after", "registry", False, None))
    ensure(
        svc._plan_target_operation(
            service_module.TargetOperationRequest(
                target="windows:user",
                key="API_TOKEN",
                value="1",
                action="set",
                scope_roots=[tmp_path],
            ),
            apply_changes=False,
        )[2]
        == "registry"
    )

    with pytest.raises(RuntimeError, match="Unsupported target"):
        svc._file_update(
            service_module.TargetOperationRequest(
                target="custom:target",
                key="API_TOKEN",
                value="1",
                action="set",
                scope_roots=[tmp_path],
            ),
            apply_changes=False,
        )

    ensure(
        operation_result(
            OperationResultInput(
                operation_id="op-1",
                target="linux:bashrc",
                action="set",
                success=True,
                backup_path=None,
                preview_only=False,
                diff_preview="",
                error_message=None,
                value_masked=None,
            )
        ).success
        is True
    )

    monkeypatch.setattr(svc, "_apply", lambda *args, **kwargs: [_result("linux:bashrc"), _result("linux:etc_environment", success=False)])
    preview = svc.preview_remove(key="API_TOKEN", targets=["linux:bashrc", "linux:etc_environment"])
    ensure(len(preview) == 2)
    ensure(svc.set_key(key="API_TOKEN", value="1", targets=["linux:bashrc", "linux:etc_environment"])["success"] is False)
    ensure(svc.remove_key(key="API_TOKEN", targets=["linux:bashrc", "linux:etc_environment"])["success"] is False)


def test_service_listing_filters_cover_registry_fallback(tmp_path: Path, monkeypatch):
    _service_with_broken_registry(tmp_path, monkeypatch)
    profile = tmp_path / "profile.ps1"

    def _raise_registry_runtime(_provider):
        raise RuntimeError("boom")

    host_rows = service_listing_module.collect_host_rows(
        request=service_listing_module.HostCollectionRequest(
            runtime_context="windows",
            root_path=tmp_path,
            scan_depth=2,
            win_provider=object(),
            powershell_profile_paths=[profile],
        ),
        collectors=service_listing_module.HostRowCollectors(
            collect_process_records_fn=lambda **kwargs: [_record("process", "process", context="windows")],
            collect_dotenv_records_fn=lambda *args, **kwargs: [_record("dotenv", str(tmp_path / ".env"), context="windows")],
            build_registry_records_fn=_raise_registry_runtime,
            collect_powershell_profile_records_fn=lambda _paths: [
                _record("powershell_profile", str(profile), context="windows")
            ],
            collect_linux_records_fn=lambda **kwargs: [_record("linux_bashrc", "~/.bashrc", context="linux")],
        ),
    )
    filtered_rows = service_listing_module.apply_row_filters(
        host_rows,
        source=["powershell_profile"],
        context="windows",
    )
    ensure(len(filtered_rows) == 1)
    ensure(filtered_rows[0].source_type == "powershell_profile")


def test_privileged_writer_returns_after_direct_write(tmp_path: Path):
    target = tmp_path / "environment"
    writes: Dict[str, object] = {}

    def _write_text_file(path: Path, text: str) -> None:
        writes["path"] = path
        writes["text"] = text
        path.write_text(text, encoding="utf-8")

    def _fail_which(_name: str):
        raise AssertionError("sudo should not be used")

    service_privileged_module.write_linux_etc_environment_with_privilege(
        fixed_path=str(target),
        expected_path=str(target),
        text="A=1\n",
        write_text_file=_write_text_file,
        which_fn=_fail_which,
    )

    ensure(writes == {"path": target, "text": "A=1\n"})


def test_coverage_helpers_cover_source_normalization_and_fallback_xml(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ensure(coverage_mod.CoverageStats(name="empty", path="x", covered=0, total=0).percent == pytest.approx(100.0))

    outside_file = tmp_path.parent / "outside.py"
    outside_file.write_text("print('x')\n", encoding="utf-8")
    ensure(coverage_mod._normalize_source_path(str(outside_file)).endswith("outside.py"))
    ensure(coverage_mod._normalize_source_path("./env_inspector.py") == "env_inspector.py")

    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("<coverage>", encoding="utf-8")
    ensure(coverage_mod.coverage_sources_from_xml(bad_xml) == set())

    fallback_xml = tmp_path / "fallback.xml"
    _write_cobertura_xml(fallback_xml, "env_inspector.py", hits="0")
    stats = coverage_mod.parse_coverage_xml("python", fallback_xml)
    ensure(stats.total == 1)
    ensure(stats.covered == 0)

    lcov_path = tmp_path / "coverage.lcov"
    lcov_path.write_text("SF:./scripts/quality/assert_coverage_100.py\nLF:1\nLH:1\n", encoding="utf-8")
    ensure(
        coverage_mod.coverage_sources_from_lcov(lcov_path) == {"scripts/quality/assert_coverage_100.py"}
    )


def test_coverage_evaluate_reports_missing_first_party_sources():
    ensure(
        coverage_mod.evaluate(
            [coverage_mod.CoverageStats(name="python", path="x", covered=1, total=1)],
            100.0,
            required_sources=["", "env_inspector.py"],
            reported_sources={"tests/test_quality_assert_coverage.py"},
        )[0]
        == "fail"
    )
    ensure(coverage_mod._matches_required_source("env_inspector.py", "") is False)


def test_coverage_render_lists_empty_sources_and_findings():
    rendered = coverage_mod._render_md(
        {
            "status": "pass",
            "min_percent": 100.0,
            "timestamp_utc": "now",
            "components": [],
            "covered_sources": [],
            "findings": [],
        }
    )
    ensure("## Covered sources" in rendered)
    ensure("- None" in rendered)


def test_coverage_main_rejects_workspace_escape(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    fallback_xml = tmp_path / "fallback.xml"
    _write_cobertura_xml(fallback_xml, "env_inspector.py", hits="0")
    invalid_args = SimpleNamespace(
        xml=[f"python={fallback_xml}"],
        lcov=[],
        require_source=["env_inspector.py"],
        min_percent=100.0,
        out_json=str(tmp_path.parent / "escaped.json"),
        out_md="reports/coverage.md",
    )
    monkeypatch.setattr(coverage_mod, "_parse_args", lambda: invalid_args)
    ensure(coverage_mod.main() == 1)
    ensure("escapes workspace root" in capsys.readouterr().err)


def test_coverage_main_cli_succeeds_with_valid_xml(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    good_xml = tmp_path / "good.xml"
    _write_cobertura_xml(good_xml, "env_inspector.py")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "assert_coverage_100.py",
            "--xml",
            f"python={good_xml}",
            "--require-source",
            "env_inspector.py",
            "--out-json",
            "reports/coverage.json",
            "--out-md",
            "reports/coverage.md",
        ],
    )
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(Path(coverage_mod.__file__)), run_name="__main__")
    ensure(exc_info.value.code == 0)


def test_coverage_main_requires_inputs(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        coverage_mod,
        "_parse_args",
        lambda: SimpleNamespace(
            xml=[],
            lcov=[],
            require_source=[],
            min_percent=100.0,
            out_json="reports/coverage.json",
            out_md="reports/coverage.md",
        ),
    )
    with pytest.raises(SystemExit, match="No coverage files were provided"):
        coverage_mod.main()


def test_assert_coverage_main_supports_lcov_inputs(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    lcov_path = tmp_path / "coverage.lcov"
    lcov_path.write_text("SF:./scripts/quality/assert_coverage_100.py\nLF:1\nLH:1\n", encoding="utf-8")
    args = SimpleNamespace(
        xml=[],
        lcov=[f"python={lcov_path}"],
        require_source=["scripts/quality/assert_coverage_100.py"],
        min_percent=100.0,
        out_json="reports/coverage.json",
        out_md="reports/coverage.md",
    )
    monkeypatch.setattr(coverage_mod, "_parse_args", lambda: args)

    ensure(coverage_mod.main() == 0)


def test_sentry_owned_branches_cover_headers_output_validation_and_main(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    ensure(sentry_mod._hits_from_headers({}) is None)
    ensure(sentry_mod._hits_from_headers({"x-hits": "bad"}) is None)

    monkeypatch.setattr(sentry_mod, "request_json_https", lambda **kwargs: ({}, {"x-hits": "0"}))
    with pytest.raises(RuntimeError, match="Unexpected Sentry response payload"):
        sentry_mod._request_project_issues("my-org", "proj", "token")

    invalid_args = SimpleNamespace(
        org="my-org",
        project=["proj"],
        token=f"{tmp_path.name}-token",
        out_json=str(tmp_path.parent / "escaped.json"),
        out_md="reports/sentry.md",
    )
    monkeypatch.setattr(sentry_mod, "_parse_args", lambda: invalid_args)
    monkeypatch.setattr(
        sentry_mod,
        "_scan_projects",
        lambda org, projects, token: ("strict", [{"project": "proj", "unresolved": 0}], [], []),
    )
    ensure(sentry_mod.main() == 1)
    ensure("escapes workspace root" in capsys.readouterr().err)

    helper_root = str(Path(sentry_mod.__file__).resolve().parent.parent)
    monkeypatch.setattr(sys, "path", [entry for entry in sys.path if entry != helper_root])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check_sentry_zero.py",
            "--out-json",
            "reports/sentry.json",
            "--out-md",
            "reports/sentry.md",
        ],
    )
    monkeypatch.delenv("SENTRY_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("SENTRY_ORG", raising=False)
    monkeypatch.delenv("SENTRY_PROJECT_BACKEND", raising=False)
    monkeypatch.delenv("SENTRY_PROJECT_WEB", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(Path(sentry_mod.__file__)), run_name="__main__")

    ensure(exc_info.value.code == 0)
