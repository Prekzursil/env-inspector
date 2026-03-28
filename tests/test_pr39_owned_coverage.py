"""Owned coverage tests for PR 39 regression branches and wrappers."""

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

from tests.assertions import ensure


def _record(
    source_type: str,
    source_path: str,
    *,
    context: str = "linux",
    source_id: str = "fixture",
) -> EnvRecord:
    """Build a minimal environment record for wrapper-focused tests."""
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
    """Build an operation result with stable defaults for service tests."""
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
    """Write a tiny Cobertura fixture for coverage-script tests."""
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


def test_main_gui_mode_runs_app_with_resolved_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GUI mode should launch the app with the resolved workspace root."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(
        env_inspector,
        "_parse_gui_args",
        lambda _argv: SimpleNamespace(root=".", print_secrets=False),
    )
    monkeypatch.setattr(env_inspector, "resolve_scan_root", lambda _root: workspace)

    captured: Dict[str, object] = {}

    class _FakeApp:
        """Capture GUI application construction and execution."""

        def __init__(self, root: Path) -> None:
            """Store the resolved root used to instantiate the app."""
            captured["root"] = root

        @staticmethod
        def run() -> None:
            """Record that the fake application was executed."""
            captured["ran"] = True

    monkeypatch.setattr(env_inspector, "EnvInspectorApp", _FakeApp)
    monkeypatch.setattr(env_inspector.sys, "argv", ["env_inspector.py"])

    ensure(env_inspector.main() == 0)
    ensure(captured == {"root": workspace, "ran": True})


def test_main_gui_mode_rejects_invalid_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """GUI mode should reject invalid roots with a user-facing error."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(
        env_inspector,
        "_parse_gui_args",
        lambda _argv: SimpleNamespace(root="bad", print_secrets=False),
    )

    def _raise_invalid_root(_root: str) -> Path:
        """Raise the path-policy error surfaced by the CLI wrapper."""
        raise PathPolicyError("bad root")

    monkeypatch.setattr(env_inspector, "resolve_scan_root", _raise_invalid_root)
    monkeypatch.setattr(env_inspector.sys, "argv", ["env_inspector.py"])

    ensure(env_inspector.main() == 2)
    ensure("Invalid --root: bad root" in capsys.readouterr().err)


def test_entrypoint_script_main_invokes_sys_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The entrypoint script should forward the CLI exit status via `sys.exit`."""
    monkeypatch.setattr(cli_module, "run_cli", lambda _argv: 0)
    monkeypatch.setattr(sys, "argv", ["env_inspector.py", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(Path(env_inspector.__file__)), run_name="__main__")

    ensure(exc_info.value.code == 0)


def _service_with_broken_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> EnvInspectorService:
    """Build a service instance whose Windows registry provider fails to load."""
    monkeypatch.setattr(service_module, "is_windows", lambda: True)

    class _BrokenProvider:
        """Registry provider stub that fails during construction."""

        def __init__(self) -> None:
            """Raise to simulate a registry bootstrap failure."""
            raise RuntimeError("registry unavailable")

    monkeypatch.setattr(service_module, "WindowsRegistryProvider", _BrokenProvider)
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    ensure(svc.win_provider is None)
    return svc


def _target_request(
    tmp_path: Path, *, target: str
) -> service_module.TargetOperationRequest:
    """Build a target-operation request for wrapper tests."""
    return service_module.TargetOperationRequest(
        target=target,
        key="API_TOKEN",
        value="1",
        action="set",
        scope_roots=[tmp_path],
    )


def _assert_service_target_helpers(
    svc: EnvInspectorService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the service helper wrappers that resolve targets and records."""

    class _NoWsl:
        """Bridge stub that reports WSL as unavailable."""

        @staticmethod
        def available() -> bool:
            """Report that no WSL bridge exists."""
            return False

    svc.wsl = _NoWsl()  # type: ignore[assignment]
    ensure(svc._bridge_distros() == [])
    resolved = svc.resolve_effective("API_TOKEN", "linux", [_record("dotenv", ".env")])
    ensure(resolved is not None)
    ensure(resolved.name == "API_TOKEN")
    ensure(
        svc._powershell_target_for_path(
            r"C:\Program Files\PowerShell\7\profile.ps1"
        )
        == "powershell:all_users"
    )
    with pytest.raises(RuntimeError, match="Unsupported PowerShell target"):
        svc._powershell_profile_path("powershell:unsupported")

    profile = tmp_path / "profile.ps1"
    monkeypatch.setattr(
        EnvInspectorService,
        "_powershell_profile_path",
        lambda _self, _target: profile,
    )
    path_out, roots, requires_privilege = svc._powershell_target_path_and_roots(
        "powershell:current_user"
    )
    ensure(path_out == profile.resolve(strict=False))
    ensure(roots == [Path.home().resolve(strict=False)])
    ensure(requires_privilege is False)


def _assert_registry_operation_wrappers(
    svc: EnvInspectorService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise wrapper behavior for registry-target planning."""
    monkeypatch.setattr(
        svc,
        "_registry_write",
        lambda *args, **kwargs: ("before", "after", "registry", False, None),
    )
    ensure(
        svc._plan_target_operation(
            _target_request(tmp_path, target="windows:user"),
            apply_changes=False,
        )[2]
        == "registry"
    )


def _assert_unsupported_target_wrapper(
    svc: EnvInspectorService, tmp_path: Path
) -> None:
    """Exercise the unsupported-target wrapper branch."""
    with pytest.raises(RuntimeError, match="Unsupported target"):
        svc._file_update(
            _target_request(tmp_path, target="custom:target"),
            apply_changes=False,
        )


def _assert_operation_result_wrapper() -> None:
    """Exercise the operation-result helper wrapper."""
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


def _assert_apply_wrappers_surface_partial_failures(
    svc: EnvInspectorService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise preview and apply wrappers when one target fails."""
    monkeypatch.setattr(
        svc,
        "_apply",
        lambda *args, **kwargs: [
            _result("linux:bashrc"),
            _result("linux:etc_environment", success=False),
        ],
    )
    preview = svc.preview_remove(
        key="API_TOKEN",
        targets=["linux:bashrc", "linux:etc_environment"],
    )
    ensure(len(preview) == 2)
    ensure(
        svc.set_key(
            key="API_TOKEN",
            value="1",
            targets=["linux:bashrc", "linux:etc_environment"],
        )["success"]
        is False
    )
    ensure(
        svc.remove_key(
            key="API_TOKEN",
            targets=["linux:bashrc", "linux:etc_environment"],
        )["success"]
        is False
    )


def test_service_wrapper_owned_target_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Owned wrapper branches should stay covered through the compatibility surface."""
    svc = _service_with_broken_registry(tmp_path, monkeypatch)
    _assert_service_target_helpers(svc, tmp_path, monkeypatch)
    _assert_registry_operation_wrappers(svc, tmp_path, monkeypatch)
    _assert_unsupported_target_wrapper(svc, tmp_path)
    _assert_operation_result_wrapper()
    _assert_apply_wrappers_surface_partial_failures(svc, monkeypatch)


def test_service_listing_filters_cover_registry_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Host-row filtering should survive a registry-provider failure."""
    _service_with_broken_registry(tmp_path, monkeypatch)
    profile = tmp_path / "profile.ps1"

    def _raise_registry_runtime(_provider) -> object:
        """Raise to simulate a runtime registry collector failure."""
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
            collect_process_records_fn=lambda **kwargs: [
                _record("process", "process", context="windows")
            ],
            collect_dotenv_records_fn=lambda *args, **kwargs: [
                _record("dotenv", str(tmp_path / ".env"), context="windows")
            ],
            build_registry_records_fn=_raise_registry_runtime,
            collect_powershell_profile_records_fn=lambda _paths: [
                _record("powershell_profile", str(profile), context="windows")
            ],
            collect_linux_records_fn=lambda **kwargs: [
                _record("linux_bashrc", "~/.bashrc", context="linux")
            ],
        ),
    )
    filtered_rows = service_listing_module.apply_row_filters(
        host_rows,
        source=["powershell_profile"],
        context="windows",
    )
    ensure(len(filtered_rows) == 1)
    ensure(filtered_rows[0].source_type == "powershell_profile")


def test_privileged_writer_returns_after_direct_write(tmp_path: Path) -> None:
    """Direct writes should bypass sudo when they already succeed."""
    target = tmp_path / "environment"
    writes: Dict[str, object] = {}

    def _write_text_file(path: Path, text: str) -> None:
        """Capture and perform the direct file write."""
        writes["path"] = path
        writes["text"] = text
        path.write_text(text, encoding="utf-8")

    def _fail_which(_name: str) -> str:
        """Fail the test if the privileged fallback path is attempted."""
        raise AssertionError("sudo should not be used")

    service_privileged_module.write_linux_etc_environment_with_privilege(
        fixed_path=str(target),
        expected_path=str(target),
        text="A=1\n",
        write_text_file=_write_text_file,
        which_fn=_fail_which,
    )

    ensure(writes == {"path": target, "text": "A=1\n"})


def test_coverage_helpers_cover_source_normalization_and_fallback_xml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coverage helpers should normalize sources and handle fallback XML cases."""
    monkeypatch.chdir(tmp_path)
    ensure(
        coverage_mod.CoverageStats(name="empty", path="x", covered=0, total=0).percent
        == pytest.approx(100.0)
    )

    outside_file = tmp_path.parent / "outside.py"
    outside_file.write_text("print('x')\n", encoding="utf-8")
    ensure(
        coverage_mod._normalize_source_path(str(outside_file)).endswith("outside.py")
    )
    ensure(
        coverage_mod._normalize_source_path("./env_inspector.py")
        == "env_inspector.py"
    )

    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("<coverage>", encoding="utf-8")
    ensure(coverage_mod.coverage_sources_from_xml(bad_xml) == set())

    fallback_xml = tmp_path / "fallback.xml"
    _write_cobertura_xml(fallback_xml, "env_inspector.py", hits="0")
    stats = coverage_mod.parse_coverage_xml("python", fallback_xml)
    ensure(stats.total == 1)
    ensure(stats.covered == 0)

    lcov_path = tmp_path / "coverage.lcov"
    lcov_path.write_text(
        "SF:./scripts/quality/assert_coverage_100.py\nLF:1\nLH:1\n",
        encoding="utf-8",
    )
    ensure(
        coverage_mod.coverage_sources_from_lcov(lcov_path)
        == {"scripts/quality/assert_coverage_100.py"}
    )


def test_coverage_evaluate_reports_missing_first_party_sources() -> None:
    """Coverage evaluation should fail when first-party sources are missing."""
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


def test_coverage_render_lists_empty_sources_and_findings() -> None:
    """Coverage markdown should render empty sections explicitly."""
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


def test_coverage_main_rejects_workspace_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Coverage CLI should reject output paths that escape the workspace."""
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


def test_coverage_main_cli_succeeds_with_valid_xml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coverage CLI should succeed for valid Cobertura input."""
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


def test_coverage_main_requires_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coverage CLI should exit when no XML or LCOV inputs are provided."""
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


def test_assert_coverage_main_supports_lcov_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coverage CLI should also accept LCOV-only input."""
    monkeypatch.chdir(tmp_path)
    lcov_path = tmp_path / "coverage.lcov"
    lcov_path.write_text(
        "SF:./scripts/quality/assert_coverage_100.py\nLF:1\nLH:1\n",
        encoding="utf-8",
    )
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
