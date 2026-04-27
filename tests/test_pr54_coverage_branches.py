"""Test pr54 coverage branches module."""

from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from importlib import import_module
service_module = import_module('env_inspector_core.service')
service_listing_module = import_module('env_inspector_core.service_listing')
service_privileged_module = import_module('env_inspector_core.service_privileged')
service_restore_module = import_module('env_inspector_core.service_restore')
from env_inspector_core.constants import SOURCE_DOTENV
from env_inspector_core.service import EnvInspectorService
from scripts.quality import check_sentry_zero as sentry_mod
from tests.assertions import ensure


def test_list_records_rejects_request_and_kwargs(tmp_path: Path) -> None:
    """list_records should reject mixing a request object with keyword overrides."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    request = service_module.ListRecordsRequest(root=tmp_path)

    with pytest.raises(
        TypeError, match="Pass either a ListRecordsRequest or keyword arguments"
    ):
        svc.list_records(request, root=tmp_path)


def test_collect_wsl_rows_rejects_positional_and_unexpected_kwargs() -> None:
    """Test collect wsl rows rejects positional and unexpected kwargs."""
    with pytest.raises(
        TypeError, match="collect_wsl_rows accepts keyword arguments only"
    ):
        service_listing_module.collect_wsl_rows("bad-arg")

    wsl = SimpleNamespace(available=lambda: False)

    with pytest.raises(TypeError, match="Unexpected keyword argument"):
        service_listing_module.collect_wsl_rows(
            runtime_context="linux",
            current_wsl_distro="Ubuntu",
            wsl=wsl,
            scan_depth=1,
            distro="Ubuntu",
            wsl_path="/home/user",
            collect_wsl_records_fn=lambda **_kwargs: [],
            collect_wsl_dotenv_records_fn=lambda **_kwargs: [],
            unexpected=True,
        )


def test_wsl_dotenv_rows_returns_empty_when_request_is_incomplete() -> None:
    """Test wsl dotenv rows returns empty when request is incomplete."""
    calls = []

    rows = service_listing_module._wsl_dotenv_rows(
        request=service_listing_module._WslDotenvRequest(
            distro=None, wsl_path="/home/user/.env", scan_depth=1
        ),
        wsl=SimpleNamespace(),
        collect_wsl_dotenv_records_fn=lambda *_args, **_kwargs: calls.append("called"),
    )

    ensure(not rows)
    ensure(not calls)


def test_bridge_rows_without_current_linux_distro_uses_no_exclusions() -> None:
    """Test bridge rows without current linux distro uses no exclusions."""
    calls = []

    def _fake_collect(_wsl, include_etc, exclude_distros):
        """Fake collect."""
        calls.append((include_etc, exclude_distros))
        return []

    rows = service_listing_module._bridge_rows(
        runtime_context="windows",
        current_wsl_distro="Ubuntu",
        wsl=SimpleNamespace(),
        collect_wsl_records_fn=_fake_collect,
    )

    ensure(not rows)
    ensure(calls == [(True, None)])


def test_apply_row_filters_and_available_targets_cover_falsey_branches(
    tmp_path: Path,
) -> None:
    """Test apply row filters and available targets cover falsey branches."""
    rows = [
        service_module.EnvRecord(
            source_type=SOURCE_DOTENV,
            source_id="dotenv",
            source_path=str(tmp_path / ".env"),
            context="linux",
            name="A",
            value="1",
            is_secret=False,
            is_persistent=True,
            is_mutable=True,
            precedence_rank=1,
            writable=True,
            requires_privilege=False,
        )
    ]

    ensure(
        service_listing_module.apply_row_filters(rows, source=None, context=None)
        == rows
    )

    unknown_record = service_module.EnvRecord(
        source_type="unknown",
        source_id="unknown",
        source_path="ignored",
        context="wsl:Ubuntu",
        name="B",
        value="2",
        is_secret=False,
        is_persistent=True,
        is_mutable=True,
        precedence_rank=1,
        writable=True,
        requires_privilege=False,
    )

    ensure(
        service_listing_module.available_targets(
            [unknown_record], context="wsl:Ubuntu", win_provider_present=False
        )
        == []
    )


def test_write_linux_etc_environment_with_privilege_rejects_invalid_arguments(
    tmp_path: Path,
) -> None:
    """Test write linux etc environment with privilege rejects invalid arguments."""
    target = tmp_path / "environment"

    with pytest.raises(TypeError, match="accepts keyword arguments only"):
        service_privileged_module.write_linux_etc_environment_with_privilege("A=1\n")

    with pytest.raises(TypeError, match="Unexpected keyword argument"):
        service_privileged_module.write_linux_etc_environment_with_privilege(
            fixed_path=str(target),
            expected_path=str(target),
            text="A=1\n",
            write_text_file=lambda _path, _text: None,
            unexpected=True,
        )


def test_restore_helpers_reject_positional_arguments(  # pylint: disable=unused-argument
    tmp_path: Path,  # noqa: ARG001 - pytest fixture
) -> None:
    """Test restore helpers reject positional arguments."""
    with pytest.raises(
        TypeError, match="restore_dotenv_target accepts keyword arguments only"
    ):
        service_restore_module.restore_dotenv_target("bad-arg")

    with pytest.raises(
        TypeError, match="restore_linux_target accepts keyword arguments only"
    ):
        service_restore_module.restore_linux_target("bad-arg")

    with pytest.raises(
        TypeError, match="restore_wsl_target accepts keyword arguments only"
    ):
        service_restore_module.restore_wsl_target("bad-arg")

    with pytest.raises(
        TypeError, match="restore_powershell_target accepts keyword arguments only"
    ):
        service_restore_module.restore_powershell_target("bad-arg")

    with pytest.raises(
        TypeError,
        match="restore_windows_registry_target accepts keyword arguments only",
    ):
        service_restore_module.restore_windows_registry_target("bad-arg")

    with pytest.raises(
        TypeError, match="restore_target accepts keyword arguments only"
    ):
        service_restore_module.restore_target("bad-arg")


def _scoped_dotenv_target(tmp_path: Path) -> SimpleNamespace:
    """Scoped dotenv target."""
    return SimpleNamespace(path=tmp_path / ".env", roots=[tmp_path])


def _wsl_write_adapter() -> SimpleNamespace:
    """Wsl write adapter."""
    return SimpleNamespace(
        write_file=lambda *_args: None,
        write_file_with_privilege=lambda *_args: None,
    )


def test_restore_dotenv_target_rejects_unexpected_keyword_arguments(
    tmp_path: Path,
) -> None:
    """Test restore dotenv target rejects unexpected keyword arguments."""
    scoped = _scoped_dotenv_target(tmp_path)

    with pytest.raises(TypeError, match="Unexpected keyword argument"):
        service_restore_module.restore_dotenv_target(
            target="dotenv:test",
            text="A=1\n",
            scope_roots=[tmp_path],
            parse_scoped_dotenv_target_fn=lambda _target, roots: scoped,
            write_scoped_text_file_fn=lambda **_kwargs: None,
            unexpected=True,
        )


def test_restore_linux_target_rejects_unexpected_keyword_arguments() -> None:
    """Test restore linux target rejects unexpected keyword arguments."""
    with pytest.raises(TypeError, match="Unexpected keyword argument"):
        service_restore_module.restore_linux_target(
            target="linux:bashrc",
            text="A=1\n",
            write_linux_etc_environment_with_privilege_fn=lambda _text: None,
            unexpected=True,
        )


def test_restore_wsl_target_rejects_unexpected_keyword_arguments() -> None:
    """Test restore wsl target rejects unexpected keyword arguments."""
    wsl = _wsl_write_adapter()

    with pytest.raises(TypeError, match="Unexpected keyword argument"):
        service_restore_module.restore_wsl_target(
            target="wsl:Ubuntu:bashrc",
            text="A=1\n",
            wsl=wsl,
            parse_wsl_dotenv_target_fn=lambda _target: ("Ubuntu", "/home/user/.env"),
            validate_wsl_distro_name_fn=lambda distro: distro,
            linux_etc_env_path="/etc/environment",
            unexpected=True,
        )


def test_restore_powershell_target_rejects_unexpected_keyword_arguments(
    tmp_path: Path,
) -> None:
    """Test restore powershell target rejects unexpected keyword arguments."""
    with pytest.raises(TypeError, match="Unexpected keyword argument"):
        service_restore_module.restore_powershell_target(
            target="powershell:current_user",
            text="$env:A='1'\n",
            validated_powershell_restore_path_fn=lambda _target: (
                tmp_path / "profile.ps1"
            ),
            write_text_file_fn=lambda _path, _text: None,
            unexpected=True,
        )


def test_restore_windows_registry_target_rejects_unexpected_keyword_arguments() -> None:
    """Test restore windows registry target rejects unexpected keyword arguments."""
    with pytest.raises(TypeError, match="Unexpected keyword argument"):
        service_restore_module.restore_windows_registry_target(
            target="windows:user",
            text="{}",
            win_provider=SimpleNamespace(
                list_scope=lambda _scope: {},
                remove_scope_value=lambda *_args: None,
                set_scope_value=lambda *_args: None,
            ),
            windows_registry_provider_cls=SimpleNamespace(
                USER_SCOPE="User", MACHINE_SCOPE="Machine"
            ),
            unexpected=True,
        )


def test_restore_target_rejects_unexpected_keyword_arguments(tmp_path: Path) -> None:
    """Test restore target rejects unexpected keyword arguments."""
    with pytest.raises(TypeError, match="Unexpected keyword argument"):
        service_restore_module.restore_target(
            target="linux:bashrc",
            text="A=1\n",
            scope_roots=[tmp_path],
            restore_dotenv_target_fn=lambda **_kwargs: None,
            restore_linux_target_fn=lambda **_kwargs: None,
            restore_wsl_target_fn=lambda **_kwargs: None,
            restore_powershell_target_fn=lambda **_kwargs: None,
            restore_windows_registry_target_fn=lambda **_kwargs: None,
            unexpected=True,
        )


def test_coerce_scan_request_covers_positional_branches() -> None:
    """Test coerce scan request covers positional branches."""
    auth_value = "auth-credential"
    request = sentry_mod.SentryScanRequest(
        org="my-org", projects=["proj"], token=auth_value
    )

    with pytest.raises(
        TypeError, match="Pass either a request object or keyword arguments"
    ):
        sentry_mod._coerce_scan_request(request, org="other")

    coerced = sentry_mod._coerce_scan_request("my-org", ("backend", "web"), auth_value)
    ensure(isinstance(coerced, sentry_mod.SentryScanRequest))
    ensure(coerced.org == "my-org")
    ensure(coerced.projects == ["backend", "web"])
    ensure(coerced.token == auth_value)

    with pytest.raises(TypeError, match="Pass a request object or keyword arguments"):
        sentry_mod._coerce_scan_request("only-org")


def test_resolve_unresolved_count_without_hits_header_and_without_issues() -> None:
    """Test resolve unresolved count without hits header and without issues."""
    failures: List[str] = []

    unresolved = sentry_mod._resolve_unresolved_count([], {}, "proj", failures)

    ensure(unresolved == 0)
    ensure(not failures)


def test_check_sentry_zero_script_does_not_duplicate_helper_root(monkeypatch) -> None:
    """Test check sentry zero script does not duplicate helper root."""
    import runpy
    import sys

    helper_root = str(Path(sentry_mod.__file__).resolve().parent.parent)
    monkeypatch.setattr(
        sys,
        "path",
        [helper_root] + [entry for entry in sys.path if entry != helper_root],
    )
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
    ensure(sys.path.count(helper_root) == 1)


def test_scan_projects_covers_request_object_and_keyword_request_paths(
    monkeypatch,
) -> None:
    """Test scan projects covers request object and keyword request paths."""
    auth_value = "auth-credential"
    monkeypatch.setattr(
        sentry_mod,
        "_request_project_issues",
        lambda org, project, token: ([], {"x-hits": "0"}),
    )

    request = sentry_mod.SentryScanRequest(
        org="my-org", projects=["proj"], token=auth_value
    )
    mode, results, findings, failures = sentry_mod._scan_projects(request)
    ensure(mode == "strict")
    ensure(results == [{"project": "proj", "unresolved": 0}])
    ensure(not findings)
    ensure(not failures)

    mode, results, findings, failures = sentry_mod._scan_projects(
        org="my-org",
        projects=["proj"],
        token=auth_value,
    )
    ensure(mode == "strict")
    ensure(results == [{"project": "proj", "unresolved": 0}])
    ensure(not findings)
    ensure(not failures)
