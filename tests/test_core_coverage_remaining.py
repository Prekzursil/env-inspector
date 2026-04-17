"""Coverage tests for cli.py, resolver.py, secrets.py, models.py, storage.py."""

from __future__ import absolute_import, division
from tests.assertions import ensure

import sys
import unittest
from io import StringIO
from pathlib import Path

import pytest

from env_inspector_core.models import EnvRecord
from env_inspector_core.resolver import resolve_effective_value
from env_inspector_core.secrets import looks_secret, mask_value, _is_path_like, _is_base64_secret
from env_inspector_core.storage import BackupManager


def _case() -> unittest.TestCase:
    return unittest.TestCase()


# ---------------------------------------------------------------------------
# cli.py coverage
# ---------------------------------------------------------------------------

def test_cli_csv_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """CLI list command with csv output exercises the CSV rendering path (line 156)."""
    from env_inspector_core.cli import run_cli
    from env_inspector_core.service import EnvInspectorService

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    monkeypatch.chdir(tmp_path)

    # Create a .env file so there's data
    (tmp_path / ".env").write_text("MY_VAR=hello\n", encoding="utf-8")

    captured = StringIO()
    monkeypatch.setattr(sys, "stdout", captured)

    exit_code = run_cli(["list", "--output", "csv", "--root", str(tmp_path)], service=svc)
    ensure(exit_code == 0)
    output = captured.getvalue()
    ensure("MY_VAR" in output or "context" in output)


def test_cli_csv_empty_rows(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """CLI list with csv output and no matching rows exercises empty CSV path (line 156)."""
    from env_inspector_core.cli import _emit_stdout_rows

    captured = StringIO()
    monkeypatch.setattr(sys, "stdout", captured)
    # Directly call with empty rows and csv output
    _emit_stdout_rows([], output="csv")
    ensure(captured.getvalue() == "")


def test_cli_table_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """CLI list command with table output exercises the table rendering path (lines 165-170)."""
    from env_inspector_core.cli import run_cli
    from env_inspector_core.service import EnvInspectorService

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    monkeypatch.chdir(tmp_path)

    (tmp_path / ".env").write_text("MY_VAR=hello\n", encoding="utf-8")

    captured = StringIO()
    monkeypatch.setattr(sys, "stdout", captured)

    exit_code = run_cli(["list", "--output", "table", "--root", str(tmp_path)], service=svc)
    assert exit_code == 0
    output = captured.getvalue()
    # Table output uses tabs
    ensure("\t" in output or output == "")


def test_cli_table_empty_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    """_emit_stdout_rows with table format and empty rows exercises line 169->exit."""
    from env_inspector_core.cli import _emit_stdout_rows

    captured = StringIO()
    monkeypatch.setattr(sys, "stdout", captured)
    _emit_stdout_rows([], output="table")
    assert captured.getvalue() == ""


def test_cli_no_command_prints_help(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI with no command prints help and returns 0 (lines 254-255)."""
    from env_inspector_core.cli import run_cli

    captured = StringIO()
    monkeypatch.setattr(sys, "stdout", captured)
    exit_code = run_cli([])
    assert exit_code == 0


def test_cli_value_error_handling(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """CLI catches ValueError and prints to stderr (lines 254-255)."""
    from env_inspector_core.cli import run_cli
    from env_inspector_core.service import EnvInspectorService

    svc = EnvInspectorService(state_dir=tmp_path / "state")

    # --include-raw-secrets raises ValueError for stdout output
    captured_err = StringIO()
    monkeypatch.setattr(sys, "stderr", captured_err)
    monkeypatch.chdir(tmp_path)

    exit_code = run_cli(
        ["list", "--output", "json", "--include-raw-secrets", "--root", str(tmp_path)],
        service=svc,
    )
    # Should print error to stderr and return exit code 2 (the default before handler runs)
    err_output = captured_err.getvalue()
    ensure("not supported" in err_output)
    ensure(exit_code == 2)


# ---------------------------------------------------------------------------
# resolver.py coverage — line 35: linux context
# ---------------------------------------------------------------------------

def test_resolve_effective_value_no_candidates() -> None:
    """resolve_effective_value returns None when no records match (line 35)."""
    result = resolve_effective_value([], "NONEXISTENT", "linux")
    ensure(result is None)


def test_resolve_effective_value_linux_context() -> None:
    """resolve_effective_value uses LINUX_PRECEDENCE for context='linux'."""
    records = [
        EnvRecord(
            source_type="linux_bashrc",
            source_id="linux",
            source_path="/home/user/.bashrc",
            context="linux",
            name="PATH",
            value="/usr/bin",
            is_secret=False,
            is_persistent=True,
            is_mutable=True,
            precedence_rank=20,
            writable=True,
            requires_privilege=False,
        ),
        EnvRecord(
            source_type="linux_etc_environment",
            source_id="linux",
            source_path="/etc/environment",
            context="linux",
            name="PATH",
            value="/usr/local/bin",
            is_secret=False,
            is_persistent=True,
            is_mutable=True,
            precedence_rank=30,
            writable=True,
            requires_privilege=True,
        ),
    ]
    result = resolve_effective_value(records, "PATH", "linux")
    ensure(result is not None)
    ensure(result.source_type == "linux_bashrc")


# ---------------------------------------------------------------------------
# secrets.py coverage
# ---------------------------------------------------------------------------

# Line 45: looks_secret GitHub token detection
def test_looks_secret_github_short_token() -> None:
    """looks_secret detects GitHub short tokens (line 45)."""
    ensure(looks_secret("SOME_VAR", "ghp_" + "a" * 20) is True)
    ensure(looks_secret("SOME_VAR", "gho_" + "a" * 20) is True)


def test_looks_secret_github_pat_token() -> None:
    """looks_secret detects GitHub PAT tokens (line 45)."""
    ensure(looks_secret("SOME_VAR", "github_pat_" + "a" * 20) is True)


# Line 45: _is_base64_secret returns False for short values
def test_is_base64_secret_short_value() -> None:
    """_is_base64_secret returns False for values shorter than 48 chars."""
    ensure(_is_base64_secret("short") is False)


# Line 52: mask_value reveal=True
def test_mask_value_reveal() -> None:
    """mask_value returns the raw value when reveal=True (line 52)."""
    ensure(mask_value("super_secret_value", reveal=True) == "super_secret_value")


# Line 52: mask_value empty string
def test_mask_value_empty() -> None:
    """mask_value returns empty string for empty input."""
    ensure(mask_value("") == "")


# Line 54: mask_value short string (<=8 chars)
def test_mask_value_short() -> None:
    """mask_value masks entire string for short values."""
    ensure(mask_value("12345678") == "********")


# _is_path_like with various path patterns
def test_is_path_like_recognizes_paths() -> None:
    """_is_path_like correctly identifies path-like strings."""
    ensure(_is_path_like("/usr/bin") is True)
    ensure(_is_path_like("./relative") is True)
    ensure(_is_path_like("../parent") is True)
    ensure(_is_path_like("https://example.com") is True)
    ensure(_is_path_like("C:\\Windows") is True)
    ensure(_is_path_like("C:drive") is True)


def test_looks_secret_base64_long_value() -> None:
    """looks_secret detects long base64-ish values as secrets."""
    # 48+ chars of base64-ish content, not path-like
    long_b64 = "A" * 50
    ensure(looks_secret("SOME_VAR", long_b64) is True)


def test_looks_secret_base64_path_not_secret() -> None:
    """looks_secret does not flag long path-like values as secrets."""
    # A long path-like value should not be flagged
    ensure(looks_secret("SOME_VAR", "/usr/local/bin/" + "a" * 50) is False)


# ---------------------------------------------------------------------------
# models.py coverage — line 26: to_dict with include_value=False
# ---------------------------------------------------------------------------

def test_env_record_to_dict_excludes_value() -> None:
    """EnvRecord.to_dict(include_value=False) sets value to empty string."""
    record = EnvRecord(
        source_type="dotenv",
        source_id="test",
        source_path="/test/.env",
        context="linux",
        name="SECRET",
        value="super_secret",
        is_secret=True,
        is_persistent=True,
        is_mutable=True,
        precedence_rank=10,
        writable=True,
        requires_privilege=False,
    )
    payload = record.to_dict(include_value=False)
    ensure(payload["value"] == "")
    ensure(payload["name"] == "SECRET")


# ---------------------------------------------------------------------------
# storage.py coverage — line 75->73 branch: list_backups with non-matching target
# ---------------------------------------------------------------------------

def test_list_backups_filters_by_target(tmp_path: Path) -> None:
    """list_backups only returns backups matching the requested target."""
    mgr = BackupManager(tmp_path / "backups")
    mgr.backup_text("target_a", "content_a")
    mgr.backup_text("target_b", "content_b")

    a_backups = mgr.list_backups("target_a")
    b_backups = mgr.list_backups("target_b")
    c_backups = mgr.list_backups("target_c")

    case = _case()
    case.assertEqual(len(a_backups), 1)
    case.assertEqual(len(b_backups), 1)
    case.assertEqual(len(c_backups), 0)


def test_list_backups_skips_corrupt_files(tmp_path: Path) -> None:
    """list_backups skips backup files that contain invalid JSON (line 75->73)."""
    mgr = BackupManager(tmp_path / "backups")
    mgr.backup_text("target_a", "content")

    # Write a corrupt backup file
    corrupt = tmp_path / "backups" / "corrupt.backup.json"
    corrupt.write_text("not json at all", encoding="utf-8")

    a_backups = mgr.list_backups("target_a")
    ensure(len(a_backups) == 1)  # Only the valid one
