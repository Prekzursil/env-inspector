from __future__ import absolute_import

from pathlib import Path

from env_inspector_gui.path_actions import is_openable_local_path, open_source_path


def test_is_openable_local_path_handles_real_and_pseudo_paths(tmp_path: Path):
    local_file = tmp_path / ".env"
    local_file.write_text("A=1\n", encoding="utf-8")

    if not (is_openable_local_path(str(local_file)) is True):
        raise AssertionError()

    if not (is_openable_local_path("wsl:Ubuntu:/etc/environment") is False):
        raise AssertionError()

    if not (is_openable_local_path("registry:HKCU\\Environment") is False):
        raise AssertionError()



def test_open_source_path_uses_platform_command(tmp_path: Path):
    local_file = tmp_path / "a.env"
    local_file.write_text("A=1\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_runner(cmd: list[str]) -> None:
        calls.append(cmd)

    ok, err = open_source_path(str(local_file), platform="linux", run_command=fake_runner)

    if not (ok is True):
        raise AssertionError()

    if not (err is None):
        raise AssertionError()

    if not (calls == [["xdg-open", str(local_file)]]):
        raise AssertionError()



def test_open_source_path_rejects_non_local_path():
    ok, err = open_source_path("wsl:Ubuntu:/etc/environment", platform="linux", run_command=lambda _cmd: None)
    if not (ok is False):
        raise AssertionError()

    if not ("Cannot open" in (err or "")):
        raise AssertionError()

