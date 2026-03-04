from __future__ import absolute_import, division

from pathlib import Path

from env_inspector_gui.path_actions import is_openable_local_path, open_source_path

def _expect(condition, message: str = "") -> None:
    if not condition: raise AssertionError(message)



def test_is_openable_local_path_handles_real_and_pseudo_paths(tmp_path: Path):
    local_file = tmp_path / ".env"
    local_file.write_text("A=1\n", encoding="utf-8")

    _expect(is_openable_local_path(str(local_file)) is True)

    _expect(is_openable_local_path("wsl:Ubuntu:/etc/environment") is False)

    _expect(is_openable_local_path("registry:HKCU\\Environment") is False)



def test_open_source_path_uses_platform_command(tmp_path: Path):
    local_file = tmp_path / "a.env"
    local_file.write_text("A=1\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_runner(cmd: list[str]) -> None:
        calls.append(cmd)

    ok, err = open_source_path(str(local_file), platform="linux", run_command=fake_runner)

    _expect(ok is True)

    _expect(err is None)

    _expect(calls == [["xdg-open", str(local_file)]])



def test_open_source_path_rejects_non_local_path():
    ok, err = open_source_path("wsl:Ubuntu:/etc/environment", platform="linux", run_command=lambda _cmd: None)
    _expect(ok is False)

    _expect("Cannot open" in (err or ""))
