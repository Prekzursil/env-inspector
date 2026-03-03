from __future__ import annotations

import os
import subprocess
from pathlib import Path


def is_openable_local_path(source_path: str) -> bool:
    if not source_path:
        return False

    path = Path(source_path)
    if path.exists():
        return True

    lowered = source_path.lower()
    if lowered.startswith(("wsl:", "registry:", "windows:", "powershell:")):
        return False

    # Typical pseudo form: distro:/path or distro:~/path
    if source_path.count(":") >= 2 and not (len(source_path) >= 2 and source_path[1] == ":"):
        return False

    return False


def open_source_path(
    source_path: str,
    *,
    platform: str | None = None,
    run_command=None,
) -> tuple[bool, str | None]:
    if not is_openable_local_path(source_path):
        return False, "Cannot open non-local source path"

    try:
        _open_path(source_path, platform=platform, run_command=run_command)
    except Exception as exc:
        return False, str(exc)

    return True, None


def _open_path(source_path: str, *, platform: str | None = None, run_command=None) -> None:
    system = (platform or _platform_name()).lower()
    if system in {"windows", "win32", "nt"}:
        if run_command is not None:
            run_command(["cmd", "/c", "start", "", source_path])
            return
        os.startfile(source_path)  # type: ignore[attr-defined]
        return

    cmd = ["open", source_path] if system == "darwin" else ["xdg-open", source_path]
    if run_command is not None:
        run_command(cmd)
        return
    subprocess.run(cmd, check=False)


def _platform_name() -> str:
    if os.name == "nt":
        return "windows"
    return os.uname().sysname.lower() if hasattr(os, "uname") else "linux"
