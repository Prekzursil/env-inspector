from __future__ import annotations

from pathlib import Path
from shutil import which
from subprocess import PIPE, CompletedProcess, run  # nosec B404
from typing import Callable


def _try_direct_write(path: Path, text: str, write_text_file: Callable[[Path, str], None]) -> bool:
    try:
        write_text_file(path, text)
        return True
    except (OSError, PermissionError):
        return False


def _run_sudo_tee(
    allowed_sudo_path: str,
    expected_path: str,
    text: str,
    run_fn: Callable[..., CompletedProcess[str]],
) -> CompletedProcess[str]:
    return run_fn(  # nosec B603
        [allowed_sudo_path, "-n", "tee", expected_path],
        input=text,
        text=True,
        stdout=PIPE,
        stderr=PIPE,
        check=False,
    )


def write_linux_etc_environment_with_privilege(
    *,
    fixed_path: str,
    expected_path: str,
    text: str,
    write_text_file: Callable[[Path, str], None],
    which_fn: Callable[[str], str | None] = which,
    run_fn: Callable[..., CompletedProcess[str]] = run,
) -> None:
    if fixed_path != expected_path:
        raise RuntimeError(f"Unexpected /etc/environment resolution: {fixed_path}")
    path = Path(expected_path)
    if _try_direct_write(path, text, write_text_file):
        return

    sudo_path = which_fn("sudo")
    allowed_sudo_path = sudo_path if sudo_path in {"/usr/bin/sudo", "/bin/sudo"} else None
    if not allowed_sudo_path:
        raise RuntimeError("sudo is not available for /etc/environment fallback.")
    proc = _run_sudo_tee(allowed_sudo_path, expected_path, text, run_fn)
    if proc.returncode == 0:
        return

    err = (proc.stderr or "").strip()
    raise RuntimeError(
        "Failed to write /etc/environment using direct write and sudo fallback. "
        "Run with elevated privileges or configure passwordless sudo for this command."
        + (f" Details: {err}" if err else "")
    )
