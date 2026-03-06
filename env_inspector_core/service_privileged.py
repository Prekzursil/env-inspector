from pathlib import Path
from shutil import which
from subprocess import PIPE, run  # nosec B404
from typing import Callable


def write_linux_etc_environment_with_privilege(
    *,
    fixed_path: str,
    expected_path: str,
    text: str,
    write_text_file: Callable[[Path, str], None],
    which_fn: Callable[[str], str | None] = which,
    run_fn: Callable[..., object] = run,
) -> None:
    if fixed_path != expected_path:
        raise RuntimeError(f"Unexpected /etc/environment resolution: {fixed_path}")
    path = Path(expected_path)
    try:
        write_text_file(path, text)
        return
    except PermissionError:
        pass
    except OSError:
        pass

    sudo_path = which_fn("sudo")
    allowed_sudo_path = sudo_path if sudo_path in {"/usr/bin/sudo", "/bin/sudo"} else None
    if not allowed_sudo_path:
        raise RuntimeError("sudo is not available for /etc/environment fallback.")
    proc = run_fn(  # nosec B603
        [allowed_sudo_path, "-n", "tee", expected_path],
        input=text,
        text=True,
        stdout=PIPE,
        stderr=PIPE,
        check=False,
    )
    if proc.returncode == 0:
        return

    err = (proc.stderr or "").strip()
    raise RuntimeError(
        "Failed to write /etc/environment using direct write and sudo fallback. "
        "Run with elevated privileges or configure passwordless sudo for this command."
        + (f" Details: {err}" if err else "")
    )
