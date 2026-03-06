from __future__ import absolute_import, division

import webbrowser
from typing import Callable, Tuple
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
    open_uri: Callable[[str], bool] | None = None,
) -> Tuple[bool, str | None]:
    if not is_openable_local_path(source_path):
        return False, "Cannot open non-local source path"

    try:
        _open_path(source_path, open_uri=open_uri)
    except Exception as exc:
        return False, str(exc)

    return True, None


def _open_path(source_path: str, *, open_uri: Callable[[str], bool] | None = None) -> None:
    uri = Path(source_path).resolve().as_uri()
    opener = open_uri or webbrowser.open
    opened = opener(uri)
    if not opened:
        raise RuntimeError("Failed to open source path")
