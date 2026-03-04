from __future__ import absolute_import, division

from pathlib import PurePosixPath
from typing import Tuple


DEFAULT_WSL_DOTENV_PREFIX = "wsl_dotenv:"
DEFAULT_WSL_DOTENV_PATH_ERROR = "Unsupported WSL dotenv target path"


def validate_wsl_distro_name(raw: str) -> str:
    distro = (raw or "").strip()
    if not distro or ":" in distro or "\x00" in distro:
        raise RuntimeError(f"Unsupported WSL distro name: {raw!r}")
    return distro


def validate_wsl_dotenv_path(raw: str, *, path_error: str = DEFAULT_WSL_DOTENV_PATH_ERROR) -> str:
    candidate = (raw or "").strip()
    if not candidate or "\x00" in candidate:
        raise RuntimeError(path_error)
    path = PurePosixPath(candidate)
    if ".." in path.parts or not str(path).startswith("/"):
        raise RuntimeError(path_error)
    if path.name != ".env" and not path.name.startswith(".env."):
        raise RuntimeError(path_error)
    return str(path)


def parse_wsl_dotenv_target(
    target: str,
    *,
    prefix: str = DEFAULT_WSL_DOTENV_PREFIX,
    path_error: str = DEFAULT_WSL_DOTENV_PATH_ERROR,
) -> Tuple[str, str]:
    raw = target[len(prefix) :]
    try:
        distro, path = raw.split(":", 1)
    except ValueError as exc:
        raise RuntimeError(f"Unsupported WSL target: {target}") from exc
    return validate_wsl_distro_name(distro), validate_wsl_dotenv_path(path, path_error=path_error)


def resolve_wsl_target(
    target: str,
    *,
    prefix: str = DEFAULT_WSL_DOTENV_PREFIX,
    etc_environment_path: str = "/etc/environment",
    path_error: str = DEFAULT_WSL_DOTENV_PATH_ERROR,
) -> Tuple[str, str, str, bool]:
    if target.startswith(prefix):
        distro, path = parse_wsl_dotenv_target(target, prefix=prefix, path_error=path_error)
        return distro, path, "key_value", False

    if not target.startswith("wsl:"):
        raise RuntimeError(f"Unsupported WSL target: {target}")

    parts = target.split(":", 2)
    if len(parts) != 3:
        raise RuntimeError(f"Unsupported WSL target: {target}")

    _prefix, distro, suffix = parts
    distro_name = validate_wsl_distro_name(distro)
    if suffix == "bashrc":
        return distro_name, "~/.bashrc", "export", False
    if suffix == "etc_environment":
        return distro_name, etc_environment_path, "key_value", True
    raise RuntimeError(f"Unsupported WSL target: {target}")
