"""Service wsl module."""

from pathlib import PurePosixPath
from typing import Tuple


def validate_wsl_distro_name(raw: str) -> str:
    """Validate wsl distro name."""
    distro = (raw or "").strip()
    if not distro or ":" in distro or "\x00" in distro:
        raise RuntimeError(f"Unsupported WSL distro name: {raw!r}")
    return distro


def validate_wsl_dotenv_path(raw: str, *, path_error: str) -> str:
    """Validate wsl dotenv path."""
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
    prefix: str,
    validate_distro_name_fn,
    validate_dotenv_path_fn,
) -> tuple[str, str]:
    """Parse wsl dotenv target."""
    raw = target[len(prefix) :]
    try:
        distro, path = raw.split(":", 1)
    except ValueError as exc:
        raise RuntimeError(f"Unsupported WSL target: {target}") from exc
    return validate_distro_name_fn(distro), validate_dotenv_path_fn(path)


def _split_wsl_target(target: str) -> tuple[str, str]:
    """Split wsl target."""
    parts = target.split(":", 2)
    if len(parts) != 3:
        raise RuntimeError(f"Unsupported WSL target: {target}")
    _prefix, distro, suffix = parts
    return distro, suffix


def _resolve_standard_wsl_target(
    target: str,
    *,
    validate_distro_name_fn,
    linux_etc_env_path: str,
) -> tuple[str, str, str, bool]:
    """Resolve standard wsl target."""
    distro, suffix = _split_wsl_target(target)
    distro_name = validate_distro_name_fn(distro)
    if suffix == "bashrc":
        return distro_name, "~/.bashrc", "export", False
    if suffix == "etc_environment":
        return distro_name, linux_etc_env_path, "key_value", True
    raise RuntimeError(f"Unsupported WSL target: {target}")


def resolve_wsl_target(*args, **kwargs) -> tuple[str, str, str, bool]:
    """Resolve wsl target."""
    if not args:
        raise TypeError("resolve_wsl_target requires a target argument.")
    target = args[0]
    if len(args) > 1:
        raise TypeError(
            "resolve_wsl_target accepts a single positional target argument only."
        )

    dotenv_prefix = kwargs.pop("dotenv_prefix")
    validate_distro_name_fn = kwargs.pop("validate_distro_name_fn")
    parse_wsl_dotenv_target_fn = kwargs.pop("parse_wsl_dotenv_target_fn")
    linux_etc_env_path = kwargs.pop("linux_etc_env_path")
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected keyword argument(s): {unexpected}")

    if target.startswith(dotenv_prefix):
        distro, path = parse_wsl_dotenv_target_fn(target)
        return distro, path, "key_value", False

    if not target.startswith("wsl:"):
        raise RuntimeError(f"Unsupported WSL target: {target}")
    return _resolve_standard_wsl_target(
        target,
        validate_distro_name_fn=validate_distro_name_fn,
        linux_etc_env_path=linux_etc_env_path,
    )
