"""Service paths module."""

import os
from pathlib import Path, PureWindowsPath
from typing import List, Tuple
from collections.abc import Callable, Sequence


def get_powershell_profile_paths() -> List[Path]:
    """Get powershell profile paths."""
    docs = Path.home() / "Documents"
    current = docs / "PowerShell" / "Microsoft.PowerShell_profile.ps1"
    all_users = Path(r"C:\\Program Files\\PowerShell\\7\\profile.ps1")
    return [current, all_users]


def is_path_within(path: Path, root: Path) -> bool:
    """Is path within."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_path_in_roots(path: Path, roots: Sequence[Path], *, label: str) -> Path:
    """Validate path in roots."""
    resolved_path = path.resolve(strict=False)
    resolved_roots = [root.resolve(strict=False) for root in roots]
    for root in resolved_roots:
        if is_path_within(resolved_path, root):
            return resolved_path
    raise RuntimeError(f"{label} is outside approved roots: {resolved_path}")


def write_text_file(path: Path, text: str, *, ensure_parent: bool) -> None:
    """Write text file."""
    if ensure_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def write_scoped_text_file(
    *,
    candidate_path: Path,
    allowed_roots: Sequence[Path],
    text: str,
    label: str,
) -> Path:
    """Write scoped text file."""
    safe_path = validate_path_in_roots(candidate_path, list(allowed_roots), label=label)
    write_text_file(safe_path, text, ensure_parent=True)
    return safe_path


def powershell_target_path_and_roots(
    target: str,
    *,
    profile_resolver: Callable[[str], Path],
    current_user_target: str,
    all_users_target: str,
) -> Tuple[Path, List[Path], bool]:
    """Powershell target path and roots."""
    if target == current_user_target:
        profile = profile_resolver(current_user_target).resolve(strict=False)
        return profile, [Path.home().resolve(strict=False)], False
    if target == all_users_target:
        profile = profile_resolver(all_users_target).resolve(strict=False)
        return profile, [Path(r"C:\\Program Files").resolve(strict=False)], True
    raise RuntimeError(f"Unsupported PowerShell target: {target}")


def validated_powershell_restore_path(
    target: str,
    *,
    profile_resolver: Callable[[str], Path],
    current_user_target: str,
    all_users_target: str,
) -> Path:
    """Validated powershell restore path."""
    profile, allowed_roots, _requires_priv = powershell_target_path_and_roots(
        target,
        profile_resolver=profile_resolver,
        current_user_target=current_user_target,
        all_users_target=all_users_target,
    )
    return validate_path_in_roots(
        profile, allowed_roots, label="PowerShell profile path"
    )


def linux_etc_environment_path(linux_etc_env_path: str) -> Path:
    """Linux etc environment path."""
    path = (
        Path(PureWindowsPath(linux_etc_env_path).as_posix())
        if os.name == "nt"
        else Path(linux_etc_env_path)
    )
    if path.as_posix() != linux_etc_env_path:
        raise RuntimeError(f"Unexpected /etc/environment resolution: {path}")
    return path
