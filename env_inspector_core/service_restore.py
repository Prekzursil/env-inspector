from __future__ import absolute_import, division

import json
from pathlib import Path
from typing import Any, Callable, List, Tuple, cast


def restore_dotenv_target(
    *,
    target: str,
    text: str,
    scope_roots: List[Path],
    parse_scoped_dotenv_target_fn: Callable[..., Any],
    write_scoped_text_file_fn: Callable[..., Path],
) -> None:
    scoped = parse_scoped_dotenv_target_fn(target, roots=scope_roots)
    write_scoped_text_file_fn(
        candidate_path=scoped.path,
        allowed_roots=scoped.roots,
        text=text,
        label="restore dotenv path",
    )


def restore_linux_target(
    *,
    target: str,
    text: str,
    write_linux_etc_environment_with_privilege_fn: Callable[[str], None],
    bashrc_target: str = "linux:bashrc",
    etc_target: str = "linux:etc_environment",
) -> None:
    if target == bashrc_target:
        path_out = Path(Path.home(), ".bashrc")
        bashrc_parent = cast(Path, path_out.parent)
        bashrc_parent.mkdir(parents=True, exist_ok=True)
        path_out.write_text(text, encoding="utf-8")
        return
    if target == etc_target:
        write_linux_etc_environment_with_privilege_fn(text)
        return
    raise RuntimeError(f"Unsupported Linux restore target: {target}")


def restore_wsl_target(
    *,
    target: str,
    text: str,
    wsl: Any,
    parse_wsl_dotenv_target_fn: Callable[[str], Tuple[str, str]],
    validate_wsl_distro_name_fn: Callable[[str], str],
    linux_etc_env_path: str,
    wsl_dotenv_prefix: str = "wsl_dotenv:",
) -> None:
    if target.startswith(wsl_dotenv_prefix):
        distro, path = parse_wsl_dotenv_target_fn(target)
        wsl.write_file(distro, path, text)
        return
    if target.startswith("wsl:") and target.endswith(":bashrc"):
        distro = validate_wsl_distro_name_fn(target.split(":", 2)[1])
        wsl.write_file(distro, "~/.bashrc", text)
        return
    if target.startswith("wsl:") and target.endswith(":etc_environment"):
        distro = validate_wsl_distro_name_fn(target.split(":", 2)[1])
        wsl.write_file_with_privilege(distro, linux_etc_env_path, text)
        return
    raise RuntimeError(f"Unsupported WSL restore target: {target}")


def restore_powershell_target(
    *,
    target: str,
    text: str,
    validated_powershell_restore_path_fn: Callable[[str], Path],
    write_text_file_fn: Callable[..., None],
) -> None:
    safe_profile = validated_powershell_restore_path_fn(target)
    write_text_file_fn(safe_profile, text)


def restore_windows_registry_target(
    *,
    target: str,
    text: str,
    win_provider: Any,
    windows_registry_provider_cls: Any,
    user_target: str = "windows:user",
) -> None:
    if win_provider is None:
        raise RuntimeError("Windows provider unavailable for registry restore")
    data = json.loads(text)
    scope = (
        windows_registry_provider_cls.USER_SCOPE
        if target == user_target
        else windows_registry_provider_cls.MACHINE_SCOPE
    )
    current = win_provider.list_scope(scope)
    for key in tuple(current):
        if key not in data:
            win_provider.remove_scope_value(scope, key)
    for key, value in data.items():
        win_provider.set_scope_value(scope, key, str(value))


def restore_target(
    *,
    target: str,
    text: str,
    scope_roots: List[Path],
    restore_dotenv_target_fn: Callable[..., None],
    restore_linux_target_fn: Callable[..., None],
    restore_wsl_target_fn: Callable[..., None],
    restore_powershell_target_fn: Callable[..., None],
    restore_windows_registry_target_fn: Callable[..., None],
) -> None:
    if target.startswith("dotenv:"):
        restore_dotenv_target_fn(target=target, text=text, scope_roots=scope_roots)
        return
    if target.startswith("linux:"):
        restore_linux_target_fn(target=target, text=text)
        return
    if target.startswith("wsl_dotenv:") or target.startswith("wsl:"):
        restore_wsl_target_fn(target=target, text=text)
        return
    if target.startswith("powershell:"):
        restore_powershell_target_fn(target=target, text=text)
        return
    if target.startswith("windows:"):
        restore_windows_registry_target_fn(target=target, text=text)
        return
    raise RuntimeError(f"Unsupported restore target: {target}")
