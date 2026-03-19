from __future__ import absolute_import, division

import json
from pathlib import Path
from typing import cast


def restore_dotenv_target(*args, **kwargs) -> None:
    if args:
        raise TypeError("restore_dotenv_target accepts keyword arguments only.")

    target = kwargs.pop("target")
    text = kwargs.pop("text")
    scope_roots = kwargs.pop("scope_roots")
    parse_scoped_dotenv_target_fn = kwargs.pop("parse_scoped_dotenv_target_fn")
    write_scoped_text_file_fn = kwargs.pop("write_scoped_text_file_fn")
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected keyword argument(s): {unexpected}")

    scoped = parse_scoped_dotenv_target_fn(target, roots=scope_roots)
    write_scoped_text_file_fn(
        candidate_path=scoped.path,
        allowed_roots=scoped.roots,
        text=text,
        label="restore dotenv path",
    )


def restore_linux_target(*args, **kwargs) -> None:
    if args:
        raise TypeError("restore_linux_target accepts keyword arguments only.")

    target = kwargs.pop("target")
    text = kwargs.pop("text")
    write_linux_etc_environment_with_privilege_fn = kwargs.pop("write_linux_etc_environment_with_privilege_fn")
    bashrc_target = kwargs.pop("bashrc_target", "linux:bashrc")
    etc_target = kwargs.pop("etc_target", "linux:etc_environment")
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected keyword argument(s): {unexpected}")

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


def restore_wsl_target(*args, **kwargs) -> None:
    if args:
        raise TypeError("restore_wsl_target accepts keyword arguments only.")

    target = kwargs.pop("target")
    text = kwargs.pop("text")
    wsl = kwargs.pop("wsl")
    parse_wsl_dotenv_target_fn = kwargs.pop("parse_wsl_dotenv_target_fn")
    validate_wsl_distro_name_fn = kwargs.pop("validate_wsl_distro_name_fn")
    linux_etc_env_path = kwargs.pop("linux_etc_env_path")
    wsl_dotenv_prefix = kwargs.pop("wsl_dotenv_prefix", "wsl_dotenv:")
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected keyword argument(s): {unexpected}")

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


def restore_powershell_target(*args, **kwargs) -> None:
    if args:
        raise TypeError("restore_powershell_target accepts keyword arguments only.")

    target = kwargs.pop("target")
    text = kwargs.pop("text")
    validated_powershell_restore_path_fn = kwargs.pop("validated_powershell_restore_path_fn")
    write_text_file_fn = kwargs.pop("write_text_file_fn")
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected keyword argument(s): {unexpected}")

    safe_profile = validated_powershell_restore_path_fn(target)
    write_text_file_fn(safe_profile, text)


def restore_windows_registry_target(*args, **kwargs) -> None:
    if args:
        raise TypeError("restore_windows_registry_target accepts keyword arguments only.")

    target = kwargs.pop("target")
    text = kwargs.pop("text")
    win_provider = kwargs.pop("win_provider")
    windows_registry_provider_cls = kwargs.pop("windows_registry_provider_cls")
    user_target = kwargs.pop("user_target", "windows:user")
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected keyword argument(s): {unexpected}")

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


def restore_target(*args, **kwargs) -> None:
    if args:
        raise TypeError("restore_target accepts keyword arguments only.")

    target = kwargs.pop("target")
    text = kwargs.pop("text")
    scope_roots = kwargs.pop("scope_roots")
    restore_dotenv_target_fn = kwargs.pop("restore_dotenv_target_fn")
    restore_linux_target_fn = kwargs.pop("restore_linux_target_fn")
    restore_wsl_target_fn = kwargs.pop("restore_wsl_target_fn")
    restore_powershell_target_fn = kwargs.pop("restore_powershell_target_fn")
    restore_windows_registry_target_fn = kwargs.pop("restore_windows_registry_target_fn")
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected keyword argument(s): {unexpected}")

    handler = _restore_dispatch(target)
    handler(
        target=target,
        text=text,
        scope_roots=scope_roots,
        restore_dotenv_target_fn=restore_dotenv_target_fn,
        restore_linux_target_fn=restore_linux_target_fn,
        restore_wsl_target_fn=restore_wsl_target_fn,
        restore_powershell_target_fn=restore_powershell_target_fn,
        restore_windows_registry_target_fn=restore_windows_registry_target_fn,
    )


def _restore_dispatch(target: str):
    if target.startswith("dotenv:"):
        return _dispatch_restore_dotenv
    if target.startswith("linux:"):
        return _dispatch_restore_linux
    if target.startswith("wsl_dotenv:") or target.startswith("wsl:"):
        return _dispatch_restore_wsl
    if target.startswith("powershell:"):
        return _dispatch_restore_powershell
    if target.startswith("windows:"):
        return _dispatch_restore_windows
    raise RuntimeError(f"Unsupported restore target: {target}")


def _dispatch_restore_dotenv(**kwargs) -> None:
    kwargs["restore_dotenv_target_fn"](target=kwargs["target"], text=kwargs["text"], scope_roots=kwargs["scope_roots"])


def _dispatch_restore_linux(**kwargs) -> None:
    kwargs["restore_linux_target_fn"](target=kwargs["target"], text=kwargs["text"])


def _dispatch_restore_wsl(**kwargs) -> None:
    kwargs["restore_wsl_target_fn"](target=kwargs["target"], text=kwargs["text"])


def _dispatch_restore_powershell(**kwargs) -> None:
    kwargs["restore_powershell_target_fn"](target=kwargs["target"], text=kwargs["text"])


def _dispatch_restore_windows(**kwargs) -> None:
    kwargs["restore_windows_registry_target_fn"](target=kwargs["target"], text=kwargs["text"])
