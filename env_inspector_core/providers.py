"""Providers module."""

import importlib
import os
import re
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING, Tuple, cast
from collections.abc import Callable

from .constants import (
    SOURCE_DOTENV,
    SOURCE_LINUX_BASHRC,
    SOURCE_LINUX_ETC_ENV,
    SOURCE_POWERSHELL_PROFILE,
    SOURCE_PROCESS,
    SOURCE_WINDOWS_MACHINE,
    SOURCE_WINDOWS_USER,
)
from .models import EnvRecord
from .parsing import parse_bash_exports, parse_dotenv_text, parse_etc_environment
from .path_policy import PathPolicyError, resolve_scan_root
from .secrets import looks_secret

try:
    import env_inspector_core.providers_wsl as _providers_wsl
except ImportError:  # pragma: no cover - direct script execution
    import providers_wsl as _providers_wsl  # type: ignore

if TYPE_CHECKING:
    from typing_extensions import Protocol

    class WinregModule(Protocol):
        """Protocol for the Windows registry module."""

        HKEY_CURRENT_USER: Any
        HKEY_LOCAL_MACHINE: Any
        KEY_READ: int
        KEY_SET_VALUE: int
        KEY_WOW64_64KEY: int
        REG_EXPAND_SZ: int
        REG_SZ: int
        OpenKey: Callable[[Any, str, int, int], Any]
        EnumValue: Callable[[Any, int], Tuple[str, Any, Any]]
        QueryInfoKey: Callable[[Any], Tuple[int, int, int]]
        SetValueEx: Callable[[Any, str, int, int, str], None]
        DeleteValue: Callable[[Any, str], None]

    class WslClient(Protocol):
        """Protocol for the WSL interop client."""

        available: Callable[[], bool]
        list_distros: Callable[[], List[str]]
        read_file: Callable[[str, str], str]
        scan_dotenv_files: Callable[[str, str, int], List[str]]
else:
    WinregModule = Any
    WslClient = Any


WslProvider = _providers_wsl.WslProvider
collect_wsl_dotenv_records = _providers_wsl.collect_wsl_dotenv_records
collect_wsl_records = _providers_wsl.collect_wsl_records


_winreg: WinregModule | None
try:
    _winreg = cast(WinregModule, importlib.import_module("winreg"))
except ModuleNotFoundError:  # pragma: no cover - non-Windows
    _winreg = None


def _require_winreg() -> WinregModule:
    """Require winreg."""
    if _winreg is None:
        raise RuntimeError("Windows registry provider only available on Windows.")
    return _winreg


SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "dist",
    "build",
    "coverage",
    "frontend/dist",
    "backend/.venv",
}



def is_windows() -> bool:
    """Is windows."""
    return os.name == "nt"


def get_runtime_context() -> str:
    """Get runtime context."""
    return "windows" if is_windows() else "linux"


def current_wsl_distro_name() -> str | None:
    """Current wsl distro name."""
    name = os.environ.get("WSL_DISTRO_NAME", "").strip()
    return name or None


def _is_workspace_scoped_path(path: Path, workspace_root: Path) -> bool:
    """Is workspace scoped path."""
    path_text = str(path)
    workspace_text = str(workspace_root)
    if path_text == workspace_text:
        return True
    return path_text.startswith(workspace_text + os.sep)


def _dotenv_matches(filename: str) -> bool:
    """Dotenv matches."""
    return filename == ".env" or filename.startswith(".env.")


def _iter_dotenv_candidates(root: Path, max_depth: int) -> List[Path]:
    """Iter dotenv candidates."""
    files: List[Path] = []
    for current, dirs, filenames in os.walk(
        root
    ):  # codeql[py/path-injection] root constrained to workspace scope
        rel = Path(os.path.relpath(current, root))
        depth = 0 if str(rel) == "." else len(rel.parts)
        if depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        files.extend(
            Path(current) / filename
            for filename in filenames
            if _dotenv_matches(filename)
        )
    return files


def discover_dotenv_files(root: Path, max_depth: int = 5) -> List[Path]:
    """Discover dotenv files."""
    try:
        safe_root = resolve_scan_root(root)
    except PathPolicyError:
        return []
    return sorted(_iter_dotenv_candidates(safe_root, max_depth=max_depth))


def collect_process_records(context: str = "windows") -> List[EnvRecord]:
    """Collect process records."""
    rows: List[EnvRecord] = []
    for key, value in sorted(os.environ.items(), key=lambda kv: kv[0].lower()):
        rows.append(
            EnvRecord(
                source_type=SOURCE_PROCESS,
                source_id="process",
                source_path="process",
                context=context,
                name=key,
                value=value,
                is_secret=looks_secret(key, value),
                is_persistent=False,
                is_mutable=False,
                precedence_rank=10,
                writable=False,
                requires_privilege=False,
                last_error=None,
            )
        )
    return rows


class WindowsRegistryProvider:
    """Provider for reading and writing Windows registry environment variables."""

    USER_SCOPE = "User"
    MACHINE_SCOPE = "Machine"

    def __init__(self) -> None:
        if not is_windows() or _winreg is None:
            raise RuntimeError("Windows registry provider only available on Windows.")

    @staticmethod
    def _scope_details(scope: str, access: int) -> Tuple[Any, str, int]:
        """Scope details."""
        if scope not in {
            WindowsRegistryProvider.USER_SCOPE,
            WindowsRegistryProvider.MACHINE_SCOPE,
        }:
            raise ValueError(f"Unsupported scope: {scope}")

        registry = _require_winreg()
        root, path, scoped_access = {
            WindowsRegistryProvider.USER_SCOPE: (
                registry.HKEY_CURRENT_USER,
                r"Environment",
                access,
            ),
            WindowsRegistryProvider.MACHINE_SCOPE: (
                registry.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                access | getattr(registry, "KEY_WOW64_64KEY", 0),
            ),
        }[scope]
        return root, path, scoped_access

    @staticmethod
    def _scope_to_key(scope: str) -> Tuple[Any, str]:
        """Scope to key."""
        root, path, _ = WindowsRegistryProvider._scope_details(scope, 0)
        return root, path

    def list_scope(self, scope: str) -> Dict[str, str]:
        """List scope."""
        registry = _require_winreg()
        root, path, access = self._scope_details(scope, registry.KEY_READ)

        with registry.OpenKey(root, path, 0, access) as regkey:
            return {
                name: str(value)
                for index in range(registry.QueryInfoKey(regkey)[1])
                for name, value, _ in [registry.EnumValue(regkey, index)]
            }

    def set_scope_value(self, scope: str, key: str, value: str) -> None:
        """Set scope value."""
        registry = _require_winreg()
        root, path, access = self._scope_details(scope, registry.KEY_SET_VALUE)
        reg_type = registry.REG_EXPAND_SZ if "%" in value else registry.REG_SZ
        with registry.OpenKey(root, path, 0, access) as regkey:
            registry.SetValueEx(regkey, key, 0, reg_type, value)

    def remove_scope_value(self, scope: str, key: str) -> None:
        """Remove scope value."""
        registry = _require_winreg()
        root, path, access = self._scope_details(scope, registry.KEY_SET_VALUE)
        with (
            registry.OpenKey(root, path, 0, access) as regkey,
            suppress(FileNotFoundError),
        ):
            registry.DeleteValue(regkey, key)


def build_registry_records(provider: WindowsRegistryProvider) -> List[EnvRecord]:
    """Build registry records."""
    rows: List[EnvRecord] = []
    for (
        source_type,
        source_id,
        source_path,
        scope,
        precedence_rank,
        requires_privilege,
    ) in (
        (
            SOURCE_WINDOWS_USER,
            "user",
            "HKCU\\Environment",
            provider.USER_SCOPE,
            20,
            False,
        ),
        (
            SOURCE_WINDOWS_MACHINE,
            "machine",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
            provider.MACHINE_SCOPE,
            30,
            True,
        ),
    ):
        for key, value in sorted(
            provider.list_scope(scope).items(), key=lambda kv: kv[0].lower()
        ):
            rows.append(
                EnvRecord(
                    source_type=source_type,
                    source_id=source_id,
                    source_path=source_path,
                    context="windows",
                    name=key,
                    value=value,
                    is_secret=looks_secret(key, value),
                    is_persistent=True,
                    is_mutable=True,
                    precedence_rank=precedence_rank,
                    writable=True,
                    requires_privilege=requires_privilege,
                    last_error=None,
                )
            )
    return rows


def _normalize_powershell_assignment_value(raw_value: str) -> str:
    """Normalize powershell assignment value."""
    value = raw_value.strip().rstrip(";").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _is_valid_powershell_env_key(key: str) -> bool:
    """Is valid powershell env key."""
    return re.fullmatch(r"[A-Za-z_]\w*", key) is not None


def _parse_powershell_assignment(line: str) -> Tuple[str, str] | None:
    """Parse powershell assignment."""
    stripped = line.lstrip()
    if not stripped or stripped.startswith("#") or not stripped.startswith("$env:"):
        return None
    body = stripped[len("$env:") :]
    separator = body.find("=")
    if separator < 0:
        return None
    key = body[:separator].strip()
    if not _is_valid_powershell_env_key(key):
        return None
    value = body[separator + 1 :].strip()
    return key, _normalize_powershell_assignment_value(value)


def parse_powershell_profile_text(text: str) -> List[Tuple[str, str]]:
    """Parse powershell profile text."""
    rows: List[Tuple[str, str]] = []
    for line in text.splitlines():
        entry = _parse_powershell_assignment(line)
        if entry:
            rows.append(entry)
    return rows


def collect_dotenv_records(
    root: Path, max_depth: int = 5, context: str = "windows"
) -> List[EnvRecord]:
    """Collect dotenv records."""
    rows: List[EnvRecord] = []
    for path in discover_dotenv_files(root, max_depth=max_depth):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="latin-1")
        for key, value in parse_dotenv_text(text):
            rows.append(
                EnvRecord(
                    source_type=SOURCE_DOTENV,
                    source_id=str(path),
                    source_path=str(path),
                    context=context,
                    name=key,
                    value=value,
                    is_secret=looks_secret(key, value),
                    is_persistent=True,
                    is_mutable=True,
                    precedence_rank=90,
                    writable=True,
                    requires_privilege=False,
                    last_error=None,
                )
            )
    return rows


def collect_powershell_profile_records(profile_paths: List[Path]) -> List[EnvRecord]:
    """Collect powershell profile records."""
    rows: List[EnvRecord] = []
    for path in profile_paths:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for key, value in parse_powershell_profile_text(text):
            requires_privilege = "program files" in str(path).lower()
            rows.append(
                EnvRecord(
                    source_type=SOURCE_POWERSHELL_PROFILE,
                    source_id=str(path),
                    source_path=str(path),
                    context="windows",
                    name=key,
                    value=value,
                    is_secret=looks_secret(key, value),
                    is_persistent=True,
                    is_mutable=True,
                    precedence_rank=25,
                    writable=True,
                    requires_privilege=requires_privilege,
                    last_error=None,
                )
            )
    return rows


def collect_linux_records(
    *,
    bashrc_path: Path | None = None,
    etc_environment_path: Path | None = None,
    context: str = "linux",
) -> List[EnvRecord]:
    """Collect linux records."""
    rows: List[EnvRecord] = []

    bashrc = bashrc_path or (Path.home() / ".bashrc")
    etc_env = etc_environment_path or Path("/etc/environment")
    for source_type, path, parser, precedence_rank, requires_privilege in [
        spec
        for spec in (
            (SOURCE_LINUX_BASHRC, bashrc, parse_bash_exports, 20, False),
            (SOURCE_LINUX_ETC_ENV, etc_env, parse_etc_environment, 30, True),
        )
        if spec[1].exists()
    ]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for key, value in parser(text).items():
            rows.append(
                EnvRecord(
                    source_type=source_type,
                    source_id="linux",
                    source_path=str(path),
                    context=context,
                    name=key,
                    value=value,
                    is_secret=looks_secret(key, value),
                    is_persistent=True,
                    is_mutable=True,
                    precedence_rank=precedence_rank,
                    writable=True,
                    requires_privilege=requires_privilege,
                    last_error=None,
                )
            )
    return rows
