from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from .constants import (
    SOURCE_DOTENV,
    SOURCE_LINUX_BASHRC,
    SOURCE_LINUX_ETC_ENV,
    SOURCE_POWERSHELL_PROFILE,
    SOURCE_PROCESS,
    SOURCE_WINDOWS_MACHINE,
    SOURCE_WINDOWS_USER,
    SOURCE_WSL_BASHRC,
    SOURCE_WSL_DOTENV,
    SOURCE_WSL_ETC_ENV,
)
from .models import EnvRecord
from .parsing import parse_bash_exports, parse_dotenv_text, parse_etc_environment
from .secrets import looks_secret

try:
    import winreg  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - non-Windows
    winreg = None


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

_HELPER_DISTRO_RE = re.compile(r"^(docker-desktop|docker-desktop-data)$", re.IGNORECASE)


def is_windows() -> bool:
    return os.name == "nt"


def get_runtime_context() -> str:
    return "windows" if is_windows() else "linux"


def current_wsl_distro_name() -> str | None:
    name = os.environ.get("WSL_DISTRO_NAME", "").strip()
    return name or None


def discover_dotenv_files(root: Path, max_depth: int = 5) -> list[Path]:
    root = Path(root)
    if not root.exists() or not root.is_dir():
        return []

    files: list[Path] = []
    for current, dirs, filenames in os.walk(root):
        rel = Path(os.path.relpath(current, root))
        depth = 0 if str(rel) == "." else len(rel.parts)
        if depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in filenames:
            if filename == ".env" or filename.startswith(".env."):
                files.append(Path(current) / filename)
    return sorted(files)


def collect_process_records(context: str = "windows") -> list[EnvRecord]:
    rows: list[EnvRecord] = []
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
    USER_SCOPE = "User"
    MACHINE_SCOPE = "Machine"

    def __init__(self) -> None:
        if not is_windows() or winreg is None:
            raise RuntimeError("Windows registry provider only available on Windows.")

    @staticmethod
    def _scope_to_key(scope: str) -> tuple[Any, str]:
        if scope == WindowsRegistryProvider.USER_SCOPE:
            return winreg.HKEY_CURRENT_USER, r"Environment"
        if scope == WindowsRegistryProvider.MACHINE_SCOPE:
            return winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        raise ValueError(f"Unsupported scope: {scope}")

    def list_scope(self, scope: str) -> dict[str, str]:
        root, path = self._scope_to_key(scope)
        access = winreg.KEY_READ
        if scope == WindowsRegistryProvider.MACHINE_SCOPE:
            access |= getattr(winreg, "KEY_WOW64_64KEY", 0)

        values: dict[str, str] = {}
        with winreg.OpenKey(root, path, 0, access) as regkey:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(regkey, index)
                except OSError:
                    break
                values[name] = value if isinstance(value, str) else str(value)
                index += 1
        return values

    def set_scope_value(self, scope: str, key: str, value: str) -> None:
        root, path = self._scope_to_key(scope)
        access = winreg.KEY_SET_VALUE
        if scope == WindowsRegistryProvider.MACHINE_SCOPE:
            access |= getattr(winreg, "KEY_WOW64_64KEY", 0)
        reg_type = winreg.REG_EXPAND_SZ if "%" in value else winreg.REG_SZ
        with winreg.OpenKey(root, path, 0, access) as regkey:
            winreg.SetValueEx(regkey, key, 0, reg_type, value)

    def remove_scope_value(self, scope: str, key: str) -> None:
        root, path = self._scope_to_key(scope)
        access = winreg.KEY_SET_VALUE
        if scope == WindowsRegistryProvider.MACHINE_SCOPE:
            access |= getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(root, path, 0, access) as regkey:
            try:
                winreg.DeleteValue(regkey, key)
            except FileNotFoundError:
                pass


def build_registry_records(provider: WindowsRegistryProvider) -> list[EnvRecord]:
    rows: list[EnvRecord] = []
    for key, value in sorted(provider.list_scope(provider.USER_SCOPE).items(), key=lambda kv: kv[0].lower()):
        rows.append(
            EnvRecord(
                source_type=SOURCE_WINDOWS_USER,
                source_id="user",
                source_path="HKCU\\Environment",
                context="windows",
                name=key,
                value=value,
                is_secret=looks_secret(key, value),
                is_persistent=True,
                is_mutable=True,
                precedence_rank=20,
                writable=True,
                requires_privilege=False,
                last_error=None,
            )
        )
    for key, value in sorted(provider.list_scope(provider.MACHINE_SCOPE).items(), key=lambda kv: kv[0].lower()):
        rows.append(
            EnvRecord(
                source_type=SOURCE_WINDOWS_MACHINE,
                source_id="machine",
                source_path="HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                context="windows",
                name=key,
                value=value,
                is_secret=looks_secret(key, value),
                is_persistent=True,
                is_mutable=True,
                precedence_rank=30,
                writable=True,
                requires_privilege=True,
                last_error=None,
            )
        )
    return rows


class WslProvider:
    def __init__(
        self,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
        wsl_exe: str | None = None,
    ) -> None:
        self.runner = runner or subprocess.run
        self.wsl_exe = wsl_exe or self._discover_wsl_exe()
        self._available_cache: bool | None = None

    @staticmethod
    def _discover_wsl_exe() -> str | None:
        candidates: list[Path] = []

        if is_windows():
            system_root = os.environ.get("SystemRoot")
            if system_root:
                candidates.append(Path(system_root) / "System32" / "wsl.exe")
        else:
            candidates.append(Path("/mnt/c/Windows/System32/wsl.exe"))

        for candidate in candidates:
            if candidate.exists():
                return str(candidate)

        for exe_name in ("wsl.exe", "wsl"):
            found = shutil.which(exe_name)
            if found:
                return found

        return None

    def available(self) -> bool:
        if self._available_cache is not None:
            return self._available_cache

        if not self.wsl_exe:
            self._available_cache = False
            return False

        try:
            proc = self.runner(
                [str(self.wsl_exe), "-l", "-q"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self._available_cache = proc.returncode == 0
        except OSError:
            self._available_cache = False

        return self._available_cache

    @staticmethod
    def _decode(data: bytes) -> str:
        if not data:
            return ""
        if b"\x00" in data:
            try:
                return data.decode("utf-16le", errors="ignore").replace("\x00", "")
            except Exception:
                pass
        return data.decode(errors="ignore")

    def _run(self, args: list[str], input_text: str | None = None) -> str:
        if not self.available() or not self.wsl_exe:
            raise RuntimeError("wsl.exe not available")
        proc = self.runner(
            [str(self.wsl_exe), *args],
            input=(input_text.encode("utf-8") if input_text is not None else None),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        out = self._decode(proc.stdout)
        err = self._decode(proc.stderr)
        if proc.returncode != 0:
            raise RuntimeError((err or out).strip() or f"wsl command failed ({proc.returncode})")
        return out

    def list_distros(self) -> list[str]:
        text = self._run(["-l", "-q"])
        distros: list[str] = []
        for raw in text.splitlines():
            name = raw.replace("\x00", "").strip().strip("*").strip()
            if name:
                distros.append(name)
        deduped: list[str] = []
        seen: set[str] = set()
        for d in distros:
            if d not in seen:
                deduped.append(d)
                seen.add(d)
        return deduped

    def list_distros_for_ui(self) -> list[str]:
        return [d for d in self.list_distros() if not _HELPER_DISTRO_RE.match(d)]

    def read_file(self, distro: str, path: str) -> str:
        quoted_path = shlex.quote(path)
        return self._run(["-d", distro, "-e", "bash", "-lc", f"cat {quoted_path} 2>/dev/null || true"])

    def write_file(self, distro: str, path: str, content: str) -> None:
        quoted_path = shlex.quote(path)
        self._run(["-d", distro, "-e", "bash", "-lc", f"cat > {quoted_path}"], input_text=content)

    def write_file_with_privilege(self, distro: str, path: str, content: str) -> None:
        quoted_path = shlex.quote(path)

        # 1) Try direct root user execution.
        try:
            self._run(["-d", distro, "-u", "root", "-e", "bash", "-lc", f"cat > {quoted_path}"], input_text=content)
            return
        except Exception:
            pass

        # 2) Fallback to sudo.
        try:
            self._run(["-d", distro, "-e", "bash", "-lc", f"sudo tee {quoted_path} >/dev/null"], input_text=content)
            return
        except Exception as exc:
            raise RuntimeError(
                "Failed to write with both root and sudo fallback. Run app as admin or configure sudo/root access."
            ) from exc

    def scan_dotenv_files(self, distro: str, root_path: str, max_depth: int) -> list[str]:
        quoted_root = shlex.quote(root_path)
        command = (
            f"find {quoted_root} -maxdepth {max_depth} -type f "
            "\\( -name '.env' -o -name '.env.*' \\) 2>/dev/null"
        )
        text = self._run(["-d", distro, "-e", "bash", "-lc", command])
        return [line.strip() for line in text.splitlines() if line.strip()]


def parse_powershell_profile_text(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    # Handles common patterns: $env:KEY = "value" or 'value'
    regex = re.compile(r"\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = regex.search(stripped)
        if not m:
            continue
        key = m.group(1)
        value = m.group(2).strip()
        if value.endswith(";"):
            value = value[:-1].strip()
        if len(value) >= 2 and ((value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")):
            value = value[1:-1]
        rows.append((key, value))
    return rows


def collect_dotenv_records(root: Path, max_depth: int = 5, context: str = "windows") -> list[EnvRecord]:
    rows: list[EnvRecord] = []
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


def collect_powershell_profile_records(profile_paths: list[Path]) -> list[EnvRecord]:
    rows: list[EnvRecord] = []
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
) -> list[EnvRecord]:
    rows: list[EnvRecord] = []

    bashrc = bashrc_path or (Path.home() / ".bashrc")
    if bashrc.exists():
        bash_text = bashrc.read_text(encoding="utf-8", errors="ignore")
        for key, value in parse_bash_exports(bash_text).items():
            rows.append(
                EnvRecord(
                    source_type=SOURCE_LINUX_BASHRC,
                    source_id="linux",
                    source_path=str(bashrc),
                    context=context,
                    name=key,
                    value=value,
                    is_secret=looks_secret(key, value),
                    is_persistent=True,
                    is_mutable=True,
                    precedence_rank=20,
                    writable=True,
                    requires_privilege=False,
                    last_error=None,
                )
            )

    etc_env = etc_environment_path or Path("/etc/environment")
    if etc_env.exists():
        etc_text = etc_env.read_text(encoding="utf-8", errors="ignore")
        for key, value in parse_etc_environment(etc_text).items():
            rows.append(
                EnvRecord(
                    source_type=SOURCE_LINUX_ETC_ENV,
                    source_id="linux",
                    source_path=str(etc_env),
                    context=context,
                    name=key,
                    value=value,
                    is_secret=looks_secret(key, value),
                    is_persistent=True,
                    is_mutable=True,
                    precedence_rank=30,
                    writable=True,
                    requires_privilege=True,
                    last_error=None,
                )
            )
    return rows


def collect_wsl_records(
    wsl: WslProvider,
    include_etc: bool = True,
    exclude_distros: set[str] | None = None,
) -> list[EnvRecord]:
    rows: list[EnvRecord] = []
    if not wsl.available():
        return rows
    excluded = {x.lower() for x in (exclude_distros or set())}
    for distro in wsl.list_distros():
        if distro.lower() in excluded:
            continue
        context = f"wsl:{distro}"

        bash_text = wsl.read_file(distro, "~/.bashrc")
        for key, value in parse_bash_exports(bash_text).items():
            rows.append(
                EnvRecord(
                    source_type=SOURCE_WSL_BASHRC,
                    source_id=distro,
                    source_path=f"{distro}:~/.bashrc",
                    context=context,
                    name=key,
                    value=value,
                    is_secret=looks_secret(key, value),
                    is_persistent=True,
                    is_mutable=True,
                    precedence_rank=20,
                    writable=True,
                    requires_privilege=False,
                    last_error=None,
                )
            )

        if include_etc:
            etc_text = wsl.read_file(distro, "/etc/environment")
            for key, value in parse_etc_environment(etc_text).items():
                rows.append(
                    EnvRecord(
                        source_type=SOURCE_WSL_ETC_ENV,
                        source_id=distro,
                        source_path=f"{distro}:/etc/environment",
                        context=context,
                        name=key,
                        value=value,
                        is_secret=looks_secret(key, value),
                        is_persistent=True,
                        is_mutable=True,
                        precedence_rank=10,
                        writable=True,
                        requires_privilege=True,
                        last_error=None,
                    )
                )
    return rows


def collect_wsl_dotenv_records(wsl: WslProvider, distro: str, root_path: str, max_depth: int) -> list[EnvRecord]:
    rows: list[EnvRecord] = []
    if not wsl.available():
        return rows
    for path in wsl.scan_dotenv_files(distro, root_path, max_depth):
        text = wsl.read_file(distro, path)
        for key, value in parse_dotenv_text(text):
            rows.append(
                EnvRecord(
                    source_type=SOURCE_WSL_DOTENV,
                    source_id=distro,
                    source_path=f"{distro}:{path}",
                    context=f"wsl:{distro}",
                    name=key,
                    value=value,
                    is_secret=looks_secret(key, value),
                    is_persistent=True,
                    is_mutable=True,
                    precedence_rank=30,
                    writable=True,
                    requires_privilege=False,
                    last_error=None,
                )
            )
    return rows
