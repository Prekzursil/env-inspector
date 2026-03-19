from __future__ import absolute_import, division

import os
import re
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from subprocess import PIPE, CompletedProcess, run  # nosec B404
from typing import Callable, Dict, List, Optional, Set, Tuple

from .constants import SOURCE_WSL_BASHRC, SOURCE_WSL_DOTENV, SOURCE_WSL_ETC_ENV
from .models import EnvRecord
from .parsing import parse_bash_exports, parse_dotenv_text, parse_etc_environment
from .secrets import looks_secret

_HELPER_DISTRO_RE = re.compile(r"^(docker-desktop|docker-desktop-data)$", re.IGNORECASE)


class WslProvider:
    def __init__(
        self,
        runner: Callable[..., CompletedProcess] | None = None,
        wsl_exe: str | None = None,
    ) -> None:
        self.runner = runner or run
        self.wsl_exe = wsl_exe or self._discover_wsl_exe()
        self._available_cache: bool | None = None

    @staticmethod
    def _discover_wsl_exe() -> str | None:
        candidate_paths = (
            Path(system_root) / "System32" / "wsl.exe" if (system_root := os.environ.get("SystemRoot")) else None,
            Path("/mnt/c/Windows/System32/wsl.exe") if os.name != "nt" else None,
        )
        discovered = next((candidate for candidate in filter(None, candidate_paths) if candidate.exists()), None)
        return (str(discovered) if discovered is not None else None) or shutil.which("wsl.exe") or shutil.which("wsl")

    def available(self) -> bool:
        if self._available_cache is not None:
            return self._available_cache

        try:
            self._available_cache = bool(
                self.wsl_exe
                and self.runner(
                    [str(self.wsl_exe), "-l", "-q"],
                    stdout=PIPE,
                    stderr=PIPE,
                    check=False,
                ).returncode
                == 0
            )
        except OSError:
            self._available_cache = False

        return self._available_cache

    @staticmethod
    def _decode(data: bytes) -> str:
        if not data:
            return ""
        if b"\x00" in data:
            try:
                return data.decode("utf-16le").replace("\x00", "")
            except UnicodeDecodeError:
                return data.decode(errors="ignore")
        return data.decode(errors="ignore")

    def _run(self, args: List[str], input_text: str | None = None) -> str:
        if not self.available():
            raise RuntimeError("wsl.exe not available")
        assert self.wsl_exe is not None
        proc = self.runner(
            [str(self.wsl_exe), *args],
            input=(input_text.encode("utf-8") if input_text is not None else None),
            stdout=PIPE,
            stderr=PIPE,
            check=False,
        )
        out = self._decode(proc.stdout)
        err = self._decode(proc.stderr)
        if proc.returncode != 0:
            raise RuntimeError((err or out).strip() or f"wsl command failed ({proc.returncode})")
        return out

    def list_distros(self) -> List[str]:
        text = self._run(["-l", "-q"])
        return list(
            dict.fromkeys(
                name
                for name in (
                    raw.replace("\x00", "").strip().strip("*").strip()
                    for raw in text.splitlines()
                )
                if name
            )
        )

    def list_distros_for_ui(self) -> List[str]:
        return [d for d in self.list_distros() if not _HELPER_DISTRO_RE.match(d)]

    def read_file(self, distro: str, path: str) -> str:
        quoted_path = shlex.quote(path)
        return self._run(["-d", distro, "-e", "bash", "-lc", f"cat {quoted_path} 2>/dev/null || true"])

    def write_file(self, distro: str, path: str, content: str) -> None:
        quoted_path = shlex.quote(path)
        self._run(["-d", distro, "-e", "bash", "-lc", f"cat > {quoted_path}"], input_text=content)

    def write_file_with_privilege(self, distro: str, path: str, content: str) -> None:
        quoted_path = shlex.quote(path)
        attempts = (
            ["-d", distro, "-u", "root", "-e", "bash", "-lc", f"cat > {quoted_path}"],
            ["-d", distro, "-e", "bash", "-lc", f"sudo tee {quoted_path} >/dev/null"],
        )
        root_error: RuntimeError | None = None
        for args in attempts:
            try:
                self._run(args, input_text=content)
                return
            except RuntimeError as exc:
                root_error = exc
        raise RuntimeError(
            "Failed to write with both root and sudo fallback. Run app as admin or configure sudo/root access."
        ) from root_error

    def scan_dotenv_files(self, distro: str, root_path: str, max_depth: int) -> List[str]:
        quoted_root = shlex.quote(root_path)
        command = (
            f"find {quoted_root} -maxdepth {max_depth} -type f "
            "\\( -name '.env' -o -name '.env.*' \\) 2>/dev/null"
        )
        text = self._run(["-d", distro, "-e", "bash", "-lc", command])
        return [line.strip() for line in text.splitlines() if line.strip()]


@dataclass(frozen=True)
class _WslRecordBatch:
    distro: str
    context: str
    source_type: str
    source_path: str
    pairs: Dict[str, str]
    precedence_rank: int
    requires_privilege: bool


def _append_wsl_records(rows: List[EnvRecord], batch: _WslRecordBatch) -> None:
    for key, value in batch.pairs.items():
        rows.append(
            EnvRecord(
                source_type=batch.source_type,
                source_id=batch.distro,
                source_path=batch.source_path,
                context=batch.context,
                name=key,
                value=value,
                is_secret=looks_secret(key, value),
                is_persistent=True,
                is_mutable=True,
                precedence_rank=batch.precedence_rank,
                writable=True,
                requires_privilege=batch.requires_privilege,
                last_error=None,
            )
        )


def collect_wsl_records(
    wsl: WslProvider,
    include_etc: bool = True,
    exclude_distros: Set[str] | None = None,
) -> List[EnvRecord]:
    rows: List[EnvRecord] = []
    if not wsl.available():
        return rows

    excluded = {x.lower() for x in (exclude_distros or set())}
    for distro in wsl.list_distros():
        if distro.lower() in excluded:
            continue
        context = f"wsl:{distro}"
        batches = (
            _WslRecordBatch(
                distro=distro,
                context=context,
                source_type=SOURCE_WSL_BASHRC,
                source_path=f"{distro}:~/.bashrc",
                pairs=parse_bash_exports(wsl.read_file(distro, "~/.bashrc")),
                precedence_rank=20,
                requires_privilege=False,
            ),
            _WslRecordBatch(
                distro=distro,
                context=context,
                source_type=SOURCE_WSL_ETC_ENV,
                source_path=f"{distro}:/etc/environment",
                pairs=parse_etc_environment(wsl.read_file(distro, "/etc/environment")),
                precedence_rank=10,
                requires_privilege=True,
            ),
        )
        for batch in batches[: 1 + int(include_etc)]:
            _append_wsl_records(rows, batch)
    return rows


def collect_wsl_dotenv_records(wsl: WslProvider, distro: str, root_path: str, max_depth: int) -> List[EnvRecord]:
    rows: List[EnvRecord] = []
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
