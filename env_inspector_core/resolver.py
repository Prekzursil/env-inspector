from __future__ import annotations, absolute_import, division

from typing import List, Tuple
from .models import EnvRecord


# Lower number means higher priority.
WINDOWS_PRECEDENCE = {
    "process": 10,
    "windows_user": 20,
    "powershell_profile": 25,
    "windows_machine": 30,
    "dotenv": 90,
}

WSL_PRECEDENCE = {
    "wsl_etc_environment": 10,
    "wsl_bashrc": 20,
    "wsl_dotenv": 30,
    "dotenv": 80,
}

LINUX_PRECEDENCE = {
    "process": 10,
    "linux_bashrc": 20,
    "linux_etc_environment": 30,
    "dotenv": 90,
}


def resolve_effective_value(records: List[EnvRecord], key: str, context: str) -> EnvRecord | None:
    key_norm = key.strip().lower()
    candidates = [r for r in records if r.name.lower() == key_norm and (r.context == context or r.context == "global")]
    if not candidates:
        return None

    if context.startswith("wsl:"):
        table = WSL_PRECEDENCE
    elif context == "linux":
        table = LINUX_PRECEDENCE
    else:
        table = WINDOWS_PRECEDENCE

    def rank(rec: EnvRecord) -> Tuple[int, int, str]:
        source_rank = table.get(rec.source_type, rec.precedence_rank)
        return (source_rank, rec.precedence_rank, rec.source_path)

    return sorted(candidates, key=rank)[0]
