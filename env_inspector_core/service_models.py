"""Typed request models shared by service helpers."""

from __future__ import absolute_import, division

from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

from .constants import DEFAULT_SCAN_DEPTH


@dataclass(frozen=True)
class TargetOperationRequest:
    """A normalized request for a single target mutation."""

    target: str
    key: str
    value: str | None
    action: str
    scope_roots: Sequence[Path]


@dataclass(frozen=True)
class TargetOperationBatch:
    """A normalized batch mutation request."""

    action: str
    key: str
    value: str | None
    targets: List[str]
    scope_roots: List[str | Path] | None = None


@dataclass(frozen=True)
class ListRecordsRequest:
    """A normalized request for record collection."""

    root: str | Path | None = None
    context: str | None = None
    source: List[str] | None = None
    wsl_path: str | None = None
    distro: str | None = None
    scan_depth: int = DEFAULT_SCAN_DEPTH
    include_raw_secrets: bool = False


@dataclass(frozen=True)
class ShellMutationRequest:
    """A normalized mutation for shell-like files."""

    key: str
    value: str | None
    action: str
    style: str
