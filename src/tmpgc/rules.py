"""Classify temporary entries and decide which ones to remove."""

import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from .entries import normalize_path


if TYPE_CHECKING:
    from .config import Settings
    from .entries import Entry, Tree
    from .processes import Processes


_MINUTE_NS = 60 * 10**9
_DEBUGGER_PIPE = re.compile(r"clr-debug-pipe-([0-9]+)-([0-9]+)-(?:in|out)")
_DIAGNOSTIC_SOCKET = re.compile(r"dotnet-diagnostic-([0-9]+)-([0-9]+)-socket")
_MSBUILD_OWNER = re.compile(r"MSBuild([0-9]+)")


class Origin(Enum):
    PRIMARY_SCAN = auto()
    TEMPORARY_ROOT = auto()
    SCRATCH_PATTERN = auto()


class Kind(Enum):
    SOCKET = auto()
    DEBUGGER_PIPE = auto()
    MSBUILD_DIRECTORY = auto()
    MSBUILD_TEMP_DIRECTORY = auto()
    NUGET_PROBE = auto()
    EMPTY_SDK_DIRECTORY = auto()
    SCRATCH = auto()
    LARGE = auto()


class Verdict(Enum):
    REMOVE = auto()
    KEEP = auto()


@dataclass(frozen=True, slots=True)
class Decision:
    kind: Kind
    verdict: Verdict
    reason: str
    allocated_kib: int | None = None


@dataclass(frozen=True, slots=True)
class Context:
    settings: Settings
    processes: Processes
    now_ns: int
    uid: int
    tree: Callable[[str], Tree | None]
    empty_dir: Callable[[str], bool]
    mount_points: frozenset[str]


@dataclass(frozen=True, slots=True)
class _Owner:
    pid: str
    start_ticks: int | None


def classify(entry: Entry, origin: Origin, context: Context) -> Kind | None:
    mode = entry.info.st_mode
    name = entry.name
    if origin is Origin.SCRATCH_PATTERN:
        return Kind.SCRATCH if entry.info.st_uid == context.uid else None
    if origin is Origin.TEMPORARY_ROOT:
        if entry.info.st_uid != context.uid:
            return None
        if stat.S_ISREG(mode) and name.startswith("CASESENSITIVETEST"):
            return Kind.NUGET_PROBE
        if (
            stat.S_ISDIR(mode)
            and re.fullmatch(r"[A-Za-z0-9]{6}", name)
            and context.empty_dir(entry.path)
        ):
            return Kind.EMPTY_SDK_DIRECTORY
        return Kind.LARGE

    if stat.S_ISSOCK(mode):
        return Kind.SOCKET
    if stat.S_ISFIFO(mode) and _DEBUGGER_PIPE.fullmatch(name):
        return Kind.DEBUGGER_PIPE
    if stat.S_ISDIR(mode) and name.startswith("MSBuild"):
        return (
            Kind.MSBUILD_TEMP_DIRECTORY
            if name.startswith("MSBuildTemp")
            else Kind.MSBUILD_DIRECTORY
        )
    return None


def _owner(name: str) -> _Owner | None:
    match = _DEBUGGER_PIPE.fullmatch(name) or _DIAGNOSTIC_SOCKET.fullmatch(name)
    if match is not None:
        return _Owner(match[1], int(match[2]))
    if (match := _MSBUILD_OWNER.fullmatch(name)) is not None:
        return _Owner(match[1], None)
    return None


def _owner_live(owner: _Owner, entry: Entry, context: Context) -> bool:
    pid = int(owner.pid)
    if owner.start_ticks is not None:
        return context.processes.started_at(pid, owner.start_ticks)
    return context.processes.started_no_later_than(
        pid, context.uid, entry.info.st_mtime_ns
    )


def _idle(tree: Tree, minutes: int, context: Context) -> bool:
    return tree.last_activity_ns < context.now_ns - minutes * _MINUTE_NS


def decide(entry: Entry, kind: Kind, context: Context) -> Decision | None:
    path = entry.path
    normalized = normalize_path(path)
    prefix = normalized.rstrip("/") + "/"
    if normalized in context.mount_points or any(
        mount.startswith(prefix) for mount in context.mount_points
    ):
        return Decision(kind, Verdict.KEEP, "at or above a mount point")

    name = entry.name
    build_minutes = context.settings.build_litter_minutes
    match kind:
        case Kind.SOCKET:
            if path in context.processes.bound_sockets:
                return Decision(kind, Verdict.KEEP, "active socket")
            owner = _owner(name)
            if owner is not None and _owner_live(owner, entry, context):
                return Decision(kind, Verdict.KEEP, "active socket")
            return Decision(kind, Verdict.REMOVE, "stale socket")

        case Kind.DEBUGGER_PIPE | Kind.MSBUILD_DIRECTORY:
            owner = _owner(name)
            if owner is not None and _owner_live(owner, entry, context):
                return Decision(kind, Verdict.KEEP, f"pid {owner.pid} alive")
            if kind is Kind.MSBUILD_DIRECTORY:
                if owner is None:
                    return Decision(kind, Verdict.KEEP, "MSBuild dir without PID")
                return Decision(kind, Verdict.REMOVE, "stale MSBuild dir")
            return Decision(kind, Verdict.REMOVE, "stale clr-debug-pipe")

        case Kind.MSBUILD_TEMP_DIRECTORY:
            tree = context.tree(path)
            if tree is None:
                return None
            if not _idle(tree, build_minutes, context):
                return Decision(
                    kind, Verdict.KEEP, f"MSBuildTemp active within {build_minutes}m"
                )
            return Decision(kind, Verdict.REMOVE, f"MSBuildTemp idle >{build_minutes}m")

        case Kind.NUGET_PROBE:
            if entry.info.st_size != 0:
                return None
            tree = context.tree(path)
            if tree is not None and _idle(tree, build_minutes, context):
                return Decision(kind, Verdict.REMOVE, "NuGet probe file")
            return None

        case Kind.EMPTY_SDK_DIRECTORY:
            tree = context.tree(path)
            if tree is not None and _idle(
                tree, context.settings.empty_directory_minutes, context
            ):
                return Decision(kind, Verdict.REMOVE, "empty .NET temp dir")
            return None

        case Kind.SCRATCH | Kind.LARGE:
            tree = context.tree(path)
            if tree is None:
                return None
            if kind is Kind.LARGE:
                if tree.allocated_kib < context.settings.large_entry_mib * 1024:
                    return None
                days = context.settings.large_entry_days
                label = "large entry"
            else:
                days = context.settings.scratch_days
                label = "scratch"
            if not _idle(tree, days * 24 * 60, context):
                return Decision(kind, Verdict.KEEP, f"{label} touched within {days}d")
            if tree.in_use:
                return Decision(kind, Verdict.KEEP, f"{label} held by a live process")
            return Decision(
                kind, Verdict.REMOVE, f"{label} idle >{days}d", tree.allocated_kib
            )
