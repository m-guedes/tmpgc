"""Classify temporary entries and decide which ones to remove."""

import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum, auto

from .config import Settings
from .entries import Entry, Tree
from .mounts import Mounts
from .processes import Processes


_DEBUGGER_PIPE = re.compile(r"clr-debug-pipe-([0-9]+)-([0-9]+)-(?:in|out)")
_DIAGNOSTIC_SOCKET = re.compile(r"dotnet-diagnostic-([0-9]+)-([0-9]+)-socket")
_MSBUILD_OWNER = re.compile(r"MSBuild([0-9]+)")
_SDK_DIRECTORY = re.compile(r"[A-Za-z0-9]{6}")


class Origin(Enum):
    PRIMARY_SCAN = auto()
    TEMPORARY_ROOT = auto()
    SCRATCH_PATTERN = auto()
    SHARED_MEMORY = auto()


class Kind(Enum):
    SOCKET = auto()
    DEBUGGER_PIPE = auto()
    MSBUILD_DIRECTORY = auto()
    MSBUILD_TEMP_DIRECTORY = auto()
    NUGET_PROBE = auto()
    EMPTY_SDK_DIRECTORY = auto()
    SCRATCH = auto()
    LARGE = auto()
    SEGMENT = auto()


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
    mounts: Mounts


@dataclass(frozen=True, slots=True)
class _Owner:
    pid: int
    start_ticks: int | None


def classify(entry: Entry, origin: Origin, context: Context) -> Kind | None:
    mode = entry.info.st_mode
    name = entry.name
    match origin:
        case Origin.PRIMARY_SCAN:
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

        case Origin.TEMPORARY_ROOT:
            if entry.info.st_uid != context.uid:
                return None
            if (
                stat.S_ISREG(mode)
                and name.startswith("CASESENSITIVETEST")
                and entry.info.st_size == 0
            ):
                return Kind.NUGET_PROBE
            if (
                stat.S_ISDIR(mode)
                and _SDK_DIRECTORY.fullmatch(name)
                and context.empty_dir(entry.path)
            ):
                return Kind.EMPTY_SDK_DIRECTORY
            return Kind.LARGE

        case Origin.SCRATCH_PATTERN:
            return Kind.SCRATCH if entry.info.st_uid == context.uid else None

        case Origin.SHARED_MEMORY:
            return (
                Kind.SEGMENT
                if stat.S_ISREG(mode) and entry.info.st_uid == context.uid
                else None
            )


def _owner(name: str) -> _Owner | None:
    match = _DEBUGGER_PIPE.fullmatch(name) or _DIAGNOSTIC_SOCKET.fullmatch(name)
    if match is not None:
        return _Owner(int(match[1]), int(match[2]))
    if (match := _MSBUILD_OWNER.fullmatch(name)) is not None:
        return _Owner(int(match[1]), None)
    return None


def _owner_live(owner: _Owner, entry: Entry, context: Context) -> bool:
    if owner.start_ticks is not None:
        return context.processes.started_at(owner.pid, owner.start_ticks)
    return context.processes.started_no_later_than(
        owner.pid, context.uid, entry.info.st_mtime_ns
    )


def _span(threshold: timedelta) -> str:
    if not threshold % timedelta(days=1):
        return f"{threshold.days}d"
    return f"{threshold // timedelta(minutes=1)}m"


def _idle(
    kind: Kind, tree: Tree, threshold: timedelta, label: str, context: Context
) -> Decision:
    threshold_ns = (threshold // timedelta(microseconds=1)) * 1000
    span = _span(threshold)
    if context.now_ns - tree.last_activity_ns <= threshold_ns:
        return Decision(kind, Verdict.KEEP, f"{label} touched within {span}")
    return Decision(kind, Verdict.REMOVE, f"{label} idle >{span}", tree.allocated_kib)


def _idle_unused(
    kind: Kind, tree: Tree, threshold: timedelta, label: str, context: Context
) -> Decision:
    decision = _idle(kind, tree, threshold, label, context)
    if decision.verdict is Verdict.REMOVE and tree.in_use:
        return Decision(kind, Verdict.KEEP, f"{label} held by a live process")
    return decision


def decide(entry: Entry, kind: Kind, context: Context) -> Decision | None:
    decision = _decide_kind(entry, kind, context)
    # Removing an entry at or above a mount point would empty the mounted tree.
    if (
        decision is not None
        and decision.verdict is Verdict.REMOVE
        and context.mounts.at_or_above(entry.location)
    ):
        return Decision(kind, Verdict.KEEP, "at or above a mount point")
    return decision


def _decide_kind(entry: Entry, kind: Kind, context: Context) -> Decision | None:
    path = entry.path
    name = entry.name
    settings = context.settings
    match kind:
        case Kind.SOCKET:
            if path in context.processes.bound_sockets:
                return Decision(kind, Verdict.KEEP, "active socket")
            owner = _owner(name)
            if owner is not None and _owner_live(owner, entry, context):
                return Decision(kind, Verdict.KEEP, "active socket")
            return Decision(kind, Verdict.REMOVE, "stale socket")

        case Kind.DEBUGGER_PIPE:
            owner = _owner(name)
            if owner is not None and _owner_live(owner, entry, context):
                return Decision(kind, Verdict.KEEP, f"pid {owner.pid} alive")
            return Decision(kind, Verdict.REMOVE, "stale clr-debug-pipe")

        case Kind.MSBUILD_DIRECTORY:
            owner = _owner(name)
            if owner is None:
                return Decision(kind, Verdict.KEEP, "MSBuild dir without PID")
            if _owner_live(owner, entry, context):
                return Decision(kind, Verdict.KEEP, f"pid {owner.pid} alive")
            tree = context.tree(path)
            if tree is None:
                return None
            return Decision(
                kind, Verdict.REMOVE, "stale MSBuild dir", tree.allocated_kib
            )

        case Kind.MSBUILD_TEMP_DIRECTORY:
            rule, threshold, label = _idle, settings.build_litter_idle, "MSBuildTemp"
        case Kind.NUGET_PROBE:
            rule, threshold, label = _idle, settings.build_litter_idle, "NuGet probe"
        case Kind.EMPTY_SDK_DIRECTORY:
            rule, threshold, label = (
                _idle,
                settings.empty_directory_idle,
                "empty .NET temp dir",
            )
        case Kind.SCRATCH:
            rule, threshold, label = _idle_unused, settings.scratch_idle, "scratch"
        case Kind.LARGE:
            rule, threshold, label = (
                _idle_unused,
                settings.large_entry_idle,
                "large entry",
            )
        case Kind.SEGMENT:
            rule, threshold, label = _idle_unused, settings.segment_idle, "segment"

    tree = context.tree(path)
    if tree is None or (
        kind is Kind.LARGE and tree.allocated_kib < settings.large_entry_mib * 1024
    ):
        return None
    return rule(kind, tree, threshold, label, context)
