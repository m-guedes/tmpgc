"""Classify temporary entries and decide which ones to remove."""

import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .config import Settings
    from .entries import Entry
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


class Verdict(Enum):
    REMOVE = auto()
    KEEP = auto()


@dataclass(frozen=True, slots=True)
class Decision:
    kind: Kind
    verdict: Verdict
    reason: str


@dataclass(frozen=True, slots=True)
class Context:
    settings: Settings
    processes: Processes
    now_ns: int
    uid: int
    newest_change: Callable[[str], int | None]
    empty_dir: Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class _Owner:
    pid: str
    start_ticks: int | None


def classify(entry: Entry, origin: Origin, uid: int) -> Kind | None:
    mode = entry.info.st_mode
    name = entry.name
    if origin is Origin.SCRATCH_PATTERN:
        return Kind.SCRATCH if entry.info.st_uid == uid else None
    if origin is Origin.TEMPORARY_ROOT:
        if entry.info.st_uid != uid:
            return None
        if stat.S_ISREG(mode) and name.startswith("CASESENSITIVETEST"):
            return Kind.NUGET_PROBE
        if stat.S_ISDIR(mode) and re.fullmatch(r"[A-Za-z0-9]{6}", name):
            return Kind.EMPTY_SDK_DIRECTORY
        return None

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


def _owner_live(owner: _Owner, context: Context) -> bool:
    pid = int(owner.pid)
    if owner.start_ticks is not None:
        return context.processes.started_at(pid, owner.start_ticks)
    return pid in context.processes.holders


def _cutoff(context: Context, minutes: int) -> int:
    # GNU findutils 4.10.0's -mmin -N and +N compare against N minutes ago.
    return context.now_ns - minutes * _MINUTE_NS


def _recent(path: str, minutes: int, context: Context) -> bool:
    newest = context.newest_change(path)
    return newest is not None and newest > _cutoff(context, minutes)


def _held(path: str, context: Context) -> bool:
    targets = context.processes.held_paths
    path = path.rstrip("/")
    return path in targets or any(target.startswith(f"{path}/") for target in targets)


def decide(entry: Entry, kind: Kind, context: Context) -> Decision | None:
    path = entry.path
    name = entry.name
    build_minutes = context.settings.build_litter_minutes
    match kind:
        case Kind.SOCKET:
            if path in context.processes.bound_sockets:
                return Decision(kind, Verdict.KEEP, "active socket")
            owner = _owner(name)
            if owner is not None and _owner_live(owner, context):
                return Decision(kind, Verdict.KEEP, "active socket")
            return Decision(kind, Verdict.REMOVE, "stale socket")

        case Kind.DEBUGGER_PIPE | Kind.MSBUILD_DIRECTORY:
            owner = _owner(name)
            if owner is not None and _owner_live(owner, context):
                return Decision(kind, Verdict.KEEP, f"pid {owner.pid} alive")
            if kind is Kind.MSBUILD_DIRECTORY:
                if owner is None:
                    return Decision(kind, Verdict.KEEP, "MSBuild dir without PID")
                return Decision(kind, Verdict.REMOVE, "stale MSBuild dir")
            return Decision(kind, Verdict.REMOVE, "stale clr-debug-pipe")

        case Kind.MSBUILD_TEMP_DIRECTORY:
            if _recent(path, build_minutes, context):
                return Decision(
                    kind, Verdict.KEEP, f"MSBuildTemp active within {build_minutes}m"
                )
            return Decision(kind, Verdict.REMOVE, f"MSBuildTemp idle >{build_minutes}m")

        case Kind.NUGET_PROBE:
            if entry.info.st_size == 0 and entry.info.st_mtime_ns < _cutoff(
                context, build_minutes
            ):
                return Decision(kind, Verdict.REMOVE, "NuGet probe file")
            return None

        case Kind.EMPTY_SDK_DIRECTORY:
            minutes = context.settings.empty_directory_minutes
            if entry.info.st_mtime_ns < _cutoff(context, minutes) and context.empty_dir(
                path
            ):
                return Decision(kind, Verdict.REMOVE, "empty .NET temp dir")
            return None

        case Kind.SCRATCH:
            days = context.settings.scratch_days
            if _recent(path, days * 24 * 60, context):
                return Decision(kind, Verdict.KEEP, f"scratch touched within {days}d")
            if _held(path, context):
                return Decision(kind, Verdict.KEEP, "scratch held by a live process")
            return Decision(kind, Verdict.REMOVE, f"scratch idle >{days}d")
