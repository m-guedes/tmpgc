"""Match configured rules and decide which entries to remove."""

import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum, auto

from .config import EntryType, Rule
from .entries import Entry, Tree
from .mounts import Mounts
from .processes import Processes


_ENTRY_MODES = {
    EntryType.SOCKET: stat.S_IFSOCK,
    EntryType.FIFO: stat.S_IFIFO,
    EntryType.DIRECTORY: stat.S_IFDIR,
    EntryType.FILE: stat.S_IFREG,
}


class Verdict(Enum):
    REMOVE = auto()
    KEEP = auto()


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    reason: str
    freed_kib: int = 0


@dataclass(frozen=True, slots=True)
class Context:
    rules: tuple[Rule, ...]
    processes: Processes
    now_ns: int
    uid: int
    tree: Callable[[str], Tree | None]
    empty_dir: Callable[[str], bool]
    mounts: Mounts


def matches(entry: Entry, rule: Rule, context: Context) -> bool:
    if entry.info.st_uid != context.uid:
        return False
    mode = stat.S_IFMT(entry.info.st_mode)
    if rule.type is not None and mode != _ENTRY_MODES[rule.type]:
        return False
    if rule.name is not None and rule.name.fullmatch(entry.name) is None:
        return False
    if rule.empty:
        if mode == stat.S_IFDIR:
            if not context.empty_dir(entry.path):
                return False
        elif mode != stat.S_IFREG or entry.info.st_size != 0:
            return False
    if rule.min_size == 0:
        return True
    tree = context.tree(entry.path)
    return tree is not None and tree.allocated_bytes >= rule.min_size


def _owner_reason(entry: Entry, rule: Rule, context: Context) -> str | None:
    if rule.name is None or "pid" not in rule.name.groupindex:
        return None
    match = rule.name.fullmatch(entry.name)
    if match is None or (pid_text := match["pid"]) is None:
        return None
    if not pid_text.isascii() or not pid_text.isdecimal():
        return "owner not a PID"
    pid = int(pid_text)
    start = match.groupdict().get("start")
    if start is None:
        live = context.processes.started_no_later_than(
            pid, context.uid, entry.info.st_mtime_ns
        )
    else:
        if not start.isascii() or not start.isdecimal():
            return "owner start not decimal"
        live = context.processes.started_at(pid, int(start))
    return f"pid {pid} alive" if live else None


def _nanoseconds(span: timedelta) -> int:
    return (span // timedelta(microseconds=1)) * 1000


def _span(threshold: timedelta) -> str:
    for unit, suffix in (
        (timedelta(days=1), "d"),
        (timedelta(hours=1), "h"),
        (timedelta(minutes=1), "min"),
    ):
        if not threshold % unit:
            return f"{threshold // unit}{suffix}"
    return f"{threshold // timedelta(seconds=1)}s"


def decide(entry: Entry, rule: Rule, context: Context) -> Decision | None:
    label = rule.label
    # Removing an entry at or above a mount point would empty the mounted tree.
    if context.mounts.at_or_above(entry.location):
        return Decision(Verdict.KEEP, f"{label} at or above a mount point")
    if (
        stat.S_ISSOCK(entry.info.st_mode)
        and entry.path in context.processes.bound_sockets
    ):
        return Decision(Verdict.KEEP, f"{label} bound")
    if (reason := _owner_reason(entry, rule, context)) is not None:
        return Decision(Verdict.KEEP, f"{label} {reason}")
    tree = context.tree(entry.path)
    if tree is None:
        return None
    idle_ns = context.now_ns - tree.last_activity_ns
    if idle_ns <= _nanoseconds(rule.idle):
        return Decision(Verdict.KEEP, f"{label} touched within {_span(rule.idle)}")
    if tree.in_use and (
        rule.held_idle is None or idle_ns <= _nanoseconds(rule.held_idle)
    ):
        return Decision(Verdict.KEEP, f"{label} held by a live process")
    reason = f"{label} idle >{_span(rule.idle)}" if rule.idle else f"stale {label}"
    # An unlinked file keeps its allocation while it is held
    # (Linux man-pages, unlink(2), 2026).
    return Decision(Verdict.REMOVE, reason, tree.allocated_kib - tree.held_kib)
