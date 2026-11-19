"""Observe liveness through Linux procfs."""

import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

from .config import SCAN_ROOT


_PROCESS_ERRORS = (FileNotFoundError, PermissionError, ProcessLookupError)


@dataclass(frozen=True, slots=True)
class Process:
    start_ticks: int


@dataclass(frozen=True, slots=True)
class Processes:
    holders: Mapping[int, tuple[Process, ...]]
    bound_sockets: frozenset[str]
    held_paths: frozenset[str]

    def started_at(self, pid: int, start_ticks: int) -> bool:
        return any(
            holder.start_ticks == start_ticks for holder in self.holders.get(pid, ())
        )


def _process_holders(process: Path) -> Iterator[tuple[int, Process]]:
    def open_file(name: str, flags: int) -> int:
        return os.open(name, flags, dir_fd=fd)

    try:
        # A directory descriptor keeps both reads on the same process across PID
        # reuse (Linux kernel documentation, The /proc Filesystem, 2009).
        fd = os.open(process, os.O_PATH | os.O_DIRECTORY)
        try:
            with open("status", "rb", opener=open_file) as status:
                pids = next(
                    (line.split()[1:] for line in status if line.startswith(b"NSpid:")),
                    (),
                )
            with open("stat", "rb", opener=open_file) as stat:
                stat_data = stat.read()
        finally:
            os.close(fd)
    except _PROCESS_ERRORS:
        return

    # The command name may contain spaces and parentheses. Field 22 follows the
    # last closing parenthesis at index 19 (Linux man-pages, proc_pid_stat(5), 2026).
    fields = stat_data.rsplit(b")", 1)[1].split()
    holder = Process(int(fields[19]))
    for pid in set(map(int, pids)):
        yield pid, holder


def _bound_sockets(process: Path, namespaces: set[str]) -> Iterator[str]:
    try:
        namespace = os.readlink(process / "ns/net")
        if namespace in namespaces:
            return
        # The table is relative to the process's network namespace (Linux man-pages,
        # proc_pid_net(5), 2025). Retry with another member if the first vanishes.
        table = (process / "net/unix").read_bytes()
    except _PROCESS_ERRORS:
        return

    namespaces.add(namespace)
    for line in table.split(b"\n"):
        fields = line.split(maxsplit=7)
        if len(fields) == 8 and fields[7].startswith(b"/"):
            yield os.fsdecode(fields[7])


def _temporary_target(link: str | Path) -> Iterator[str]:
    try:
        target = os.readlink(link)
    except _PROCESS_ERRORS:
        return
    if target.startswith(f"{SCAN_ROOT}/"):
        yield target


def _held_paths(process: Path) -> Iterator[str]:
    yield from _temporary_target(process / "cwd")
    try:
        with os.scandir(process / "fd") as descriptors:
            for descriptor in descriptors:
                yield from _temporary_target(descriptor.path)
    except _PROCESS_ERRORS:
        return


def observe() -> Processes:
    holders: dict[int, list[Process]] = {}
    sockets: set[str] = set()
    paths: set[str] = set()
    namespaces: set[str] = set()
    for process in Path("/proc").iterdir():
        if process.name.isdecimal():
            for pid, holder in _process_holders(process):
                holders.setdefault(pid, []).append(holder)
            sockets.update(_bound_sockets(process, namespaces))
            paths.update(_held_paths(process))
    return Processes(
        {pid: tuple(processes) for pid, processes in holders.items()},
        frozenset(sockets),
        frozenset(paths),
    )
