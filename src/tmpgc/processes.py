"""Observe liveness through Linux procfs."""

import errno
import os
from collections.abc import Iterator, Mapping
from collections.abc import Set as AbstractSet
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .entries import FileId, file_id


_PROCESS_ERRORS = (FileNotFoundError, PermissionError, ProcessLookupError)
_SECOND_NS = 10**9


@dataclass(frozen=True, slots=True)
class Process:
    start_ticks: int
    uid: int


@dataclass(frozen=True, slots=True)
class Processes:
    holders: Mapping[int, tuple[Process, ...]]
    bound_sockets: frozenset[str]
    held: frozenset[FileId]
    boot_ns: int
    ticks_per_second: int

    def started_at(self, pid: int, start_ticks: int) -> bool:
        return any(
            holder.start_ticks == start_ticks for holder in self.holders.get(pid, ())
        )

    def started_no_later_than(self, pid: int, uid: int, instant_ns: int) -> bool:
        return any(
            holder.uid == uid and self._start_ns(holder.start_ticks) <= instant_ns
            for holder in self.holders.get(pid, ())
        )

    def _start_ns(self, start_ticks: int) -> int:
        return self.boot_ns + start_ticks * _SECOND_NS // self.ticks_per_second


def _process_holders(process: Path) -> Iterator[tuple[int, Process]]:
    def open_file(name: str, flags: int) -> int:
        return os.open(name, flags, dir_fd=fd)

    try:
        # A directory descriptor keeps both reads on the same process across PID
        # reuse (Linux kernel documentation, The /proc Filesystem, 2009).
        fd = os.open(process, os.O_PATH | os.O_DIRECTORY)
        try:
            with open("status", "rb", opener=open_file) as status:
                ids: dict[bytes, list[bytes]] = {}
                for line in status:
                    if line.startswith((b"Uid:", b"NSpid:")):
                        field, *values = line.split()
                        ids[field] = values
            with open("stat", "rb", opener=open_file) as stat:
                stat_data = stat.read()
        finally:
            os.close(fd)
    except _PROCESS_ERRORS:
        return

    # The command name may contain spaces and parentheses. Field 22 follows the
    # last closing parenthesis at index 19 (Linux man-pages, proc_pid_stat(5), 2026).
    fields = stat_data.rsplit(b")", 1)[1].split()
    # The real UID comes first (Linux man-pages, proc_pid_status(5), 2026).
    holder = Process(int(fields[19]), int(ids[b"Uid:"][0]))
    for pid in set(map(int, ids.get(b"NSpid:", ()))):
        yield pid, holder


def _bound_sockets(
    process: Path, namespaces: AbstractSet[str]
) -> tuple[str, set[str]] | None:
    try:
        namespace = os.readlink(process / "ns/net")
        if namespace in namespaces:
            return None
        # The table is relative to the process's network namespace (Linux man-pages,
        # proc_pid_net(5), 2025). Retry with another member if the first vanishes.
        table = (process / "net/unix").read_bytes()
    except _PROCESS_ERRORS:
        return None

    paths: set[str] = set()
    for line in table.split(b"\n"):
        fields = line.split(maxsplit=7)
        if len(fields) == 8 and fields[7].startswith(b"/"):
            paths.add(os.fsdecode(fields[7]))
    return namespace, paths


def _link_id(link: str | Path) -> FileId | None:
    try:
        return file_id(os.stat(link))
    except _PROCESS_ERRORS:
        return None
    except OSError as error:
        if error.errno == errno.ESTALE:
            return None
        raise


def _held(process: Path) -> Iterator[FileId]:
    if (identity := _link_id(process / "cwd")) is not None:
        yield identity
    with suppress(*_PROCESS_ERRORS), os.scandir(process / "fd") as descriptors:
        for descriptor in descriptors:
            if (identity := _link_id(descriptor.path)) is not None:
                yield identity

    try:
        with (process / "maps").open("rb") as maps:
            for line in maps:
                fields = line.split(maxsplit=5)
                if inode := int(fields[4]):
                    # The device is printed in hex (Linux man-pages, proc_pid_maps(5), 2026).
                    major, minor = fields[3].split(b":")
                    yield os.makedev(int(major, 16), int(minor, 16)), inode
    except _PROCESS_ERRORS:
        return


def _boot_ns() -> int:
    # btime is seconds since the Epoch (Linux man-pages, proc_stat(5), 2026).
    with Path("/proc/stat").open("rb") as stat:
        for line in stat:
            if line.startswith(b"btime "):
                return int(line.split()[1]) * _SECOND_NS
    raise ValueError("/proc/stat is missing btime")


def observe() -> Processes:
    holders: dict[int, list[Process]] = {}
    sockets: set[str] = set()
    held: set[FileId] = set()
    namespaces: set[str] = set()
    for process in Path("/proc").iterdir():
        if process.name.isdecimal():
            for pid, holder in _process_holders(process):
                holders.setdefault(pid, []).append(holder)
            if (bound := _bound_sockets(process, namespaces)) is not None:
                namespace, paths = bound
                namespaces.add(namespace)
                sockets.update(paths)
            held.update(_held(process))
    return Processes(
        {pid: tuple(processes) for pid, processes in holders.items()},
        frozenset(sockets),
        frozenset(held),
        boot_ns=_boot_ns(),
        ticks_per_second=os.sysconf("SC_CLK_TCK"),
    )
