"""Observe liveness through Linux procfs."""

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .config import SCAN_ROOT


_PROCESS_ERRORS = (FileNotFoundError, PermissionError, ProcessLookupError)


@dataclass(frozen=True, slots=True)
class Processes:
    live_pids: frozenset[int]
    bound_sockets: frozenset[str]
    held_paths: frozenset[str]


def _namespace_pids(process: Path) -> Iterator[int]:
    try:
        with (process / "status").open("rb") as status:
            for line in status:
                if line.startswith(b"NSpid:"):
                    yield from map(int, line.split()[1:])
                    return
    except _PROCESS_ERRORS:
        return


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
    pids: set[int] = set()
    sockets: set[str] = set()
    paths: set[str] = set()
    namespaces: set[str] = set()
    for process in Path("/proc").iterdir():
        if process.name.isdecimal():
            pids.update(_namespace_pids(process))
            sockets.update(_bound_sockets(process, namespaces))
            paths.update(_held_paths(process))
    return Processes(frozenset(pids), frozenset(sockets), frozenset(paths))
