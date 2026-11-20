"""Scan physical filesystem entries and measure their attributes."""

import os
import stat
from collections.abc import Generator, Iterator
from collections.abc import Set as AbstractSet
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

from .mounts import Mounts
from .paths import location


_SCAN_ERRORS = (FileNotFoundError, NotADirectoryError, PermissionError)
_DIRECTORY_FLAGS = os.O_DIRECTORY | os.O_NOFOLLOW


type FileId = tuple[int, int]


@dataclass(frozen=True, slots=True)
class Entry:
    path: str
    info: os.stat_result

    @property
    def name(self) -> str:
        return os.path.basename(self.path.rstrip("/"))

    @property
    def location(self) -> PurePosixPath:
        return location(self.path)


@dataclass(frozen=True, slots=True)
class Tree:
    allocated_kib: int
    last_activity_ns: int
    in_use: bool


def file_id(info: os.stat_result) -> FileId:
    return info.st_dev, info.st_ino


@contextmanager
def parent_directory(path: str) -> Generator[tuple[int, str]]:
    parent, name = os.path.split(path.rstrip("/") or "/")
    fd = os.open("/", os.O_PATH | _DIRECTORY_FLAGS)
    try:
        # Resolve each component relative to a directory descriptor. O_NOFOLLOW
        # applies only to the last component (Linux man-pages, open(2), 2025).
        for part in parent.split("/"):
            if part:
                child_fd = os.open(part, os.O_PATH | _DIRECTORY_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child_fd
        yield fd, name or "."
    finally:
        os.close(fd)


@contextmanager
def _read_directory(name: str, parent_fd: int) -> Generator[int]:
    fd = os.open(name, os.O_RDONLY | _DIRECTORY_FLAGS, dir_fd=parent_fd)
    try:
        yield fd
    finally:
        os.close(fd)


def _children(directory: Entry, parent_fd: int) -> Generator[tuple[Entry, int]]:
    try:
        with (
            _read_directory(directory.name or ".", parent_fd) as fd,
            os.scandir(fd) as scan,
        ):
            if not os.path.samestat(directory.info, os.fstat(fd)):
                return
            for child in scan:
                try:
                    info = child.stat(follow_symlinks=False)
                except _SCAN_ERRORS:
                    continue
                yield Entry(os.path.join(directory.path, child.name), info), fd
    except _SCAN_ERRORS:
        return


@contextmanager
def _opened(path: str) -> Generator[tuple[Entry, int]]:
    with parent_directory(path) as (parent_fd, name):
        yield Entry(path, os.lstat(name, dir_fd=parent_fd)), parent_fd


def entry_at(path: str) -> Entry | None:
    try:
        with _opened(path) as (entry, _):
            return entry
    except _SCAN_ERRORS:
        return None


def children(directory: str) -> Iterator[Entry]:
    with suppress(*_SCAN_ERRORS), _opened(directory) as (entry, parent_fd):
        if stat.S_ISDIR(entry.info.st_mode):
            for child, _ in _children(entry, parent_fd):
                yield child


def walk(root: str, depth: int | None, mounts: Mounts) -> Iterator[Entry]:
    with suppress(*_SCAN_ERRORS), _opened(root) as (entry, parent_fd):
        yield entry
        if depth == 0 or not stat.S_ISDIR(entry.info.st_mode):
            return

        stack = [_children(entry, parent_fd)]
        try:
            while stack:
                child = next(stack[-1], None)
                if child is None:
                    stack.pop()
                    continue
                entry, fd = child
                yield entry
                # dir_cleanup skips child mounts, even when the scan root is a
                # mount itself (systemd project, tmpfiles.c, 2026).
                if (
                    (depth is None or len(stack) < depth)
                    and stat.S_ISDIR(entry.info.st_mode)
                    and not mounts.is_mount(entry.location)
                ):
                    stack.append(_children(entry, fd))
        finally:
            for scan in reversed(stack):
                scan.close()


def _matches(directory: str, component: str) -> Iterator[Entry]:
    if not any(character in component for character in "*?["):
        if (entry := entry_at(os.path.join(directory, component))) is not None:
            yield entry
        return

    for entry in children(directory):
        if entry.name.startswith(".") and not component.startswith("."):
            continue
        if fnmatchcase(entry.name, component):
            yield entry


def expand(pattern: str) -> Iterator[Entry]:
    root = entry_at("/")
    if root is None:
        return
    entries = [root]
    for component in pattern.split("/"):
        if component:
            entries = [
                match
                for directory in entries
                if stat.S_ISDIR(directory.info.st_mode)
                for match in _matches(directory.path, component)
            ]
    for entry in entries:
        if pattern.endswith("/") and not stat.S_ISDIR(entry.info.st_mode):
            continue
        yield entry


def empty_dir(path: str) -> bool:
    try:
        with (
            parent_directory(path) as (parent_fd, name),
            _read_directory(name, parent_fd) as fd,
            os.scandir(fd) as scan,
        ):
            return next(scan, None) is None
    except _SCAN_ERRORS:
        return False


def used_kib(root: str) -> int:
    # df's Used column. The Open Group, POSIX.1-2024 sys/statvfs.h (2024),
    # defines f_blocks and f_bfree in units of f_frsize.
    info = os.statvfs(root)
    return (info.f_blocks - info.f_bfree) * info.f_frsize // 1024


def measure(path: str, held: AbstractSet[FileId], mounts: Mounts) -> Tree | None:
    blocks = 0
    last_activity_ns: int | None = None
    in_use = False
    linked: set[FileId] = set()
    for entry in walk(path, None, mounts):
        # A child mount's own stat data also belongs to the mounted filesystem.
        if entry.path != path and mounts.is_mount(entry.location):
            continue
        info = entry.info
        identity = file_id(info)
        directory = stat.S_ISDIR(info.st_mode)
        in_use = in_use or identity in held
        activity_ns = max(info.st_mtime_ns, info.st_ctime_ns)
        # Directory listings advance atime, including listings by this scan.
        if not directory:
            activity_ns = max(activity_ns, info.st_atime_ns)
        last_activity_ns = (
            activity_ns
            if last_activity_ns is None
            else max(last_activity_ns, activity_ns)
        )
        if info.st_nlink > 1 and not directory:
            if identity in linked:
                continue
            linked.add(identity)
        blocks += info.st_blocks
    if last_activity_ns is None:
        return None
    # Linux st_blocks counts 512-byte blocks. du -sk rounds the tree's sum to KiB.
    return Tree((blocks + 1) // 2, last_activity_ns, in_use)
