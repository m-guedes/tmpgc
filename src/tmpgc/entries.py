"""Scan physical filesystem entries and measure their attributes."""

import errno
import os
import stat
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from fnmatch import fnmatchcase


_SCAN_ERRORS = (FileNotFoundError, NotADirectoryError, PermissionError)
_DIRECTORY_FLAGS = os.O_DIRECTORY | os.O_NOFOLLOW


@dataclass(frozen=True, slots=True)
class Entry:
    path: str
    info: os.stat_result

    @property
    def name(self) -> str:
        return os.path.basename(self.path.rstrip("/"))


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


def walk(root: str, depth: int | None = None) -> Iterator[Entry]:
    try:
        with parent_directory(root) as (parent_fd, name):
            entry = Entry(root, os.lstat(name, dir_fd=parent_fd))
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
                    if (depth is None or len(stack) < depth) and stat.S_ISDIR(
                        entry.info.st_mode
                    ):
                        stack.append(_children(entry, fd))
            finally:
                for scan in reversed(stack):
                    scan.close()
    except _SCAN_ERRORS:
        return


def _matches(directory: str, component: str) -> Iterator[Entry]:
    if not any(character in component for character in "*?["):
        yield from walk(os.path.join(directory, component), 0)
        return

    entries = walk(directory, 1)
    next(entries, None)
    for entry in entries:
        if entry.name.startswith(".") and not component.startswith("."):
            continue
        if fnmatchcase(entry.name, component):
            yield entry


def _owned_match(entry: Entry, uid: int) -> bool:
    if entry.info.st_uid != uid:
        return False
    if not stat.S_ISLNK(entry.info.st_mode):
        return True
    # Bash -O tests the target of a link. Age, allocation and removal use the link itself.
    try:
        with parent_directory(entry.path) as (fd, name):
            return os.stat(name, dir_fd=fd).st_uid == uid
    except _SCAN_ERRORS:
        return False
    except OSError as error:
        if error.errno == errno.ELOOP:
            return False
        raise


def expand(pattern: str, uid: int) -> Iterator[Entry]:
    entries = list(walk("/", 0))
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
        if _owned_match(entry, uid):
            yield entry


def newest_change(path: str) -> int | None:
    return max(
        (max(entry.info.st_mtime_ns, entry.info.st_ctime_ns) for entry in walk(path)),
        default=None,
    )


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


def allocated_kib(path: str) -> int:
    blocks = 0
    linked: set[tuple[int, int]] = set()
    for entry in walk(path):
        info = entry.info
        if info.st_nlink > 1 and not stat.S_ISDIR(info.st_mode):
            identity = (info.st_dev, info.st_ino)
            if identity in linked:
                continue
            linked.add(identity)
        blocks += info.st_blocks
    # Linux st_blocks counts 512-byte blocks. du -sk rounds the tree's sum to KiB.
    return (blocks + 1) // 2
