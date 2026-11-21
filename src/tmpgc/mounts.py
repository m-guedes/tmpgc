"""Read mount points from procfs."""

import os
import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from .paths import location, with_ancestors


_MOUNT_ESCAPE = re.compile(rb"\\([0-7]{3})")


class Mounts:
    __slots__ = ("_enclosing", "_points")

    def __init__(self, points: Iterable[PurePosixPath]) -> None:
        self._points = frozenset(points)
        self._enclosing = with_ancestors(self._points)

    def is_mount(self, path: PurePosixPath) -> bool:
        return path in self._points

    def at_or_above(self, path: PurePosixPath) -> bool:
        return path in self._enclosing

    def containing(self, path: PurePosixPath) -> PurePosixPath | None:
        return next(
            (point for point in (path, *path.parents) if self.is_mount(point)), None
        )


def read() -> Mounts:
    points: set[PurePosixPath] = set()
    with open("/proc/self/mountinfo", "rb") as mounts:
        for record in mounts:
            # Field 5 is the mount path (Linux man-pages, proc_pid_mountinfo(5), 2026).
            target = record.split(b" ", 5)[4]
            decoded = _MOUNT_ESCAPE.sub(
                lambda escape: int(escape[1], 8).to_bytes(1), target
            )
            points.add(location(os.fsdecode(decoded)))
    return Mounts(points)
