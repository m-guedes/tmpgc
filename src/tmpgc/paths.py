"""Identify entries by their lexical absolute path."""

import os
from collections.abc import Iterable
from pathlib import PurePosixPath


def location(path: str) -> PurePosixPath:
    # Traversal opens each directory with O_NOFOLLOW, so lexical normalization
    # preserves the location of any entry reached. Linux treats leading // as /.
    return PurePosixPath(os.path.normpath("/" + path.lstrip("/")))


def with_ancestors(paths: Iterable[PurePosixPath]) -> frozenset[PurePosixPath]:
    return frozenset(parent for path in paths for parent in (path, *path.parents))
