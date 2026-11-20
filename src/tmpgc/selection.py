"""Select candidate entries in section order."""

import os
from collections.abc import Iterable, Iterator
from pathlib import PurePosixPath

from .config import SCAN_ROOT, SHARED_MEMORY_ROOT
from .entries import Entry, expand, normalize_path, walk
from .rules import Context, Kind, Origin, classify


_SECTION = {
    Kind.SOCKET: 0,
    Kind.DEBUGGER_PIPE: 1,
    Kind.MSBUILD_DIRECTORY: 2,
    Kind.MSBUILD_TEMP_DIRECTORY: 2,
    Kind.NUGET_PROBE: 3,
    Kind.EMPTY_SDK_DIRECTORY: 4,
    Kind.SCRATCH: 5,
    Kind.LARGE: 6,
    Kind.SEGMENT: 7,
}
_MSBUILD_KINDS = {Kind.MSBUILD_DIRECTORY, Kind.MSBUILD_TEMP_DIRECTORY}


def _classify_entries(
    entries: Iterable[Entry], origin: Origin, context: Context
) -> Iterator[tuple[Entry, Kind]]:
    msbuild_roots: set[PurePosixPath] = set()
    for entry in entries:
        kind = classify(entry, origin, context)
        if kind is None:
            continue
        if kind in _MSBUILD_KINDS:
            # Bash prunes MSBuild trees in this section alone.
            path = PurePosixPath(entry.path)
            if not msbuild_roots.isdisjoint(path.parents):
                continue
            msbuild_roots.add(path)
        yield entry, kind


def _top_level_entries(roots: Iterable[str], root_paths: set[str]) -> Iterator[Entry]:
    # Nested roots are scan locations. Use original spellings for physical traversal.
    seen = root_paths.copy()
    for root in dict.fromkeys(roots):
        entries = walk(root, 1)
        next(entries, None)
        for entry in entries:
            path = normalize_path(entry.path)
            if path not in seen:
                seen.add(path)
                yield entry


def _scratch_entries(patterns: Iterable[str]) -> Iterator[Entry]:
    seen: set[str] = set()
    for pattern in patterns:
        for entry in expand(pattern):
            if entry.path not in seen:
                seen.add(entry.path)
                yield entry


def candidates(context: Context) -> Iterator[tuple[Entry, Kind]]:
    settings = context.settings
    root_paths = {normalize_path(root) for root in settings.temporary_roots}
    candidates = [
        *_classify_entries(
            walk(SCAN_ROOT, settings.depth), Origin.PRIMARY_SCAN, context
        ),
        *_classify_entries(
            _top_level_entries(settings.temporary_roots, root_paths),
            Origin.TEMPORARY_ROOT,
            context,
        ),
        *_classify_entries(
            _scratch_entries(settings.scratch_patterns), Origin.SCRATCH_PATTERN, context
        ),
        *_classify_entries(
            _top_level_entries((SHARED_MEMORY_ROOT,), root_paths),
            Origin.SHARED_MEMORY,
            context,
        ),
    ]
    protected = {PurePosixPath(root) for root in root_paths}
    protected.update(
        PurePosixPath(normalize_path(entry.path))
        for entry, kind in candidates
        if kind is not Kind.LARGE
    )
    protected |= {parent for path in protected for parent in path.parents}
    yield from sorted(
        (
            (entry, kind)
            for entry, kind in candidates
            if kind is not Kind.LARGE
            or PurePosixPath(normalize_path(entry.path)) not in protected
        ),
        key=lambda candidate: (_SECTION[candidate[1]], os.fsencode(candidate[0].path)),
    )
