"""Select candidate entries in section order."""

import os
import stat
from collections.abc import Iterable, Iterator
from pathlib import PurePosixPath

from .entries import Entry, children, expand, walk
from .paths import location, with_ancestors
from .rules import Context, Kind, Origin, classify


def _section_sort_rank(kind: Kind) -> int:
    match kind:
        case Kind.SOCKET:
            return 0
        case Kind.DEBUGGER_PIPE:
            return 1
        case Kind.MSBUILD_DIRECTORY | Kind.MSBUILD_TEMP_DIRECTORY:
            return 2
        case Kind.NUGET_PROBE:
            return 3
        case Kind.EMPTY_SDK_DIRECTORY:
            return 4
        case Kind.SCRATCH:
            return 5
        case Kind.LARGE:
            return 6
        case Kind.SEGMENT:
            return 7


def _classify_entries(
    entries: Iterable[Entry], origin: Origin, context: Context
) -> Iterator[tuple[Entry, Kind]]:
    for entry in entries:
        kind = classify(entry, origin, context)
        if kind is not None:
            yield entry, kind


def _top_level_entries(
    roots: Iterable[str], root_paths: set[PurePosixPath]
) -> Iterator[Entry]:
    # Nested roots are scan locations. Use original spellings for physical traversal.
    seen = root_paths.copy()
    for root in dict.fromkeys(roots):
        for entry in children(root):
            path = entry.location
            if path not in seen:
                seen.add(path)
                yield entry


def _scratch_entries(patterns: Iterable[str]) -> Iterator[Entry]:
    seen: set[PurePosixPath] = set()
    for pattern in patterns:
        for entry in expand(pattern):
            path = entry.location
            if path not in seen:
                seen.add(path)
                yield entry


def candidates(context: Context) -> Iterator[tuple[Entry, Kind]]:
    settings = context.settings
    root_paths = {location(root) for root in settings.temporary_roots}
    found = [
        *_classify_entries(
            walk(settings.scan_root, settings.depth, context.mounts),
            Origin.PRIMARY_SCAN,
            context,
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
            _top_level_entries((settings.shared_memory_root,), root_paths),
            Origin.SHARED_MEMORY,
            context,
        ),
    ]
    # Removing a directory removes its contents, so the outermost selected directory governs them.
    # Large entries yield to configured roots and specific candidates at or below them.
    directories = {
        entry.location
        for entry, kind in found
        if kind is not Kind.LARGE and stat.S_ISDIR(entry.info.st_mode)
    }
    protected = with_ancestors(
        root_paths.union(
            entry.location for entry, kind in found if kind is not Kind.LARGE
        )
    )
    yield from sorted(
        (
            (entry, kind)
            for entry, kind in found
            if directories.isdisjoint(entry.location.parents)
            and (kind is not Kind.LARGE or entry.location not in protected)
        ),
        key=lambda candidate: (
            _section_sort_rank(candidate[1]),
            os.fsencode(candidate[0].path),
        ),
    )
