"""Run the cleanup sections and report their results."""

import os
import shutil
import stat
import sys
from collections.abc import Iterable, Iterator
from pathlib import PurePosixPath

from .config import SCAN_ROOT, SHARED_MEMORY_ROOT
from .entries import Entry, expand, normalize_path, parent_directory, used_kib, walk
from .rules import Context, Kind, Origin, Verdict, classify, decide


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
_SIZE_UNITS = "KMGTPEZYRQ"


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


def _candidates(context: Context) -> Iterator[tuple[Entry, Kind]]:
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


def format_size(kib: int) -> str:
    if kib == 0:
        return "0"
    scale = 1
    index = 0
    # numfmt rounds upward and promotes to the next unit if rounding reaches 1024.
    while (kib + scale - 1) // scale >= 1024 and index < len(_SIZE_UNITS) - 1:
        scale *= 1024
        index += 1
    unit = _SIZE_UNITS[index]
    tenths = (kib * 10 + scale - 1) // scale
    if tenths < 100:
        return f"{tenths // 10}.{tenths % 10}{unit}"
    return f"{(kib + scale - 1) // scale}{unit}"


def _remove(entry: Entry) -> bool:
    failed = False

    def record_error(_operation: object, _path: str, error: BaseException) -> None:
        nonlocal failed
        if not isinstance(error, OSError):
            raise error
        if not isinstance(error, FileNotFoundError):
            failed = True

    try:
        with parent_directory(entry.path) as (fd, name):
            # rm -rf refuses dot entries and the filesystem root.
            if name in {".", ".."}:
                return False
            current = os.lstat(name, dir_fd=fd)
            if not os.path.samestat(entry.info, current):
                return False
            if stat.S_ISDIR(current.st_mode):
                shutil.rmtree(name, dir_fd=fd, onexc=record_error)
            else:
                os.unlink(name, dir_fd=fd)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return not failed


def run(context: Context, *, dry_run: bool, verbose: bool) -> int:
    removed = 0
    skipped = 0
    failed = 0
    freed_kib = 0

    for entry, kind in _candidates(context):
        decision = decide(entry, kind, context)
        if decision is None:
            continue
        path = entry.path
        reason = decision.reason
        if decision.verdict is Verdict.KEEP:
            if verbose:
                print(f"SKIP ({reason}): {path}")
            skipped += 1
            continue

        kib = 0
        if decision.allocated_kib is not None:
            kib = decision.allocated_kib
            reason = f"{reason}, {format_size(kib)}"
        if dry_run:
            print(f"WOULD REMOVE ({reason}): {path}")
        else:
            if verbose:
                print(f"REMOVING ({reason}): {path}")
            if not _remove(entry):
                print(f"FAILED ({reason}): {path}", file=sys.stderr)
                failed += 1
                continue
        removed += 1
        freed_kib += kib

    freed = f"{format_size(freed_kib)} from scratch trees, large entries and segments"
    held = ", ".join(
        f"{root} holds {format_size(used_kib(root))}"
        for root in (SCAN_ROOT, SHARED_MEMORY_ROOT)
    )
    if dry_run:
        print(
            f"Dry run: {removed} items would be removed ({freed}), {skipped} active items kept. {held}."
        )
    else:
        print(
            f"Done: {removed} items removed ({freed}), {skipped} active items kept, {failed} failed. {held}."
        )
    return int(failed > 0)
