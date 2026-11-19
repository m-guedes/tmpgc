"""Run the cleanup sections and report their results."""

import os
import shutil
import stat
import sys
from collections.abc import Iterable, Iterator
from pathlib import PurePosixPath

from .config import SCAN_ROOT
from .entries import Entry, allocated_kib, expand, parent_directory, walk
from .rules import Context, Kind, Origin, Verdict, classify, decide


_SECTION = {
    Kind.SOCKET: 0,
    Kind.DEBUGGER_PIPE: 1,
    Kind.MSBUILD_DIRECTORY: 2,
    Kind.MSBUILD_TEMP_DIRECTORY: 2,
    Kind.NUGET_PROBE: 3,
    Kind.EMPTY_SDK_DIRECTORY: 4,
    Kind.SCRATCH: 5,
}
_MSBUILD_KINDS = {Kind.MSBUILD_DIRECTORY, Kind.MSBUILD_TEMP_DIRECTORY}
_SIZE_UNITS = "KMGTPEZYRQ"


def _ordered(
    entries: Iterable[Entry], origin: Origin, uid: int
) -> list[tuple[Entry, Kind]]:
    selected: list[tuple[Entry, Kind]] = []
    msbuild_roots: set[PurePosixPath] = set()
    for entry in entries:
        kind = classify(entry, origin, uid)
        if kind is None:
            continue
        if kind in _MSBUILD_KINDS:
            # Bash prunes MSBuild trees in this section alone.
            path = PurePosixPath(entry.path)
            if not msbuild_roots.isdisjoint(path.parents):
                continue
            msbuild_roots.add(path)
        selected.append((entry, kind))
    return sorted(
        selected,
        key=lambda candidate: (_SECTION[candidate[1]], os.fsencode(candidate[0].path)),
    )


def _temporary_entries(roots: Iterable[str]) -> Iterator[Entry]:
    for root in roots:
        entries = walk(root, 1)
        next(entries, None)
        yield from entries


def _scratch_entries(patterns: Iterable[str], uid: int) -> Iterator[Entry]:
    seen: set[str] = set()
    for pattern in patterns:
        for entry in expand(pattern, uid):
            if entry.path not in seen:
                seen.add(entry.path)
                yield entry


def _candidates(context: Context) -> Iterator[tuple[Entry, Kind]]:
    settings = context.settings
    uid = context.uid
    yield from _ordered(walk(SCAN_ROOT, settings.depth), Origin.PRIMARY_SCAN, uid)
    yield from _ordered(
        _temporary_entries(settings.temporary_roots), Origin.TEMPORARY_ROOT, uid
    )
    yield from _ordered(
        _scratch_entries(settings.scratch_patterns, uid), Origin.SCRATCH_PATTERN, uid
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
        if decision.kind is Kind.SCRATCH:
            kib = allocated_kib(path)
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

    freed = f"{format_size(freed_kib)} from scratch trees"
    if dry_run:
        print(
            f"Dry run: {removed} items would be removed ({freed}), {skipped} active items kept."
        )
    else:
        print(
            f"Done: {removed} items removed ({freed}), {skipped} active items kept, {failed} failed."
        )
    return int(failed > 0)
