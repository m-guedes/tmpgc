"""Run the cleanup sections and report their results."""

import sys

from .entries import used_kib
from .removal import remove
from .rules import Context, Verdict, decide
from .selection import candidates


__all__ = ["run"]
_SIZE_UNITS = "KMGTPEZYRQ"


def _format_size(kib: int) -> str:
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


def run(context: Context, *, dry_run: bool, verbose: bool) -> int:
    removed = 0
    skipped = 0
    failed = 0
    freed_kib = 0

    for entry, kind in candidates(context):
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
            reason = f"{reason}, {_format_size(kib)}"
        if dry_run:
            print(f"WOULD REMOVE ({reason}): {path}")
        else:
            if verbose:
                print(f"REMOVING ({reason}): {path}")
            if not remove(entry):
                print(f"FAILED ({reason}): {path}", file=sys.stderr)
                failed += 1
                continue
        removed += 1
        freed_kib += kib

    freed = f"{_format_size(freed_kib)} from scratch trees, large entries and segments"
    held = ", ".join(
        f"{root} holds {_format_size(used_kib(root))}"
        for root in (context.settings.scan_root, context.settings.shared_memory_root)
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
