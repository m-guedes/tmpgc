"""Report cleanup decisions, failures and filesystem usage."""

import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field

from .removal import RemovalError
from .rules import Decision


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


def used_kib(root: str) -> int:
    # df's Used column. The Open Group, POSIX.1-2024 sys/statvfs.h (2024),
    # defines f_blocks and f_bfree in units of f_frsize.
    info = os.statvfs(root)
    return (info.f_blocks - info.f_bfree) * info.f_frsize // 1024


def _removal_reason(decision: Decision) -> str:
    if decision.freed_kib == 0:
        return decision.reason
    return f"{decision.reason}, {_format_size(decision.freed_kib)}"


@dataclass(slots=True, kw_only=True)
class Report:
    dry_run: bool
    verbose: bool
    _kept: int = field(default=0, init=False)
    _removed: int = field(default=0, init=False)
    _failed: int = field(default=0, init=False)
    _freed_kib: int = field(default=0, init=False)

    def kept(self, path: str, reason: str) -> None:
        self._kept += 1
        if self.verbose:
            print(f"SKIP ({reason}): {path}")

    def removing(self, path: str, decision: Decision) -> None:
        if self.dry_run or self.verbose:
            action = "WOULD REMOVE" if self.dry_run else "REMOVING"
            print(f"{action} ({_removal_reason(decision)}): {path}")

    def removed(self, decision: Decision) -> None:
        self._removed += 1
        self._freed_kib += decision.freed_kib

    def failed(self, path: str, decision: Decision, cause: RemovalError) -> None:
        self._failed += 1
        print(f"FAILED ({_removal_reason(decision)}): {path}: {cause}", file=sys.stderr)

    def summary(self, roots: Iterable[str]) -> None:
        size = _format_size(self._freed_kib)
        held = ", ".join(
            f"{root} holds {_format_size(used_kib(root))}" for root in roots
        )
        usage = f" {held}." if held else ""
        if self.dry_run:
            print(
                f"Dry run: {self._removed} items would be removed ({size} to free), "
                f"{self._kept} active items kept.{usage}"
            )
        else:
            print(
                f"Done: {self._removed} items removed ({size} freed), "
                f"{self._kept} active items kept, {self._failed} failed.{usage}"
            )

    def exit_status(self) -> int:
        return int(self._failed > 0)
