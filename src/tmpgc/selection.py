"""Select entries by rule order and directory precedence."""

import os
import stat
from collections.abc import Iterator
from pathlib import PurePosixPath

from .config import Patterns, Rule, Search
from .entries import Entry, expand, walk
from .mounts import Mounts
from .paths import location, with_ancestors
from .rules import Context, matches


def _entries(select: Patterns | Search, mounts: Mounts) -> Iterator[Entry]:
    match select:
        case Patterns(globs):
            for pattern in globs:
                yield from expand(pattern)
        case Search(roots, depth):
            for root in dict.fromkeys(roots):
                entries = walk(root, depth, mounts)
                next(entries, None)
                yield from entries


def candidates(context: Context) -> Iterator[tuple[Entry, Rule]]:
    protected = with_ancestors(
        location(root)
        for rule in context.rules
        if isinstance(rule.select, Search)
        for root in rule.select.roots
    )
    claimed: set[PurePosixPath] = set()
    directories: set[PurePosixPath] = set()
    ancestors: set[PurePosixPath] = set()
    selected: list[tuple[Entry, Rule]] = []
    for rule in context.rules:
        found: list[tuple[PurePosixPath, Entry]] = []
        for entry in _entries(rule.select, context.mounts):
            path = entry.location
            if (
                path not in protected
                and path not in claimed
                and matches(entry, rule, context)
            ):
                claimed.add(path)
                found.append((path, entry))

        # Earlier rules take precedence. Within a rule, a parent is considered first.
        survivors: list[Entry] = []
        for path, entry in sorted(found, key=lambda item: len(item[0].parts)):
            if path in ancestors or not directories.isdisjoint(path.parents):
                continue
            ancestors.update(path.parents)
            if stat.S_ISDIR(entry.info.st_mode):
                directories.add(path)
            survivors.append(entry)
        selected.extend(
            (entry, rule)
            for entry in sorted(survivors, key=lambda entry: os.fsencode(entry.path))
        )
    yield from selected
