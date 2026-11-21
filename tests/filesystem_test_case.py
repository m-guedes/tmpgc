"""Provide real and synthetic filesystem entries for tests."""

import os
import re
import stat
import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from tmpgc.config import EntryType, Patterns, Rule, Search
from tmpgc.entries import Entry


_TOP_LEVEL = Search(("/tmp",), 1)


class FilesystemTestCase(unittest.TestCase):
    def rule(
        self,
        label: str,
        *,
        select: Patterns | Search = _TOP_LEVEL,
        idle: timedelta = timedelta(),
        entry_type: EntryType | None = None,
        name: str | None = None,
        empty: bool = False,
        min_size: int = 0,
    ) -> Rule:
        return Rule(
            label,
            select,
            idle,
            entry_type,
            re.compile(name) if name is not None else None,
            empty,
            min_size,
        )


class TreeTestCase(FilesystemTestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.file = self.root / "file"
        self.file.write_bytes(b"contents")


class SyntheticEntryTestCase(FilesystemTestCase):
    uid = 1000

    def entry(self, path: str, mode: int = stat.S_IFDIR, *, mtime_ns: int = 0) -> Entry:
        info = os.stat_result(
            (mode, 0, 0, 1, self.uid, 0, 0, 0, 0, 0), {"st_mtime_ns": mtime_ns}
        )
        return Entry(path, info)
