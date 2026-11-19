"""Provide real and synthetic filesystem entries for tests."""

import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tmpgc.entries import Entry


class TreeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.file = self.root / "file"
        self.file.write_bytes(b"contents")


class SyntheticEntryTestCase(unittest.TestCase):
    uid = 1000

    def entry(self, path: str, mode: int = stat.S_IFDIR, *, mtime_ns: int = 0) -> Entry:
        info = os.stat_result(
            (mode, 0, 0, 1, self.uid, 0, 0, 0, 0, 0), {"st_mtime_ns": mtime_ns}
        )
        return Entry(path, info)
