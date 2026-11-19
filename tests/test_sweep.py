"""Exercise removal against a scratch directory."""

import tempfile
import unittest
from pathlib import Path

from tmpgc.entries import walk
from tmpgc.sweep import _remove


class RemovalTests(unittest.TestCase):
    def test_keeps_contents_of_dot_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "child").mkdir()
            sentinel = root / "sentinel"
            sentinel.touch()
            for suffix in (".", "child/.."):
                with self.subTest(suffix=suffix):
                    entry = next(walk(f"{directory}/{suffix}", 0))
                    self.assertFalse(_remove(entry))
                    self.assertTrue(sentinel.is_file())
