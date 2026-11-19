"""Provide an isolated filesystem tree for observation tests."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


class TreeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.file = self.root / "file"
        self.file.write_bytes(b"contents")
