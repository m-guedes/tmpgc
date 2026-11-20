"""Exercise physical removal."""

from tmpgc.entries import walk
from tmpgc.removal import remove

from .filesystem_test_case import TreeTestCase


class RemovalTests(TreeTestCase):
    def test_keeps_contents_of_dot_entries(self) -> None:
        (self.root / "child").mkdir()
        for suffix in (".", "child/.."):
            with self.subTest(suffix=suffix):
                entry = next(walk(f"{self.root}/{suffix}", 0))
                self.assertFalse(remove(entry))
                self.assertTrue(self.file.is_file())
