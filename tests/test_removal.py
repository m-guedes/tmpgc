"""Exercise physical removal."""

from tmpgc.entries import entry_at
from tmpgc.removal import RemovalError, remove

from .filesystem_test_case import TreeTestCase


class RemovalTests(TreeTestCase):
    def test_keeps_contents_of_dot_entries(self) -> None:
        (self.root / "child").mkdir()
        for suffix in (".", "child/.."):
            with self.subTest(suffix=suffix):
                entry = entry_at(f"{self.root}/{suffix}")
                assert entry is not None
                with self.assertRaises(RemovalError):
                    remove(entry)
                self.assertTrue(self.file.is_file())
