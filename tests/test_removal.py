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
                    remove(entry, only_if_empty=False)
                self.assertTrue(self.file.is_file())

    def test_empty_only_keeps_content_added_after_scan(self) -> None:
        contents = b"created after the scan"
        for kind in ("directory", "file"):
            with self.subTest(kind=kind):
                path = self.root / f"empty-{kind}"
                if kind == "directory":
                    path.mkdir()
                    target = path / "child"
                else:
                    path.touch()
                    target = path
                entry = entry_at(str(path))
                assert entry is not None
                target.write_bytes(contents)
                with self.assertRaises(RemovalError):
                    remove(entry, only_if_empty=True)
                self.assertEqual(target.read_bytes(), contents)
