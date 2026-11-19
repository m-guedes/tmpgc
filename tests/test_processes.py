"""Check which filesystem entries are held by live processes."""

import mmap
import subprocess
import sys

from tree_test_case import TreeTestCase

from tmpgc.entries import measure
from tmpgc.processes import observe


class ProcessTests(TreeTestCase):
    def _tree_in_use(self) -> bool:
        tree = measure(str(self.root), observe().held)
        assert tree is not None
        return tree.in_use

    def test_tree_with_open_file_is_in_use(self) -> None:
        with self.file.open("rb"):
            self.assertTrue(self._tree_in_use())

    def test_tree_with_mapped_file_is_in_use_after_close(self) -> None:
        with self.file.open("rb") as file:
            mapping = mmap.mmap(
                file.fileno(), 0, access=mmap.ACCESS_READ, trackfd=False
            )
        with mapping:
            self.assertTrue(self._tree_in_use())

    def test_tree_with_process_working_directory_is_in_use(self) -> None:
        with subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.read()"],
            cwd=self.root,
            stdin=subprocess.PIPE,
        ):
            self.assertTrue(self._tree_in_use())

    def test_tree_without_holders_is_unused(self) -> None:
        self.assertFalse(self._tree_in_use())
