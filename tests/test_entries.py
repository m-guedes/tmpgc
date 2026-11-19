"""Check filesystem activity measured from a tree."""

import os
import time

from filesystem_test_case import TreeTestCase

from tmpgc.entries import expand, measure


class EntryTests(TreeTestCase):
    def test_counts_file_access_and_modification(self) -> None:
        hour_ns = 3600 * 10**9
        # Keep the explicit times ahead of the ctime updates made by utime.
        written = time.time_ns() + hour_ns
        listed = written + hour_ns
        read = listed + hour_ns
        rewritten = read + hour_ns
        os.utime(self.file, ns=(written, written))
        for path, times, expected in (
            (self.root, (listed, self.root.stat().st_mtime_ns), written),
            (self.file, (read, written), read),
            (self.file, (read, rewritten), rewritten),
        ):
            with self.subTest(path=path, times=times):
                os.utime(path, ns=times)
                tree = measure(str(self.root), frozenset())
                assert tree is not None
                self.assertEqual(tree.last_activity_ns, expected)

    def test_expanding_pattern_preserves_symlink_access_time(self) -> None:
        link = self.root / "link"
        link.symlink_to(self.file)
        os.utime(link, ns=(1, 1), follow_symlinks=False)

        matches = [entry.path for entry in expand(str(self.root / "li*"))]
        self.assertEqual(matches, [str(link)])
        self.assertEqual(link.lstat().st_atime_ns, 1)
