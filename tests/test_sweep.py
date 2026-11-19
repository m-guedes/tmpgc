"""Exercise candidate selection and physical removal."""

import stat
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

from filesystem_test_case import SyntheticEntryTestCase

from tmpgc.config import Settings
from tmpgc.entries import Entry, normalize_path, walk
from tmpgc.processes import Processes
from tmpgc.rules import Context, Kind
from tmpgc.sweep import _candidates, _remove


class CandidateTests(SyntheticEntryTestCase):
    def test_large_selection_preserves_specific_rules_and_roots(self) -> None:
        root = "/tmp/configured-root"
        alias = "//tmp/configured-root/./"
        sdk_named_root = "/tmp/CfgDir"
        scratch = self.entry("/tmp/scratch-holder/scratch")
        socket = self.entry("/tmp/socket-holder/open.sock", stat.S_IFSOCK)
        plain = "/tmp/root-holder-extra"
        top_level = (
            "/tmp/scratch-holder",
            "/tmp/socket-holder",
            root,
            sdk_named_root,
            "/tmp/root-holder",
            plain,
        )
        context = Context(
            settings=Settings(
                ("/tmp", alias, root, sdk_named_root, "/tmp/root-holder/nested"),
                ("/tmp/scratch-holder/*",),
            ),
            processes=Processes({}, frozenset(), frozenset(), 0, 100),
            now_ns=0,
            uid=self.uid,
            tree=lambda _: None,
            empty_dir=lambda path: path == sdk_named_root,
            mount_points=frozenset(),
        )

        def scan(path: str, depth: int | None) -> Iterator[Entry]:
            yield self.entry(path)
            if path == "/tmp":
                yield from (self.entry(child) for child in top_level)
                if depth == context.settings.depth:
                    yield socket
            elif path in {root, alias}:
                yield self.entry(f"{path.rstrip('/')}/child")

        with (
            patch("tmpgc.sweep.walk", side_effect=scan),
            patch("tmpgc.sweep.expand", return_value=iter((scratch,))),
        ):
            selected = [
                (normalize_path(entry.path), kind)
                for entry, kind in _candidates(context)
            ]

        self.assertEqual(
            selected,
            [
                (socket.path, Kind.SOCKET),
                (scratch.path, Kind.SCRATCH),
                (f"{root}/child", Kind.LARGE),
                (plain, Kind.LARGE),
            ],
        )


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
