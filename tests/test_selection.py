"""Exercise candidate selection."""

import stat
from collections.abc import Iterator
from unittest.mock import patch

from tmpgc.config import Settings
from tmpgc.entries import Entry, normalize_path
from tmpgc.processes import Processes
from tmpgc.rules import Context, Kind
from tmpgc.selection import candidates

from .filesystem_test_case import SyntheticEntryTestCase


class CandidateTests(SyntheticEntryTestCase):
    def test_large_selection_preserves_specific_rules_and_roots(self) -> None:
        root = "/tmp/configured-root"
        alias = "//tmp/configured-root/./"
        sdk_named_root = "/tmp/CfgDir"
        scratch = self.entry("/tmp/scratch-holder/scratch")
        socket = self.entry("/tmp/socket-holder/open.sock", stat.S_IFSOCK)
        segment = self.entry("/dev/shm/pool", stat.S_IFREG)
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
                (
                    "/tmp",
                    alias,
                    root,
                    sdk_named_root,
                    "/tmp/root-holder/nested",
                    "/dev/shm",
                ),
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
            elif path == "/dev/shm":
                yield segment

        with (
            patch("tmpgc.selection.walk", side_effect=scan),
            patch("tmpgc.selection.expand", return_value=iter((scratch,))),
        ):
            selected = [
                (normalize_path(entry.path), kind)
                for entry, kind in candidates(context)
            ]

        self.assertEqual(
            selected,
            [
                (socket.path, Kind.SOCKET),
                (scratch.path, Kind.SCRATCH),
                (f"{root}/child", Kind.LARGE),
                (plain, Kind.LARGE),
                (segment.path, Kind.SEGMENT),
            ],
        )
