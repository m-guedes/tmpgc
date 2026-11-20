"""Exercise candidate selection."""

import os
from socket import AF_UNIX, socket

from tmpgc.config import Settings
from tmpgc.entries import empty_dir
from tmpgc.mounts import Mounts
from tmpgc.processes import Processes
from tmpgc.rules import Context, Kind
from tmpgc.selection import candidates

from .filesystem_test_case import TreeTestCase


class CandidateTests(TreeTestCase):
    def test_large_selection_preserves_specific_rules_and_roots(self) -> None:
        root = self.root / "configured-root"
        alias = f"/{root}/./"
        sdk_named_root = self.root / "CfgDir"
        nested_root = self.root / "root-holder" / "nested"
        scratch = self.root / "scratch-holder" / "scratch"
        socket_path = self.root / "socket-holder" / "open.sock"
        shm = self.root / "shm"
        segment = shm / "pool"
        child = root / "child"
        for directory in (
            child,
            sdk_named_root,
            nested_root,
            scratch,
            socket_path.parent,
            shm,
        ):
            directory.mkdir(parents=True)
        self.enterContext(socket(AF_UNIX)).bind(str(socket_path))
        segment.touch()
        context = Context(
            settings=Settings(
                (
                    str(self.root),
                    alias,
                    str(root),
                    str(sdk_named_root),
                    str(nested_root),
                    str(shm),
                ),
                (str(scratch.parent / "*"),),
                scan_root=str(self.root),
                shared_memory_root=str(shm),
            ),
            processes=Processes({}, frozenset(), frozenset(), 0, 100),
            now_ns=0,
            uid=os.getuid(),
            tree=lambda _: None,
            empty_dir=empty_dir,
            mounts=Mounts(()),
        )

        self.assertEqual(
            [(entry.location, kind) for entry, kind in candidates(context)],
            [
                (socket_path, Kind.SOCKET),
                (scratch, Kind.SCRATCH),
                (child, Kind.LARGE),
                (self.file, Kind.LARGE),
                (segment, Kind.SEGMENT),
            ],
        )
