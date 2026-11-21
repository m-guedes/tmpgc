"""Exercise candidate selection."""

import os
from socket import AF_UNIX, socket

from tmpgc.config import EntryType, Patterns, Search
from tmpgc.entries import Tree, empty_dir
from tmpgc.mounts import Mounts
from tmpgc.processes import Processes
from tmpgc.rules import Context
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
        primary = Search((str(self.root),), 2)
        top_level = Search(
            (
                str(self.root),
                alias,
                str(root),
                str(sdk_named_root),
                str(nested_root),
                str(shm),
            ),
            1,
        )
        socket_rule = self.rule("socket", select=primary, entry_type=EntryType.SOCKET)
        sdk = self.rule(
            "SDK",
            select=top_level,
            entry_type=EntryType.DIRECTORY,
            name=r"[A-Za-z0-9]{6}",
            empty=True,
        )
        scratch_rule = self.rule(
            "scratch", select=Patterns((str(scratch.parent / "*"),))
        )
        large = self.rule("large", select=top_level, min_size=1024)
        shared_memory = self.rule(
            "segment", select=Search((str(shm),), 1), entry_type=EntryType.FILE
        )
        context = Context(
            rules=(socket_rule, sdk, scratch_rule, shared_memory, large),
            processes=Processes({}, frozenset(), frozenset(), 0, 100),
            now_ns=0,
            uid=os.getuid(),
            tree=lambda _: Tree(1024, 0, in_use=False, held_kib=0),
            empty_dir=empty_dir,
            mounts=Mounts(()),
        )

        self.assertEqual(
            [(entry.location, rule) for entry, rule in candidates(context)],
            [
                (socket_path, socket_rule),
                (scratch, scratch_rule),
                (segment, shared_memory),
                (child, large),
                (self.file, large),
            ],
        )
