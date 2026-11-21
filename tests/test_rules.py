"""Exercise each cleanup rule with observed facts supplied by the test."""

import stat
from dataclasses import replace
from datetime import timedelta

from tmpgc.config import EntryType, Rule
from tmpgc.entries import Tree
from tmpgc.mounts import Mounts
from tmpgc.paths import location
from tmpgc.processes import Process, Processes
from tmpgc.rules import Context, Decision, Verdict, decide, matches

from .filesystem_test_case import SyntheticEntryTestCase


_SECOND_NS = 10**9
_DAY = 24 * 60 * 60
_DEFAULT_AGE_SECONDS = 4 * _DAY
_ALLOCATED_KIB = 4


class RuleTests(SyntheticEntryTestCase):
    now_ns = 10 * _DAY * _SECOND_NS

    def setUp(self) -> None:
        self.socket = self.rule("socket", entry_type=EntryType.SOCKET)
        self.diagnostic = self.rule(
            "dotnet diagnostic socket",
            entry_type=EntryType.SOCKET,
            name=r"dotnet-diagnostic-(?P<pid>[0-9]+)-(?P<start>[0-9]+)-socket",
        )
        self.pipe = self.rule(
            "clr-debug-pipe",
            entry_type=EntryType.FIFO,
            name=r"clr-debug-pipe-(?P<pid>[0-9]+)-(?P<start>[0-9]+)-(?:in|out)",
        )
        msbuild_owner = r"MSBuild(?P<pid>[0-9]+)"
        self.msbuild_socket = self.rule(
            "MSBuild socket", entry_type=EntryType.SOCKET, name=msbuild_owner
        )
        self.msbuild_dir = self.rule(
            "MSBuild dir", entry_type=EntryType.DIRECTORY, name=msbuild_owner
        )
        self.msbuild_temp = self.rule(
            "MSBuildTemp",
            idle=timedelta(hours=1),
            entry_type=EntryType.DIRECTORY,
            name=r"MSBuildTemp.*",
        )
        self.nuget = self.rule(
            "NuGet probe",
            idle=timedelta(hours=1),
            entry_type=EntryType.FILE,
            name=r"CASESENSITIVETEST.*",
            empty=True,
        )
        self.sdk = self.rule(
            "empty .NET temp dir",
            idle=timedelta(days=1),
            entry_type=EntryType.DIRECTORY,
            name=r"[A-Za-z0-9]{6}",
            empty=True,
        )
        self.scratch = self.rule("scratch", idle=timedelta(days=3))
        self.large = self.rule(
            "large entry", idle=timedelta(days=1), min_size=100 * 1024**2
        )
        self.segment = self.rule(
            "segment", idle=timedelta(days=1), entry_type=EntryType.FILE
        )
        self.trees = {
            f"/tmp/{name}": Tree(
                _ALLOCATED_KIB * 1024, self.now_ns, in_use=False, held_kib=0
            )
            for name in ("MSBuildTempRecent", "scratch-recent")
        }
        self.context = Context(
            rules=(),
            processes=Processes(
                {42: (Process(100, self.uid),)},
                frozenset({"/tmp/bound.sock"}),
                frozenset(),
                boot_ns=self.now_ns - (_DEFAULT_AGE_SECONDS + 1) * _SECOND_NS,
                ticks_per_second=100,
            ),
            now_ns=self.now_ns,
            uid=self.uid,
            tree=self.trees.get,
            empty_dir=self._empty_dir,
            mounts=Mounts(()),
        )

    def _set_holders(self, *holders: Process) -> None:
        self.context = replace(
            self.context,
            processes=replace(self.context.processes, holders={42: holders}),
        )

    def _empty_dir(self, path: str) -> bool:
        return path != "/tmp/NotEmp"

    def _decision(
        self,
        rule: Rule,
        name: str,
        mode: int,
        *,
        root: str = "/tmp",
        seconds_ago: int = _DEFAULT_AGE_SECONDS,
    ) -> Decision | None:
        timestamp = self.now_ns - seconds_ago * _SECOND_NS
        entry = self.entry(f"{root}/{name}", mode, mtime_ns=timestamp)
        allocated_kib = 0 if mode in {stat.S_IFSOCK, stat.S_IFIFO} else _ALLOCATED_KIB
        self.trees.setdefault(
            entry.path, Tree(allocated_kib * 1024, timestamp, in_use=False, held_kib=0)
        )
        return (
            decide(entry, rule, self.context)
            if matches(entry, rule, self.context)
            else None
        )

    def _assert_one_day_idle_unused(
        self,
        rule: Rule,
        mode: int,
        allocated_kib: int,
        *,
        root: str = "/tmp",
    ) -> None:
        cutoff = self.now_ns - _DAY * _SECOND_NS
        for last_activity_ns, in_use, verdict in (
            (cutoff - 1, False, Verdict.REMOVE),
            (cutoff + 1, False, Verdict.KEEP),
            (cutoff - 1, True, Verdict.KEEP),
        ):
            with self.subTest(last_activity_ns=last_activity_ns, in_use=in_use):
                self.trees[f"{root}/entry"] = Tree(
                    allocated_kib * 1024, last_activity_ns, in_use=in_use, held_kib=0
                )
                decision = self._decision(rule, "entry", mode, root=root)
                assert decision is not None
                self.assertIs(decision.verdict, verdict)
                self.assertEqual(
                    decision.freed_kib,
                    allocated_kib if verdict is Verdict.REMOVE else 0,
                )

    def test_removes_unbound_socket(self) -> None:
        self.assertEqual(
            self._decision(self.socket, "unbound.sock", stat.S_IFSOCK),
            Decision(Verdict.REMOVE, "stale socket"),
        )

    def test_keeps_bound_socket(self) -> None:
        self.assertEqual(
            self._decision(self.socket, "bound.sock", stat.S_IFSOCK),
            Decision(Verdict.KEEP, "socket bound"),
        )

    def test_keeps_unbound_diagnostic_socket_with_live_pid(self) -> None:
        self.assertEqual(
            self._decision(
                self.diagnostic, "dotnet-diagnostic-42-100-socket", stat.S_IFSOCK
            ),
            Decision(Verdict.KEEP, "dotnet diagnostic socket pid 42 alive"),
        )

    def test_removes_debugger_pipe_for_exited_pid(self) -> None:
        self.assertEqual(
            self._decision(self.pipe, "clr-debug-pipe-43-100-in", stat.S_IFIFO),
            Decision(Verdict.REMOVE, "stale clr-debug-pipe"),
        )

    def test_keeps_debugger_pipe_for_live_pid(self) -> None:
        self.assertEqual(
            self._decision(self.pipe, "clr-debug-pipe-42-100-in", stat.S_IFIFO),
            Decision(Verdict.KEEP, "clr-debug-pipe pid 42 alive"),
        )

    def test_removes_debugger_pipe_when_pid_was_reused(self) -> None:
        self.assertEqual(
            self._decision(self.pipe, "clr-debug-pipe-42-99-out", stat.S_IFIFO),
            Decision(Verdict.REMOVE, "stale clr-debug-pipe"),
        )

    def test_keeps_debugger_pipe_when_one_pid_holder_matches(self) -> None:
        self._set_holders(Process(1, self.uid), Process(100, self.uid))
        self.assertEqual(
            self._decision(self.pipe, "clr-debug-pipe-42-100-in", stat.S_IFIFO),
            Decision(Verdict.KEEP, "clr-debug-pipe pid 42 alive"),
        )

    def test_removes_unbound_msbuild_socket_when_only_root_holds_its_pid(self) -> None:
        self._set_holders(Process(100, 0))
        self.assertEqual(
            self._decision(self.msbuild_socket, "MSBuild42", stat.S_IFSOCK),
            Decision(Verdict.REMOVE, "stale MSBuild socket"),
        )

    def test_removes_unbound_msbuild_socket_when_holder_started_later(self) -> None:
        self._set_holders(Process(101, self.uid))
        self.assertEqual(
            self._decision(self.msbuild_socket, "MSBuild42", stat.S_IFSOCK),
            Decision(Verdict.REMOVE, "stale MSBuild socket"),
        )

    def test_keeps_unbound_msbuild_socket_when_one_holder_started_at_bind(self) -> None:
        self._set_holders(Process(1, 0), Process(100, self.uid))
        self.assertEqual(
            self._decision(self.msbuild_socket, "MSBuild42", stat.S_IFSOCK),
            Decision(Verdict.KEEP, "MSBuild socket pid 42 alive"),
        )

    def test_removes_msbuild_directory_for_exited_pid(self) -> None:
        self.assertEqual(
            self._decision(self.msbuild_dir, "MSBuild43", stat.S_IFDIR),
            Decision(Verdict.REMOVE, "stale MSBuild dir", _ALLOCATED_KIB),
        )

    def test_keeps_msbuild_directory_for_live_pid(self) -> None:
        self.assertEqual(
            self._decision(self.msbuild_dir, "MSBuild42", stat.S_IFDIR),
            Decision(Verdict.KEEP, "MSBuild dir pid 42 alive"),
        )

    def test_excludes_msbuild_directory_without_pid(self) -> None:
        self.assertIsNone(
            self._decision(self.msbuild_dir, "MSBuildOther", stat.S_IFDIR)
        )

    def test_removes_idle_msbuild_temp_directory(self) -> None:
        self.assertEqual(
            self._decision(self.msbuild_temp, "MSBuildTempOld", stat.S_IFDIR),
            Decision(Verdict.REMOVE, "MSBuildTemp idle >1h", _ALLOCATED_KIB),
        )

    def test_keeps_recent_msbuild_temp_directory(self) -> None:
        self.assertEqual(
            self._decision(self.msbuild_temp, "MSBuildTempRecent", stat.S_IFDIR),
            Decision(Verdict.KEEP, "MSBuildTemp touched within 1h"),
        )

    def test_removes_old_empty_nuget_probe(self) -> None:
        self.assertEqual(
            self._decision(
                self.nuget, "CASESENSITIVETEST42", stat.S_IFREG, seconds_ago=3601
            ),
            Decision(Verdict.REMOVE, "NuGet probe idle >1h", _ALLOCATED_KIB),
        )

    def test_keeps_nuget_probe_at_age_limit(self) -> None:
        self.assertEqual(
            self._decision(
                self.nuget, "CASESENSITIVETEST42", stat.S_IFREG, seconds_ago=3600
            ),
            Decision(Verdict.KEEP, "NuGet probe touched within 1h"),
        )

    def test_removes_old_empty_sdk_directory(self) -> None:
        self.assertEqual(
            self._decision(self.sdk, "AbCd42", stat.S_IFDIR),
            Decision(Verdict.REMOVE, "empty .NET temp dir idle >1d", _ALLOCATED_KIB),
        )

    def test_keeps_nonempty_sdk_directory(self) -> None:
        self.assertIsNone(self._decision(self.sdk, "NotEmp", stat.S_IFDIR))

    def test_removes_idle_unused_scratch(self) -> None:
        self.assertEqual(
            self._decision(self.scratch, "scratch-idle", stat.S_IFDIR),
            Decision(Verdict.REMOVE, "scratch idle >3d", _ALLOCATED_KIB),
        )

    def test_keeps_idle_scratch_in_use(self) -> None:
        self.trees["/tmp/scratch-held"] = Tree(
            _ALLOCATED_KIB * 1024, 0, in_use=True, held_kib=_ALLOCATED_KIB
        )
        self.assertEqual(
            self._decision(self.scratch, "scratch-held", stat.S_IFDIR),
            Decision(Verdict.KEEP, "scratch held by a live process"),
        )

    def test_keeps_mount_point_and_its_ancestor(self) -> None:
        self.context = replace(
            self.context, mounts=Mounts((location("/tmp/scratch-mounted/nested"),))
        )
        for name in ("scratch-mounted", "scratch-mounted/nested"):
            with self.subTest(name=name):
                self.assertEqual(
                    self._decision(self.scratch, name, stat.S_IFDIR),
                    Decision(Verdict.KEEP, "scratch at or above a mount point"),
                )
        with self.subTest(rule=self.large.label):
            self.assertIsNone(
                self._decision(self.large, "scratch-mounted", stat.S_IFDIR)
            )
        self.assertEqual(
            self._decision(self.scratch, "scratch-mount", stat.S_IFDIR),
            Decision(Verdict.REMOVE, "scratch idle >3d", _ALLOCATED_KIB),
        )

    def test_keeps_recent_scratch(self) -> None:
        self.assertEqual(
            self._decision(self.scratch, "scratch-recent", stat.S_IFDIR),
            Decision(Verdict.KEEP, "scratch touched within 3d"),
        )

    def test_large_entry_needs_size_idleness_and_no_holders(self) -> None:
        threshold_kib = self.large.min_size // 1024
        self._assert_one_day_idle_unused(self.large, stat.S_IFDIR, threshold_kib)
        self.trees["/tmp/small"] = Tree(
            (threshold_kib - 1) * 1024, 0, in_use=False, held_kib=0
        )
        self.assertIsNone(self._decision(self.large, "small", stat.S_IFDIR))

    def test_shared_memory_segment_needs_idleness_and_no_holders(self) -> None:
        self._assert_one_day_idle_unused(
            self.segment, stat.S_IFREG, _ALLOCATED_KIB, root="/dev/shm"
        )
