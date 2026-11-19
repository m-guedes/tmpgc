"""Exercise each cleanup rule with observed facts supplied by the test."""

import stat
from dataclasses import replace

from filesystem_test_case import SyntheticEntryTestCase

from tmpgc.config import Settings
from tmpgc.entries import Tree
from tmpgc.processes import Process, Processes
from tmpgc.rules import Context, Decision, Kind, Origin, Verdict, classify, decide


_SECOND_NS = 10**9
_DAY = 24 * 60 * 60
_DEFAULT_AGE_SECONDS = 4 * _DAY
_ALLOCATED_KIB = 4


class RuleTests(SyntheticEntryTestCase):
    now_ns = 10 * _DAY * _SECOND_NS

    def setUp(self) -> None:
        self.trees = {
            f"/tmp/{name}": Tree(_ALLOCATED_KIB, self.now_ns, in_use=False)
            for name in ("MSBuildTempRecent", "scratch-recent")
        }
        self.context = Context(
            settings=Settings(("/tmp",), ()),
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
            mount_points=frozenset(),
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
        name: str,
        mode: int,
        *,
        origin: Origin = Origin.PRIMARY_SCAN,
        seconds_ago: int = _DEFAULT_AGE_SECONDS,
    ) -> Decision | None:
        timestamp = self.now_ns - seconds_ago * _SECOND_NS
        entry = self.entry(f"/tmp/{name}", mode, mtime_ns=timestamp)
        self.trees.setdefault(entry.path, Tree(_ALLOCATED_KIB, timestamp, in_use=False))
        kind = classify(entry, origin, self.context)
        return None if kind is None else decide(entry, kind, self.context)

    def test_removes_unbound_socket(self) -> None:
        self.assertEqual(
            self._decision("unbound.sock", stat.S_IFSOCK),
            Decision(Kind.SOCKET, Verdict.REMOVE, "stale socket"),
        )

    def test_keeps_bound_socket(self) -> None:
        self.assertEqual(
            self._decision("bound.sock", stat.S_IFSOCK),
            Decision(Kind.SOCKET, Verdict.KEEP, "active socket"),
        )

    def test_keeps_unbound_diagnostic_socket_with_live_pid(self) -> None:
        self.assertEqual(
            self._decision("dotnet-diagnostic-42-100-socket", stat.S_IFSOCK),
            Decision(Kind.SOCKET, Verdict.KEEP, "active socket"),
        )

    def test_removes_debugger_pipe_for_exited_pid(self) -> None:
        self.assertEqual(
            self._decision("clr-debug-pipe-43-100-in", stat.S_IFIFO),
            Decision(Kind.DEBUGGER_PIPE, Verdict.REMOVE, "stale clr-debug-pipe"),
        )

    def test_keeps_debugger_pipe_for_live_pid(self) -> None:
        self.assertEqual(
            self._decision("clr-debug-pipe-42-100-in", stat.S_IFIFO),
            Decision(Kind.DEBUGGER_PIPE, Verdict.KEEP, "pid 42 alive"),
        )

    def test_removes_debugger_pipe_when_pid_was_reused(self) -> None:
        self.assertEqual(
            self._decision("clr-debug-pipe-42-99-out", stat.S_IFIFO),
            Decision(Kind.DEBUGGER_PIPE, Verdict.REMOVE, "stale clr-debug-pipe"),
        )

    def test_keeps_debugger_pipe_when_one_pid_holder_matches(self) -> None:
        self._set_holders(Process(1, self.uid), Process(100, self.uid))
        self.assertEqual(
            self._decision("clr-debug-pipe-42-100-in", stat.S_IFIFO),
            Decision(Kind.DEBUGGER_PIPE, Verdict.KEEP, "pid 42 alive"),
        )

    def test_removes_unbound_msbuild_socket_when_only_root_holds_its_pid(self) -> None:
        self._set_holders(Process(100, 0))
        self.assertEqual(
            self._decision("MSBuild42", stat.S_IFSOCK),
            Decision(Kind.SOCKET, Verdict.REMOVE, "stale socket"),
        )

    def test_removes_unbound_msbuild_socket_when_holder_started_later(self) -> None:
        self._set_holders(Process(101, self.uid))
        self.assertEqual(
            self._decision("MSBuild42", stat.S_IFSOCK),
            Decision(Kind.SOCKET, Verdict.REMOVE, "stale socket"),
        )

    def test_keeps_unbound_msbuild_socket_when_one_holder_started_at_bind(self) -> None:
        self._set_holders(Process(1, 0), Process(100, self.uid))
        self.assertEqual(
            self._decision("MSBuild42", stat.S_IFSOCK),
            Decision(Kind.SOCKET, Verdict.KEEP, "active socket"),
        )

    def test_removes_msbuild_directory_for_exited_pid(self) -> None:
        self.assertEqual(
            self._decision("MSBuild43", stat.S_IFDIR),
            Decision(Kind.MSBUILD_DIRECTORY, Verdict.REMOVE, "stale MSBuild dir"),
        )

    def test_keeps_msbuild_directory_for_live_pid(self) -> None:
        self.assertEqual(
            self._decision("MSBuild42", stat.S_IFDIR),
            Decision(Kind.MSBUILD_DIRECTORY, Verdict.KEEP, "pid 42 alive"),
        )

    def test_keeps_msbuild_directory_without_pid(self) -> None:
        self.assertEqual(
            self._decision("MSBuildOther", stat.S_IFDIR),
            Decision(Kind.MSBUILD_DIRECTORY, Verdict.KEEP, "MSBuild dir without PID"),
        )

    def test_removes_idle_msbuild_temp_directory(self) -> None:
        self.assertEqual(
            self._decision("MSBuildTempOld", stat.S_IFDIR),
            Decision(
                Kind.MSBUILD_TEMP_DIRECTORY, Verdict.REMOVE, "MSBuildTemp idle >60m"
            ),
        )

    def test_keeps_recent_msbuild_temp_directory(self) -> None:
        self.assertEqual(
            self._decision("MSBuildTempRecent", stat.S_IFDIR),
            Decision(
                Kind.MSBUILD_TEMP_DIRECTORY,
                Verdict.KEEP,
                "MSBuildTemp active within 60m",
            ),
        )

    def test_removes_old_empty_nuget_probe(self) -> None:
        self.assertEqual(
            self._decision(
                "CASESENSITIVETEST42",
                stat.S_IFREG,
                origin=Origin.TEMPORARY_ROOT,
                seconds_ago=3601,
            ),
            Decision(Kind.NUGET_PROBE, Verdict.REMOVE, "NuGet probe file"),
        )

    def test_keeps_nuget_probe_at_age_limit(self) -> None:
        self.assertIsNone(
            self._decision(
                "CASESENSITIVETEST42",
                stat.S_IFREG,
                origin=Origin.TEMPORARY_ROOT,
                seconds_ago=3600,
            )
        )

    def test_removes_old_empty_sdk_directory(self) -> None:
        self.assertEqual(
            self._decision("AbCd42", stat.S_IFDIR, origin=Origin.TEMPORARY_ROOT),
            Decision(Kind.EMPTY_SDK_DIRECTORY, Verdict.REMOVE, "empty .NET temp dir"),
        )

    def test_keeps_nonempty_sdk_directory(self) -> None:
        self.assertIsNone(
            self._decision("NotEmp", stat.S_IFDIR, origin=Origin.TEMPORARY_ROOT)
        )

    def test_removes_idle_unused_scratch(self) -> None:
        self.assertEqual(
            self._decision("scratch-idle", stat.S_IFDIR, origin=Origin.SCRATCH_PATTERN),
            Decision(Kind.SCRATCH, Verdict.REMOVE, "scratch idle >3d", _ALLOCATED_KIB),
        )

    def test_keeps_idle_scratch_in_use(self) -> None:
        self.trees["/tmp/scratch-held"] = Tree(_ALLOCATED_KIB, 0, in_use=True)
        self.assertEqual(
            self._decision("scratch-held", stat.S_IFDIR, origin=Origin.SCRATCH_PATTERN),
            Decision(Kind.SCRATCH, Verdict.KEEP, "scratch held by a live process"),
        )

    def test_keeps_mount_point_and_its_ancestor(self) -> None:
        self.context = replace(
            self.context, mount_points=frozenset({"/tmp/scratch-mounted/nested"})
        )
        for name in ("scratch-mounted", "scratch-mounted/nested"):
            with self.subTest(name=name):
                self.assertEqual(
                    self._decision(name, stat.S_IFDIR, origin=Origin.SCRATCH_PATTERN),
                    Decision(Kind.SCRATCH, Verdict.KEEP, "at or above a mount point"),
                )
        self.assertEqual(
            self._decision(
                "scratch-mount", stat.S_IFDIR, origin=Origin.SCRATCH_PATTERN
            ),
            Decision(Kind.SCRATCH, Verdict.REMOVE, "scratch idle >3d", _ALLOCATED_KIB),
        )

    def test_keeps_recent_scratch(self) -> None:
        self.assertEqual(
            self._decision(
                "scratch-recent", stat.S_IFDIR, origin=Origin.SCRATCH_PATTERN
            ),
            Decision(Kind.SCRATCH, Verdict.KEEP, "scratch touched within 3d"),
        )

    def test_large_entry_needs_size_idleness_and_no_holders(self) -> None:
        threshold_kib = self.context.settings.large_entry_mib * 1024
        recent = self.now_ns - _DAY * _SECOND_NS + 1
        for tree, verdict, expected_size in (
            (Tree(threshold_kib, 0, in_use=False), Verdict.REMOVE, threshold_kib),
            (Tree(threshold_kib, recent, in_use=False), Verdict.KEEP, None),
            (Tree(threshold_kib, 0, in_use=True), Verdict.KEEP, None),
            (Tree(threshold_kib - 1, 0, in_use=False), None, None),
        ):
            with self.subTest(tree=tree):
                self.trees["/tmp/large"] = tree
                decision = self._decision(
                    "large", stat.S_IFDIR, origin=Origin.TEMPORARY_ROOT
                )
                if verdict is None:
                    self.assertIsNone(decision)
                else:
                    assert decision is not None
                    self.assertIs(decision.kind, Kind.LARGE)
                    self.assertIs(decision.verdict, verdict)
                    self.assertEqual(decision.allocated_kib, expected_size)
