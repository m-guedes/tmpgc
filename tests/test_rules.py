"""Exercise each cleanup rule with observed facts supplied by the test."""

import os
import stat
import unittest
from dataclasses import replace

from tmpgc.config import Settings
from tmpgc.entries import Entry
from tmpgc.processes import Process, Processes
from tmpgc.rules import Context, Decision, Kind, Origin, Verdict, classify, decide


_SECOND_NS = 10**9
_DAY = 24 * 60 * 60


class RuleTests(unittest.TestCase):
    uid = 1000
    now_ns = 10 * _DAY * _SECOND_NS

    def setUp(self) -> None:
        self.context = Context(
            settings=Settings(("/tmp",), ()),
            processes=Processes(
                {42: (Process(100),)},
                frozenset({"/tmp/bound.sock"}),
                frozenset(
                    {
                        "/tmp/scratch-held/child/open",
                        "/tmp/unrelated/tmp/scratch-idle/open",
                    }
                ),
            ),
            now_ns=self.now_ns,
            uid=self.uid,
            newest_change=self._newest_change,
            empty_dir=self._empty_dir,
        )

    def _newest_change(self, path: str) -> int:
        return (
            self.now_ns
            if path in {"/tmp/MSBuildTempRecent", "/tmp/scratch-recent"}
            else 0
        )

    def _empty_dir(self, path: str) -> bool:
        return path != "/tmp/NotEmp"

    def _decision(
        self,
        name: str,
        mode: int,
        *,
        origin: Origin = Origin.PRIMARY_SCAN,
        seconds_ago: int = 4 * _DAY,
    ) -> Decision | None:
        timestamp = self.now_ns - seconds_ago * _SECOND_NS
        info = os.stat_result(
            (mode, 0, 0, 1, self.uid, 0, 0, 0, 0, 0), {"st_mtime_ns": timestamp}
        )
        entry = Entry(f"/tmp/{name}", info)
        kind = classify(entry, origin, self.uid)
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
        self.context = replace(
            self.context,
            processes=replace(
                self.context.processes, holders={42: (Process(1), Process(100))}
            ),
        )
        self.assertEqual(
            self._decision("clr-debug-pipe-42-100-in", stat.S_IFIFO),
            Decision(Kind.DEBUGGER_PIPE, Verdict.KEEP, "pid 42 alive"),
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

    def test_removes_idle_scratch_when_its_path_is_only_a_substring(self) -> None:
        self.assertEqual(
            self._decision("scratch-idle", stat.S_IFDIR, origin=Origin.SCRATCH_PATTERN),
            Decision(Kind.SCRATCH, Verdict.REMOVE, "scratch idle >3d"),
        )

    def test_keeps_idle_scratch_with_held_descendant(self) -> None:
        self.assertEqual(
            self._decision("scratch-held", stat.S_IFDIR, origin=Origin.SCRATCH_PATTERN),
            Decision(Kind.SCRATCH, Verdict.KEEP, "scratch held by a live process"),
        )

    def test_keeps_recent_scratch(self) -> None:
        self.assertEqual(
            self._decision(
                "scratch-recent", stat.S_IFDIR, origin=Origin.SCRATCH_PATTERN
            ),
            Decision(Kind.SCRATCH, Verdict.KEEP, "scratch touched within 3d"),
        )
