"""Parse options, assemble the run context and start the sweep."""

import argparse
import os
import sys
import time
from functools import cache
from typing import Never, override

from . import config, entries, mounts, processes, sweep
from .rules import Context


class _Parser(argparse.ArgumentParser):
    @override
    def error(self, message: str) -> Never:
        self.print_help(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


class _Options(argparse.Namespace):
    dry_run: bool
    verbose: bool


def main() -> int:
    path = config.config_path()
    parser = _Parser(prog="tmpgc", epilog=f"The configuration file {path} is required.")
    parser.add_argument(
        "-n", dest="dry_run", action="store_true", help="show what would be removed"
    )
    parser.add_argument(
        "-v", dest="verbose", action="store_true", help="show kept entries and removals"
    )
    options = parser.parse_args(namespace=_Options())
    uid = os.getuid()
    try:
        rules = config.load(path, uid)
    except config.ConfigError as error:
        parser.error(str(error))
    now_ns = time.time_ns()
    observed = processes.observe()
    mount_table = mounts.read()

    @cache
    def tree(path: str) -> entries.Tree | None:
        return entries.measure(path, observed.held, mount_table)

    context = Context(
        rules=rules,
        now_ns=now_ns,
        uid=uid,
        processes=observed,
        tree=tree,
        empty_dir=entries.empty_dir,
        mounts=mount_table,
    )
    return sweep.run(context, dry_run=options.dry_run, verbose=options.verbose)
