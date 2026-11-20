"""Parse options, assemble the run context and start the sweep."""

import argparse
import os
import sys
import time
from dataclasses import replace
from datetime import timedelta
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
    depth: int
    scratch_days: int


def _nonnegative_integer(value: str) -> int:
    digits = value.removeprefix("+")
    if digits.isascii() and digits.isdecimal():
        return int(digits)
    raise argparse.ArgumentTypeError("expected a non-negative integer")


def main() -> int:
    path = config.config_path()
    parser = _Parser(
        prog="tmpgc", epilog=f"Settings are read from {path} if it exists."
    )
    parser.add_argument(
        "-n", dest="dry_run", action="store_true", help="show what would be removed"
    )
    parser.add_argument(
        "-v", dest="verbose", action="store_true", help="show kept entries and removals"
    )
    parser.add_argument(
        "-d",
        dest="depth",
        metavar="depth",
        type=_nonnegative_integer,
        default=config.DEFAULT_DEPTH,
        help="maximum directory search depth (default: %(default)s)",
    )
    parser.add_argument(
        "-s",
        dest="scratch_days",
        metavar="days",
        type=_nonnegative_integer,
        default=config.DEFAULT_SCRATCH_DAYS,
        help="idle days before scratch removal (default: %(default)s)",
    )
    options = parser.parse_args(namespace=_Options())
    if options.scratch_days > timedelta.max.days:
        parser.error(f"-s accepts at most {timedelta.max.days} days")
    uid = os.getuid()
    try:
        settings = config.load(path, uid)
    except config.ConfigError as error:
        parser.error(str(error))
    now_ns = time.time_ns()
    observed = processes.observe()
    mount_table = mounts.read()
    context = Context(
        settings=replace(
            settings,
            depth=options.depth,
            scratch_idle=timedelta(days=options.scratch_days),
        ),
        now_ns=now_ns,
        uid=uid,
        processes=observed,
        tree=lambda path: entries.measure(path, observed.held, mount_table),
        empty_dir=entries.empty_dir,
        mounts=mount_table,
    )
    return sweep.run(context, dry_run=options.dry_run, verbose=options.verbose)
