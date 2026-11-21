"""Apply cleanup decisions to selected entries."""

from collections.abc import Iterator

from .config import Patterns, Rule, Search
from .entries import fixed_prefix
from .paths import location
from .removal import RemovalError, remove
from .report import Report
from .rules import Context, Verdict, decide
from .selection import candidates


def _search_prefixes(rules: tuple[Rule, ...]) -> Iterator[str]:
    for rule in rules:
        match rule.select:
            case Patterns(globs):
                for pattern in globs:
                    yield fixed_prefix(pattern)
            case Search(roots):
                yield from roots


def run(context: Context, *, dry_run: bool, verbose: bool) -> int:
    report = Report(dry_run=dry_run, verbose=verbose)
    for entry, rule in candidates(context):
        decision = decide(entry, rule, context)
        if decision is None:
            continue
        if decision.verdict is Verdict.KEEP:
            report.kept(entry.path, decision.reason)
            continue

        report.removing(entry.path, decision)
        if not dry_run:
            try:
                remove(entry, decision.scope)
            except RemovalError as error:
                report.failed(entry.path, decision, error)
                continue
        report.removed(decision)

    filesystems = dict.fromkeys(
        str(point)
        for prefix in _search_prefixes(context.rules)
        if (point := context.mounts.containing(location(prefix))) is not None
    )
    report.summary(filesystems)
    return report.exit_status()
