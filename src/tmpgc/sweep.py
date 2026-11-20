"""Apply cleanup decisions to selected entries."""

from .removal import RemovalError, remove
from .report import Report
from .rules import Context, Verdict, decide
from .selection import candidates


def run(context: Context, *, dry_run: bool, verbose: bool) -> int:
    report = Report(dry_run=dry_run, verbose=verbose)
    for entry, kind in candidates(context):
        decision = decide(entry, kind, context)
        if decision is None:
            continue
        if decision.verdict is Verdict.KEEP:
            report.kept(entry.path, decision.reason)
            continue

        report.removing(entry.path, decision)
        if not dry_run:
            try:
                remove(entry)
            except RemovalError as error:
                report.failed(entry.path, decision, error)
                continue
        report.removed(decision)

    report.summary((context.settings.scan_root, context.settings.shared_memory_root))
    return report.exit_status()
