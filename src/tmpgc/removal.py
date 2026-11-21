"""Remove entries that still match their scan."""

import os
import shutil
import stat

from .entries import Entry, parent_directory
from .rules import Scope


class RemovalError(Exception):
    """The scanned entry could not be removed."""


def _remove_tree(name: str, parent_fd: int) -> None:
    first_error: tuple[str, OSError] | None = None

    def record_error(_operation: object, path: str, error: BaseException) -> None:
        nonlocal first_error
        if not isinstance(error, OSError):
            raise error
        # Continue removing siblings while retaining the first failure and its path.
        if first_error is None and not isinstance(error, FileNotFoundError):
            first_error = path, error

    shutil.rmtree(name, dir_fd=parent_fd, onexc=record_error)
    if first_error is not None:
        path, error = first_error
        # CPython's rmtree adds a filename even to message-only OSErrors.
        # Their original message is in the exception arguments (shutil.py, 2026).
        cause = error.strerror or BaseException.__str__(error)
        raise RemovalError(f"{path}: {cause}") from error


def remove(entry: Entry, scope: Scope) -> None:
    try:
        with parent_directory(entry.path) as (fd, name):
            # rm -rf refuses dot entries and the filesystem root.
            if name in {".", ".."}:
                raise RemovalError(f"refusing to remove dot entry {name!r}")
            current = os.lstat(name, dir_fd=fd)
            if not os.path.samestat(entry.info, current):
                raise RemovalError("entry changed since scan")
            if stat.S_ISDIR(current.st_mode):
                if scope is Scope.EMPTY:
                    # rmdir protects entries created after the scan, as in
                    # systemd-tmpfiles (systemd project, tmpfiles.c, 2026).
                    os.rmdir(name, dir_fd=fd)
                else:
                    _remove_tree(name, fd)
            else:
                # A writer can still change the length between this check and unlink.
                if scope is Scope.EMPTY and current.st_size:
                    raise RemovalError("entry changed since scan")
                os.unlink(name, dir_fd=fd)
    except FileNotFoundError:
        return
    except OSError as error:
        raise RemovalError(str(error)) from error
