"""Remove entries that still match their scan."""

import os
import shutil
import stat

from .entries import Entry, parent_directory


def remove(entry: Entry) -> bool:
    failed = False

    def record_error(_operation: object, _path: str, error: BaseException) -> None:
        nonlocal failed
        if not isinstance(error, OSError):
            raise error
        if not isinstance(error, FileNotFoundError):
            failed = True

    try:
        with parent_directory(entry.path) as (fd, name):
            # rm -rf refuses dot entries and the filesystem root.
            if name in {".", ".."}:
                return False
            current = os.lstat(name, dir_fd=fd)
            if not os.path.samestat(entry.info, current):
                return False
            if stat.S_ISDIR(current.st_mode):
                shutil.rmtree(name, dir_fd=fd, onexc=record_error)
            else:
                os.unlink(name, dir_fd=fd)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return not failed
