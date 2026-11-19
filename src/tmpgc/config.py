"""Load temporary roots and scratch patterns."""

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast


SCAN_ROOT = "/tmp"
DEFAULT_DEPTH = 2
DEFAULT_SCRATCH_DAYS = 3


@dataclass(frozen=True, slots=True)
class Settings:
    temporary_roots: tuple[str, ...]
    scratch_patterns: tuple[str, ...]
    depth: int = DEFAULT_DEPTH
    scratch_days: int = DEFAULT_SCRATCH_DAYS
    build_litter_minutes: int = 60
    empty_directory_minutes: int = 24 * 60


class ConfigError(ValueError):
    """The configuration could not be read or is invalid."""


def config_path() -> Path:
    return (
        Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        / "tmpgc.toml"
    )


def _absolute_strings(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{key} must be an array of absolute strings")

    paths: list[str] = []
    for item in cast(list[object], value):
        if not isinstance(item, str) or not os.path.isabs(item) or "\0" in item:
            raise ConfigError(f"{key} must be an array of absolute strings")
        paths.append(item)
    return tuple(paths)


def load(
    path: Path,
    uid: int,
    *,
    depth: int = DEFAULT_DEPTH,
    scratch_days: int = DEFAULT_SCRATCH_DAYS,
) -> Settings:
    try:
        with path.open("rb") as file:
            document = tomllib.load(file)
    except FileNotFoundError:
        document = {}
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"{path}: {error}") from error

    if unknown := document.keys() - {"temporary_roots", "scratch_patterns"}:
        raise ConfigError(
            f"{path}: unknown configuration keys: {', '.join(sorted(unknown))}"
        )

    try:
        roots = _absolute_strings(
            document.get("temporary_roots", []), "temporary_roots"
        )
        patterns = _absolute_strings(
            document.get("scratch_patterns", []), "scratch_patterns"
        )
    except ConfigError as error:
        raise ConfigError(f"{path}: {error}") from error

    return Settings(
        (SCAN_ROOT, *roots),
        (f"{SCAN_ROOT}/claude-{uid}/*/*", f"{SCAN_ROOT}/*/claude-{uid}/*/*", *patterns),
        depth=depth,
        scratch_days=scratch_days,
    )
