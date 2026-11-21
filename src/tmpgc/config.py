"""Load the cleanup rules and validate their configuration."""

import os
import re
import tomllib
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from pathlib import Path
from typing import cast


class ConfigError(ValueError):
    """The configuration could not be read or is invalid."""


class EntryType(Enum):
    SOCKET = "socket"
    FIFO = "fifo"
    DIRECTORY = "directory"
    FILE = "file"


@dataclass(frozen=True, slots=True)
class Patterns:
    globs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.globs:
            raise ConfigError("paths must contain at least one glob")


@dataclass(frozen=True, slots=True)
class Search:
    roots: tuple[str, ...]
    depth: int

    def __post_init__(self) -> None:
        if not self.roots:
            raise ConfigError("under must contain at least one root")
        if self.depth < 1:
            raise ConfigError("depth must be at least 1")


@dataclass(frozen=True, slots=True)
class Rule:
    label: str
    select: Patterns | Search
    idle: timedelta
    type: EntryType | None = None
    name: re.Pattern[str] | None = None
    empty: bool = False
    min_size: int = 0
    held_idle: timedelta | None = None

    def __post_init__(self) -> None:
        if not self.label:
            raise ConfigError("label must be non-empty")
        if self.name is not None:
            groups = self.name.groupindex.keys()
            if groups - {"pid", "start"}:
                raise ConfigError("name may only define named groups pid and start")
            if "start" in groups and "pid" not in groups:
                raise ConfigError("name group start requires a group named pid")
        if self.held_idle is not None:
            if self.type is EntryType.SOCKET:
                raise ConfigError("socket rules cannot override in_use")
            if self.held_idle < self.idle:
                raise ConfigError("the in_use window cannot be shorter than idle")
        if self.empty and self.type in {EntryType.SOCKET, EntryType.FIFO}:
            raise ConfigError("empty cannot be used with type socket or fifo")


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


def load(path: Path, uid: int) -> tuple[Rule, ...]:
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

    return _rules(roots, patterns, uid)


def _rules(
    roots: tuple[str, ...], patterns: tuple[str, ...], uid: int
) -> tuple[Rule, ...]:
    deep = Search(("/tmp",), 2)
    top_level = Search(("/tmp", *roots), 1)
    immediate = timedelta()
    hour = timedelta(hours=1)
    day = timedelta(days=1)
    msbuild_owner = re.compile(r"MSBuild(?P<pid>[0-9]+)")
    return (
        Rule(
            "dotnet diagnostic socket",
            deep,
            immediate,
            EntryType.SOCKET,
            re.compile(r"dotnet-diagnostic-(?P<pid>[0-9]+)-(?P<start>[0-9]+)-socket"),
        ),
        Rule("MSBuild socket", deep, immediate, EntryType.SOCKET, msbuild_owner),
        Rule("socket", deep, immediate, EntryType.SOCKET),
        Rule(
            "clr-debug-pipe",
            deep,
            immediate,
            EntryType.FIFO,
            re.compile(r"clr-debug-pipe-(?P<pid>[0-9]+)-(?P<start>[0-9]+)-(?:in|out)"),
        ),
        Rule("MSBuild dir", deep, immediate, EntryType.DIRECTORY, msbuild_owner),
        Rule(
            "MSBuildTemp",
            deep,
            hour,
            EntryType.DIRECTORY,
            re.compile(r"MSBuildTemp.*"),
        ),
        Rule(
            "NuGet probe",
            top_level,
            hour,
            EntryType.FILE,
            re.compile(r"CASESENSITIVETEST.*"),
            empty=True,
        ),
        Rule(
            "empty .NET temp dir",
            top_level,
            day,
            EntryType.DIRECTORY,
            re.compile(r"[A-Za-z0-9]{6}"),
            empty=True,
        ),
        Rule(
            "scratch",
            Patterns((f"/tmp/claude-{uid}/*/*", f"/tmp/*/claude-{uid}/*/*", *patterns)),
            timedelta(days=3),
        ),
        Rule("large entry", top_level, day, min_size=100 * 1024**2),
        Rule("segment", Search(("/dev/shm",), 1), day, EntryType.FILE),
    )
