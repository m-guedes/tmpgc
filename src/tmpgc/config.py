"""Load the cleanup rules and validate their configuration."""

import os
import re
import tomllib
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from pathlib import Path
from typing import cast


_RULE_KEYS = {
    "label",
    "paths",
    "under",
    "exclude",
    "depth",
    "type",
    "name",
    "empty",
    "min_size",
    "idle",
    "in_use",
}
# The integer time units in this subset of systemd's tmpfiles.d(5) and
# systemd.time(7) (systemd project, systemd 259, 2026).
_DURATION_TERM = re.compile(r"([0-9]+)\s*(min|[smhdw])\s*", re.ASCII)
_SECONDS = {"s": 1, "m": 60, "min": 60, "h": 3600, "d": 86400, "w": 604800}
# Binary size suffixes from systemd.resource-control(5) (systemd project, 2026).
_SIZE = re.compile(r"([0-9]+)([KMGT]?)")
_SIZE_SCALES = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_SPECIFIER = re.compile(r"%.?", re.DOTALL)


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
    exclude: tuple[str, ...] = ()

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


def _expand_specifiers(path: str, key: str, uid: int) -> str:
    # Resolve once, so %%U produces a literal %U (systemd project, tmpfiles.d(5), 2026).
    def replace(specifier: re.Match[str]) -> str:
        match specifier[0]:
            case "%U":
                return str(uid)
            case "%%":
                return "%"
            case unknown:
                raise ConfigError(
                    f"{key} has unknown specifier {unknown!r} in {path!r}"
                )

    return _SPECIFIER.sub(replace, path)


def _absolute_paths(value: object, key: str, uid: int) -> tuple[str, ...]:
    return tuple(
        _expand_specifiers(path, key, uid) for path in _absolute_strings(value, key)
    )


def _selector(table: dict[str, object], uid: int) -> Patterns | Search:
    has_paths = "paths" in table
    if has_paths == ("under" in table):
        raise ConfigError("exactly one of paths or under is required")
    key = "paths" if has_paths else "under"
    paths = _absolute_paths(table[key], key, uid)
    if has_paths:
        if "depth" in table:
            raise ConfigError("depth can only be used with under")
        return Patterns(paths)
    depth = table.get("depth")
    if type(depth) is not int:
        raise ConfigError("under requires an integer depth")
    return Search(paths, depth)


def _quantity_text(value: object, key: str) -> str:
    if type(value) is int:
        return str(value)
    if isinstance(value, str):
        return value.strip()
    raise ConfigError(f"{key} must be a string or integer")


def _decimal(digits: str, key: str) -> int:
    try:
        return int(digits)
    except ValueError as error:
        raise ConfigError(f"{key} is too large") from error


def _duration(value: object, key: str) -> timedelta:
    text = _quantity_text(value, key)
    if not text:
        raise ConfigError(f"{key} must be a duration")
    if text.isascii() and text.isdecimal():
        seconds = _decimal(text, key)
    else:
        seconds = 0
        offset = 0
        while offset < len(text):
            term = _DURATION_TERM.match(text, offset)
            if term is None:
                raise ConfigError(f"{key} must be a duration in s, m, min, h, d or w")
            seconds += _decimal(term[1], key) * _SECONDS[term[2]]
            offset = term.end()
    try:
        return timedelta(seconds=seconds)
    except OverflowError as error:
        raise ConfigError(f"{key} is too large") from error


def _size(value: object) -> int:
    text = _quantity_text(value, "min_size")
    if (match := _SIZE.fullmatch(text)) is None:
        raise ConfigError("min_size must be bytes with an optional K, M, G or T suffix")
    return _decimal(match[1], "min_size") * _SIZE_SCALES[match[2]]


def _entry_type(value: object) -> EntryType | None:
    if value is None:
        return None
    try:
        return EntryType(value)
    except ValueError as error:
        choices = ", ".join(member.value for member in EntryType)
        raise ConfigError(f"type must be one of {choices}") from error


def _name(value: object) -> re.Pattern[str] | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError("name must be a regular expression string")
    try:
        return re.compile(value)
    except (re.PatternError, OverflowError, RecursionError) as error:
        raise ConfigError(f"invalid name pattern: {error}") from error


def _held_idle(value: object, idle: timedelta) -> timedelta | None:
    if isinstance(value, bool):
        return None if value else idle
    duration = _duration(value, "in_use")
    if duration <= idle:
        raise ConfigError("in_use duration must be longer than idle")
    return duration


def _exclude(table: dict[str, object], uid: int) -> tuple[str, ...]:
    if "exclude" not in table:
        return ()
    if not (globs := _absolute_paths(table["exclude"], "exclude", uid)):
        raise ConfigError("exclude must contain at least one glob")
    return globs


def _parse_rule(table: dict[str, object], uid: int) -> Rule:
    if unknown := table.keys() - _RULE_KEYS:
        raise ConfigError(f"unknown keys: {', '.join(sorted(unknown))}")
    label = table.get("label")
    if not isinstance(label, str):
        raise ConfigError("label is required and must be a string")
    if "idle" not in table:
        raise ConfigError("idle is required")
    idle = _duration(table["idle"], "idle")
    entry_type = _entry_type(table.get("type"))
    empty = table.get("empty", False)
    if not isinstance(empty, bool):
        raise ConfigError("empty must be a boolean")
    if entry_type is EntryType.SOCKET and "in_use" in table:
        raise ConfigError("in_use cannot be specified with type socket")
    return Rule(
        label,
        _selector(table, uid),
        idle,
        type=entry_type,
        name=_name(table.get("name")),
        empty=empty,
        min_size=_size(table.get("min_size", 0)),
        held_idle=_held_idle(table.get("in_use", True), idle),
        exclude=_exclude(table, uid),
    )


def load(path: Path, uid: int) -> tuple[Rule, ...]:
    try:
        with path.open("rb") as file:
            document = tomllib.load(file)
    except (OSError, ValueError, RecursionError) as error:
        raise ConfigError(f"{path}: {error}") from error

    if unknown := document.keys() - {"rule"}:
        raise ConfigError(
            f"{path}: unknown configuration keys: {', '.join(sorted(unknown))}"
        )
    values: object = document.get("rule")
    if not isinstance(values, list) or not values:
        raise ConfigError(f"{path}: expected at least one [[rule]]")

    rules: list[Rule] = []
    for number, value in enumerate(cast(list[object], values), start=1):
        where = f"{path}: rule {number}"
        if not isinstance(value, dict):
            raise ConfigError(f"{where}: expected a table")
        table = cast(dict[str, object], value)
        label = table.get("label")
        if isinstance(label, str) and label:
            where += f" ({label!r})"
        try:
            rules.append(_parse_rule(table, uid))
        except ConfigError as error:
            raise ConfigError(f"{where}: {error}") from error
    return tuple(rules)
