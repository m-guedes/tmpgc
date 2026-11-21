set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments := true

units := justfile_directory() / "systemd"
service := units / "tmpgc.service"
timer := units / "tmpgc.timer"
default_config := justfile_directory() / "tmpgc.toml"
ruff := "ruff@0.17.5"
basedpyright := "basedpyright@1.40.2"

[private]
default:
    @just --list

# Run tmpgc from this checkout: just run -n -v
run *args:
    uv run tmpgc "$@"

# Format Python files.
fmt:
    uvx {{ ruff }} format .

# Check the default configuration, Python code and the installed service command.
lint: (_check-config default_config)
    uvx {{ ruff }} format --check .
    uvx {{ ruff }} check .
    uvx {{ basedpyright }}
    systemd-analyze --user verify {{ quote(service) }} {{ quote(timer) }}

# Run the cleanup rule tests.
test:
    uv run python -m unittest discover -s tests -t .

# Install the default configuration. Use -f to replace an existing file.
config flag="":
    #!/usr/bin/env bash
    uv run python - {{ quote(default_config) }} "$1" <<'PY'
    import os
    import sys
    from pathlib import Path
    from tempfile import TemporaryDirectory

    from tmpgc.config import config_path

    flag = sys.argv[2]
    if flag not in ("", "-f"):
        sys.exit("usage: just config [-f]")

    path = config_path()
    try:
        data = Path(sys.argv[1]).read_bytes()
        path.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=path.parent) as directory:
            staged = Path(directory) / path.name
            staged.write_bytes(data)
            staged.chmod(0o600)
            if flag == "-f":
                # Replace the destination atomically (Linux man-pages, rename(2), 2026).
                os.replace(staged, path)
            else:
                # Publish the complete file without replacing an existing name
                # (Linux man-pages, link(2), 2026).
                os.link(staged, path)
    except OSError as error:
        sys.exit(str(error))
    PY

[private]
_check-config path="":
    #!/usr/bin/env bash
    uv run python - "$1" <<'PY'
    import os
    import sys
    from pathlib import Path

    from tmpgc.config import ConfigError, config_path, load

    path = Path(sys.argv[1]) if sys.argv[1] else config_path()
    try:
        load(path, os.getuid())
    except ConfigError as error:
        sys.exit(str(error))
    PY

# Install tmpgc, link the user units and start the hourly timer.
install: _check-config
    uv tool install --reinstall .
    # The timer starts the linked service by name.
    systemctl --user link --force {{ quote(service) }}
    systemctl --user enable --force --now {{ quote(timer) }}

# Stop the timer, unlink the user units and uninstall tmpgc.
uninstall:
    systemctl --user disable --now tmpgc.timer tmpgc.service
    uv tool uninstall tmpgc
