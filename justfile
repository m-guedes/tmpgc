set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments := true

units := justfile_directory() / "systemd"
service := units / "tmpgc.service"
timer := units / "tmpgc.timer"
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

# Check Python formatting, lint rules, types and the installed service command.
lint:
    uvx {{ ruff }} format --check .
    uvx {{ ruff }} check .
    uvx {{ basedpyright }}
    systemd-analyze --user verify {{ quote(service) }} {{ quote(timer) }}

# Run the cleanup rule tests.
test:
    uv run python -m unittest discover -s tests -t .

# Install tmpgc, link the user units and start the hourly timer.
install:
    uv tool install --reinstall .
    # The timer starts the linked service by name.
    systemctl --user link --force {{ quote(service) }}
    systemctl --user enable --force --now {{ quote(timer) }}

# Stop the timer, unlink the user units and uninstall tmpgc.
uninstall:
    systemctl --user disable --now tmpgc.timer tmpgc.service
    uv tool uninstall tmpgc
