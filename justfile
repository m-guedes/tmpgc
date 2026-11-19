set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments := true

script := justfile_directory() / "sh/ccleanup"
units := justfile_directory() / "sh"
bin_path := ".local/bin/ccleanup"
bin := home_directory() / bin_path
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

# Check Python formatting, lint rules, types and the current units.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    uvx {{ ruff }} format --check .
    uvx {{ ruff }} check .
    uvx {{ basedpyright }}
    bash -n {{ quote(script) }}

    verify_dir=$(mktemp -d)
    trap 'rm -rf -- "$verify_dir"' EXIT
    verify_bin="$verify_dir/{{ bin_path }}"
    mkdir -p -- "$(dirname -- "$verify_bin")"
    ln -s -- {{ quote(script) }} "$verify_bin"
    # Substitute %Y, the unit's directory, for %h in the temporary copy
    # (systemd developers, systemd.unit(5), 2023).
    sed '/^ExecStart=/s|%h/|%Y/|' {{ quote(units / "ccleanup.service") }} > "$verify_dir/ccleanup.service"
    cp -- {{ quote(units / "ccleanup.timer") }} "$verify_dir/"
    systemd-analyze --user verify "$verify_dir/ccleanup.service" "$verify_dir/ccleanup.timer"

# Run the cleanup rule tests.
test:
    uv run python -m unittest discover -s tests

# Link the script and the units from this checkout and start the hourly timer.
install:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -e "{{ bin }}" ] && [ ! -L "{{ bin }}" ]; then
        echo "{{ bin }} exists and is not a link; remove it first." >&2
        exit 1
    fi
    mkdir -p "$(dirname "{{ bin }}")"
    ln -sfn "{{ script }}" "{{ bin }}"
    # The timer starts the service by name, so the service is linked though only the timer is
    # enabled. --force replaces a stale link and refuses a regular file: documented for enable,
    # observed for link under systemd 259.
    systemctl --user link --force "{{ units }}/ccleanup.service"
    systemctl --user enable --force --now "{{ units }}/ccleanup.timer"

# Stop the timer, unlink the units and remove the command link into this checkout.
uninstall:
    #!/usr/bin/env bash
    set -euo pipefail
    systemctl --user disable --now ccleanup.timer ccleanup.service
    if [ "$(readlink "{{ bin }}")" = "{{ script }}" ]; then
        rm "{{ bin }}"
    fi
