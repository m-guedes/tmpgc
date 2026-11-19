set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments := true

script := justfile_directory() / "sh/ccleanup"
units := justfile_directory() / "sh"
bin_path := ".local/bin/ccleanup"
bin := home_directory() / bin_path

[private]
default:
    @just --list

# Run the script from this checkout: just run -n -v
run *args:
    "{{ script }}" "$@"

# Check the script's syntax and the units, including the command the service runs.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
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
