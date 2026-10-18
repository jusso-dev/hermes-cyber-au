#!/usr/bin/env bash
# Weekly backup, retention compaction, and vacuum.
#
# Hermes runs this file from $HERMES_HOME/scripts with a sanitised environment.
# Do not read the profile .env. stdout is delivered verbatim.
#
# Commands, in order: `store backup`, then `store compact` (retention
# compaction), then `store vacuum`. Backup runs first so a failed compaction
# still leaves a copy.
set -euo pipefail
unset CDPATH

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ -n ${HERMES_HOME:-} ]]; then
  profile=$HERMES_HOME
else
  profile=$(cd -- "$script_dir/.." && pwd)
fi

bin="${profile}/mcp/.venv/bin/cyberau-mcp"
if [[ ! -x "$bin" ]]; then
  printf 'store maintenance failed: cyberau-mcp is not installed under mcp/.venv\n'
  exit 1
fi

run_step() {
  local step=$1
  shift
  local output
  if ! output=$("$bin" "$@" 2>&1); then
    local line=${output%%$'\n'*}
    line=${line:0:200}
    printf 'store maintenance failed at %s: %s\n' "$step" "${line:-command failed}"
    exit 1
  fi
}

run_step backup store backup
run_step retention store compact
run_step vacuum store vacuum
python3 "$script_dir/cyberau_cleanup.py" --profile-home "$profile" --apply
printf 'store maintenance ok: backup, retention, vacuum\n'
