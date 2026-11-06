# shellcheck shell=bash
# Shared setup for the no-agent cron scripts. Source it, do not run it.
#
# Sets script_dir, profile (HERMES_HOME, else the directory above scripts/),
# data_dir (CYBERAU_DATA_DIR, else $profile/plugin-data/cyber-au) and bin (the
# profile's cyberau-mcp). Hermes delivers stdout verbatim and reads its first
# line, so every helper prints at most one short line.
# shellcheck disable=SC2034
unset CDPATH

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -n ${HERMES_HOME:-} ]]; then
  profile=$HERMES_HOME
else
  profile=$(cd -- "$script_dir/.." && pwd)
fi
data_dir=${CYBERAU_DATA_DIR:-$profile/plugin-data/cyber-au}
bin="${profile}/mcp/.venv/bin/cyberau-mcp"

# require_cli LABEL: stop with one line when cyberau-mcp is not installed.
require_cli() {
  if [[ ! -x "$bin" ]]; then
    printf '%s failed: cyberau-mcp is not installed under mcp/.venv\n' "$1"
    exit 1
  fi
}

# die_first_line PREFIX OUTPUT [FALLBACK]: print "PREFIX: " and the first line
# of OUTPUT cut to 200 characters (FALLBACK, default "command failed", when
# that line is empty), then exit 1.
die_first_line() {
  local line=${2%%$'\n'*}
  line=${line:0:200}
  printf '%s: %s\n' "$1" "${line:-${3-command failed}}"
  exit 1
}

# run_cli PREFIX ARGS...: run cyberau-mcp quietly, and on failure stop with
# one line from die_first_line.
run_cli() {
  local prefix=$1 output
  shift
  output=$("$bin" "$@" 2>&1) || die_first_line "$prefix" "$output"
}
