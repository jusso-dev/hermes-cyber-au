#!/usr/bin/env bash
# Nightly: fold old observations into counters and drop feed advisories and
# EPSS history older than cyber_au.store.feed_retention_days (default 180).
#
# Hermes runs this file from $HERMES_HOME/scripts with a sanitised environment.
# Do not read the profile .env. stdout is delivered verbatim.
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
  printf 'store expiry failed: cyberau-mcp is not installed under mcp/.venv\n'
  exit 1
fi

if ! output=$("$bin" store compact 2>&1); then
  line=${output%%$'\n'*}
  line=${line:0:200}
  printf 'store expiry failed: %s\n' "${line:-command failed}"
  exit 1
fi
printf 'store expiry ok\n'
