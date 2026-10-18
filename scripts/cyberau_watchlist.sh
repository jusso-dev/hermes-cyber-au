#!/usr/bin/env bash
# Nightly: recompute watchlist matches against the current store. Matches whose
# store row expired are removed. Watched domains are sent only to crt.sh.
# A fresh install with no watchlists.yaml succeeds and does nothing.
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
  printf 'watchlist failed: cyberau-mcp is not installed under mcp/.venv\n'
  exit 1
fi

if ! output=$("$bin" store watchlist run --crtsh 2>&1); then
  line=${output%%$'\n'*}
  line=${line:0:200}
  printf 'watchlist failed: %s\n' "${line:-command failed}"
  exit 1
fi
printf 'watchlist ok\n'
