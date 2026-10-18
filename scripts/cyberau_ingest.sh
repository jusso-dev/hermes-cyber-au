#!/usr/bin/env bash
# Ingest of keyless public feeds into the intel store.
#
# Hermes runs this file from $HERMES_HOME/scripts. The cron script environment
# is sanitised, so provider credentials are not inherited. Opening the profile
# .env from this process would still be possible, and it is not safe: stdout
# is delivered verbatim, so a credential printed by a fault would leave the
# machine. Keyed sources stay on agent jobs, where each MCP server receives
# its keys from mcp_servers.*.env. This script refreshes keyless sources only
# (asd, kev, epss, auscert, and the public Feodo list).
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
  printf 'ingest failed: cyberau-mcp is not installed under mcp/.venv\n'
  exit 1
fi

# One argument picks the sources (comma separated). The per-feed jobs pass
# one source each so every feed runs on its own cadence.
sources=${1:-asd,kev,epss,auscert,feodo}
if ! output=$("$bin" refresh --sources "$sources" --store \
  --snapshot-dir "${profile}/plugin-data/cyber-au/snapshots" 2>&1); then
  line=${output%%$'\n'*}
  line=${line:0:200}
  printf 'ingest failed: %s\n' "${line:-refresh failed}"
  exit 1
fi
printf 'ingest ok: %s\n' "$sources"
