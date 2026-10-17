#!/usr/bin/env bash
# Hourly ingest of keyless public feeds.
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

sources=asd,kev,epss,auscert,feodo
if ! output=$("$bin" refresh --sources "$sources" --store 2>&1); then
  line=${output%%$'\n'*}
  line=${line:0:200}
  printf 'ingest failed: %s\n' "${line:-refresh failed}"
  exit 1
fi
printf 'ingest ok: %s\n' "$sources"
