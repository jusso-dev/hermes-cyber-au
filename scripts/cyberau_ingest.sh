#!/usr/bin/env bash
# Ingest of keyless public feeds into the intel store.
#
# Hermes runs this file from $HERMES_HOME/scripts. The cron script environment
# is sanitised, so provider credentials are not inherited. Opening the profile
# .env from this process would still be possible, and it is not safe: stdout
# is delivered verbatim, so a credential printed by a fault would leave the
# machine. Keyed sources stay on agent jobs, where each MCP server receives
# its keys from mcp_servers.*.env. This script refreshes keyless sources only
# (asd, kev, epss, auscert, the public Feodo list, and the public custom feeds
# turned on in watchlists.yaml).
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=_cyberau_lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/_cyberau_lib.sh"
require_cli 'ingest'

# One argument picks the sources (comma separated). The per-feed jobs pass
# one source each so every feed runs on its own cadence.
sources=${1:-asd,kev,epss,auscert,feodo}
refresh_args=(refresh --sources "$sources" --store)
if [[ ",${sources//[[:space:]]/}," == *",kev,"* ]]; then
  refresh_args+=(--kev-snapshot "${data_dir}/snapshots/kev.json")
fi
if ! output=$("$bin" "${refresh_args[@]}" 2>&1); then
  die_first_line 'ingest failed' "$output" 'refresh failed'
fi
printf 'ingest ok: %s\n' "$sources"
