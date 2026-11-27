#!/usr/bin/env bash
# Daily: look for lookalike certificates of watched domains on crt.sh, and BGP
# hijack and route leak events for watched ASNs on Cloudflare Radar, then
# recompute watchlist matches. Each lookup runs only when its connector is
# enabled in the profile config.yaml (both ship off for licence terms), and
# only the watched domains go to crt.sh and only the watched ASNs go to Radar.
# Every query is written to the audit log first.
#
# Hermes runs this file from $HERMES_HOME/scripts with a sanitised environment.
# Do not read the profile .env. Radar needs CLOUDFLARE_RADAR_API_TOKEN in the
# job environment; without it the Radar part is skipped with a warning.
# stdout is delivered verbatim.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=_cyberau_lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/_cyberau_lib.sh"
require_cli 'watchlist lookups'
run_cli 'watchlist lookups failed' store watchlist run --crtsh --radar \
  --profile-config "${profile}/config.yaml"
printf 'watchlist lookups ok\n'
