#!/usr/bin/env bash
# Hourly: recompute watchlist matches against the current store and record the
# run in routine_state for the briefing. Matches whose store row expired are
# removed. Local only: no watched value leaves the machine. The daily
# cyberau_watchlist_lookups.sh job does the crt.sh and Radar lookups.
# A fresh install with no watchlists.yaml succeeds and does nothing.
#
# Hermes runs this file from $HERMES_HOME/scripts with a sanitised environment.
# Do not read the profile .env. stdout is delivered verbatim.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=_cyberau_lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/_cyberau_lib.sh"
require_cli 'watchlist'
run_cli 'watchlist failed' store watchlist run
printf 'watchlist ok\n'
