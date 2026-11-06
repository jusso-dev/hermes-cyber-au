#!/usr/bin/env bash
# Nightly: recompute watchlist matches against the current store. Matches whose
# store row expired are removed. Watched domains are sent only to crt.sh.
# A fresh install with no watchlists.yaml succeeds and does nothing.
#
# Hermes runs this file from $HERMES_HOME/scripts with a sanitised environment.
# Do not read the profile .env. stdout is delivered verbatim.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=_cyberau_lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/_cyberau_lib.sh"
require_cli 'watchlist'
run_cli 'watchlist failed' store watchlist run --crtsh
printf 'watchlist ok\n'
