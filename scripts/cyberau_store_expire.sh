#!/usr/bin/env bash
# Nightly: fold old observations into counters and drop feed advisories and
# EPSS history older than cyber_au.store.feed_retention_days (default 180).
#
# Hermes runs this file from $HERMES_HOME/scripts with a sanitised environment.
# Do not read the profile .env. stdout is delivered verbatim.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=_cyberau_lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/_cyberau_lib.sh"
require_cli 'store expiry'
run_cli 'store expiry failed' store compact
printf 'store expiry ok\n'
