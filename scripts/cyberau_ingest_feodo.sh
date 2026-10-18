#!/usr/bin/env bash
# Refresh one feed into the intel store: Feodo Tracker botnet C2 blocklist (abuse.ch, keyless).
# Hermes runs this from $HERMES_HOME/scripts with a sanitised environment.
# Membership feeds drop entries the publisher withdrew; see cyberau_ingest.sh.
set -euo pipefail
unset CDPATH
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
exec bash "$script_dir/cyberau_ingest.sh" feodo
