#!/usr/bin/env bash
# Refresh one feed into the intel store: the custom RSS and Atom feeds and feed packs
# turned on in watchlists.yaml. Nothing is fetched when none are turned on.
# Hermes runs this from $HERMES_HOME/scripts with a sanitised environment.
set -euo pipefail
unset CDPATH
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
exec bash "$script_dir/cyberau_ingest.sh" custom
