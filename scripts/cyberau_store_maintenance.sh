#!/usr/bin/env bash
# Weekly backup, retention compaction, and vacuum.
#
# Hermes runs this file from $HERMES_HOME/scripts with a sanitised environment.
# Do not read the profile .env. stdout is delivered verbatim.
#
# Backup runs first so a failed compaction still leaves a copy.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=_cyberau_lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/_cyberau_lib.sh"
require_cli 'store maintenance'
run_cli 'store maintenance failed at backup' store backup
run_cli 'store maintenance failed at retention' store compact
run_cli 'store maintenance failed at vacuum' store vacuum
python3 "$script_dir/cyberau_cleanup.py" --profile-home "$profile" --apply
printf 'store maintenance ok: backup, retention, vacuum\n'
