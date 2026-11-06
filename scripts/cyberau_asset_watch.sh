#!/usr/bin/env bash
# Match the locally refreshed CISA KEV snapshot against the local software inventory.
# This no-agent job does not make network requests or deliver notifications.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=_cyberau_lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/_cyberau_lib.sh"

inventory="${data_dir}/assets.yaml"
snapshot="${data_dir}/snapshots/kev.json"
output="${data_dir}/software-watch.json"
require_cli 'software watch'
if [[ ! -f "$inventory" ]]; then
  printf 'software watch skipped: asset inventory is not configured\n'
  exit 0
fi
if [[ ! -f "$snapshot" ]]; then
  printf 'software watch skipped: CISA KEV snapshot is not available\n'
  exit 0
fi
if ! output_text=$("$bin" assets check --inventory "$inventory" --kev "$snapshot" --output "$output" 2>&1); then
  die_first_line 'software watch failed' "$output_text" ''
fi
printf 'software watch ok: %s\n' "${output_text:0:200}"
