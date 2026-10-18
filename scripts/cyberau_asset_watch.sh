#!/usr/bin/env bash
# Match the locally refreshed CISA KEV snapshot against the local software inventory.
# This no-agent job does not make network requests or deliver notifications.
set -euo pipefail
unset CDPATH

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ -n ${HERMES_HOME:-} ]]; then
  profile=$HERMES_HOME
else
  profile=$(cd -- "$script_dir/.." && pwd)
fi

bin="${profile}/mcp/.venv/bin/cyberau-mcp"
data_dir="${profile}/plugin-data/cyber-au"
inventory="${data_dir}/assets.yaml"
snapshot="${data_dir}/snapshots/kev.json"
output="${data_dir}/software-watch.json"
if [[ ! -x "$bin" ]]; then
  printf 'software watch failed: cyberau-mcp is not installed under mcp/.venv\n'
  exit 1
fi
if [[ ! -f "$inventory" ]]; then
  printf 'software watch skipped: asset inventory is not configured\n'
  exit 0
fi
if [[ ! -f "$snapshot" ]]; then
  printf 'software watch skipped: CISA KEV snapshot is not available\n'
  exit 0
fi
if ! output_text=$("$bin" assets check --inventory "$inventory" --kev "$snapshot" --output "$output" 2>&1); then
  line=${output_text%%$'\n'*}
  printf 'software watch failed: %s\n' "${line:0:200}"
  exit 1
fi
printf 'software watch ok: %s\n' "${output_text:0:200}"
