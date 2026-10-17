#!/bin/sh
# Weekly no-agent job. Backup first, then vacuum.
# Vacuum folds observations older than cyber_au.store.retention_days into
# indicator counters and reclaims free pages. Advisories are kept.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ -x "$root/mcp/.venv/bin/cyberau-mcp" ]; then
  bin="$root/mcp/.venv/bin/cyberau-mcp"
elif command -v cyberau-mcp >/dev/null 2>&1; then
  bin=$(command -v cyberau-mcp)
else
  echo "cyberau-mcp is not installed" >&2
  exit 1
fi

if [ -z "${CYBERAU_DATA_DIR:-}" ]; then
  CYBERAU_DATA_DIR="$root/plugin-data/cyber-au"
  export CYBERAU_DATA_DIR
fi

"$bin" store backup
"$bin" store vacuum
