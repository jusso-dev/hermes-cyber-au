#!/bin/sh
# Idempotent post-install and post-update step.
# Syncs the MCP virtualenv, patches mcp_servers when the renderer is present,
# and applies intel store migrations.
set -eu

usage() {
  echo "usage: bootstrap.sh [--profile <name>] [--profile-home <path>]" >&2
  exit 2
}

PROFILE="${CYBERAU_PROFILE:-cyber-au}"
PROFILE_HOME=""

# The updater needs Python 3.11 or newer. A bare python3 can be older, as on macOS.
PYTHON=""
for candidate in python3 python3.13 python3.12 python3.11; do
  if command -v "$candidate" >/dev/null 2>&1 &&
    "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    PYTHON="$candidate"
    break
  fi
done
if [ -z "$PYTHON" ]; then
  echo "bootstrap.sh needs Python 3.11 or newer on PATH" >&2
  exit 1
fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      [ "$#" -ge 2 ] || usage
      PROFILE="$2"
      shift 2
      ;;
    --profile-home)
      [ "$#" -ge 2 ] || usage
      PROFILE_HOME="$2"
      shift 2
      ;;
    --non-interactive|--offline|--yes)
      shift
      ;;
    *)
      usage
      ;;
  esac
done

if [ -z "$PROFILE_HOME" ] && command -v hermes >/dev/null 2>&1; then
  PROFILE_HOME=$(hermes -p "$PROFILE" config path --home 2>/dev/null || true)
fi

if [ -z "$PROFILE_HOME" ]; then
  PROFILE_HOME="${HOME}/.hermes/profiles/${PROFILE}"
fi

if [ -f "$PROFILE_HOME/mcp/pyproject.toml" ] && command -v uv >/dev/null 2>&1; then
  uv sync --project "$PROFILE_HOME/mcp" --frozen
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

if [ -f "$ROOT/install/render_config.py" ]; then
  "$PYTHON" "$ROOT/install/render_config.py" --profile "$PROFILE" --profile-home "$PROFILE_HOME"
fi

exec "$PYTHON" "$ROOT/plugins/cyber-au/cli.py" migrate --profile-home "$PROFILE_HOME"
