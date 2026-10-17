#!/bin/sh
# Idempotent cyber-au profile bootstrap. Safe to run more than once.
# hermes cyber-au doctor and the intel store are separate tickets. When those
# commands are not in this checkout, this script says so and continues.
set -eu

PROFILE=cyber-au
OFFLINE=0
NONINTERACTIVE=0
YES=0
# Flags install.sh and CI pass through. Bootstrap does not prompt.
: "${NONINTERACTIVE}" "${YES}"

usage() {
  cat <<'EOF'
Usage: bootstrap.sh [options]

Prepare an installed cyber-au profile: connector venv, mcp_servers, plugin
enable, and a local intel store when that command exists.

Options:
  --profile <name>     Profile name (default: cyber-au)
  --offline            Do not contact the network (uv sync --offline)
  --non-interactive    Do not prompt
  --yes                Accepted for callers that pass it through
  -h, --help           Show this help
EOF
}

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

need_value() {
  if [ $# -lt 2 ] || [ -z "$2" ]; then
    die "missing value for $1"
  fi
}

while [ $# -gt 0 ]; do
  case $1 in
    --profile)
      need_value "$@"
      PROFILE=$2
      shift 2
      ;;
    --profile=*)
      PROFILE=${1#--profile=}
      [ -n "$PROFILE" ] || die "missing value for --profile"
      shift
      ;;
    --offline)
      OFFLINE=1
      shift
      ;;
    --non-interactive)
      NONINTERACTIVE=1
      shift
      ;;
    --yes)
      YES=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

if [ -n "${CYBERAU_PROFILE:-}" ]; then
  PROFILE=$CYBERAU_PROFILE
fi

unset CDPATH
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

profile_home() {
  config_path=$(hermes -p "$PROFILE" config path 2>/dev/null) || config_path=
  if [ -n "$config_path" ]; then
    # hermes config path prints the config file. There is no --home flag.
    dirname "$config_path"
    return 0
  fi
  printf '%s\n' "$HOME/.hermes/profiles/$PROFILE"
}

PROFILE_HOME=$(profile_home)
[ -f "$PROFILE_HOME/mcp/pyproject.toml" ] ||
  die "The profile connector project is missing at $PROFILE_HOME/mcp. Install the profile before bootstrap."
mkdir -p "$PROFILE_HOME/plugin-data/cyber-au"

if [ -f "$PROFILE_HOME/mcp/servers.yaml" ]; then
  SERVERS_YAML=$PROFILE_HOME/mcp/servers.yaml
elif [ -f "$REPO_ROOT/mcp/servers.yaml" ]; then
  SERVERS_YAML=$REPO_ROOT/mcp/servers.yaml
else
  die "mcp/servers.yaml was not found in the profile or the checkout"
fi

printf '%s\n' "Bootstrapping profile $PROFILE at $PROFILE_HOME."

# Keep a copy so a later install.sh that is not inside a checkout can re-run bootstrap.
saved_install=$PROFILE_HOME/plugin-data/cyber-au/install
mkdir -p "$saved_install"
saved_real=$(cd -- "$saved_install" && pwd)
script_real=$(cd -- "$SCRIPT_DIR" && pwd)
if [ "$script_real" != "$saved_real" ]; then
  cp "$SCRIPT_DIR/bootstrap.sh" "$saved_install/bootstrap.sh"
  cp "$SCRIPT_DIR/render_config.py" "$saved_install/render_config.py"
  chmod +x "$saved_install/bootstrap.sh"
fi

if ! command -v uv >/dev/null 2>&1; then
  die "uv is required to build the connector environment. Install uv, then re-run bootstrap."
fi

if [ "$OFFLINE" -eq 1 ]; then
  uv sync --project "$PROFILE_HOME/mcp" --frozen --offline
else
  uv sync --project "$PROFILE_HOME/mcp" --frozen
fi

PYTHON=${CYBERAU_PYTHON:-}
if [ -z "$PYTHON" ] && [ -x "$PROFILE_HOME/mcp/.venv/bin/python" ]; then
  PYTHON=$PROFILE_HOME/mcp/.venv/bin/python
fi
if [ -z "$PYTHON" ]; then
  PYTHON=$(command -v python3) || die "python3 is required to render config.yaml"
fi

"$PYTHON" "$SCRIPT_DIR/render_config.py" \
  --profile-home "$PROFILE_HOME" \
  --servers "$SERVERS_YAML" \
  --config "$PROFILE_HOME/config.yaml" \
  --env-file "$PROFILE_HOME/.env" \
  --managed "$PROFILE_HOME/plugin-data/cyber-au/managed-servers.json" \
  --status "$PROFILE_HOME/plugin-data/cyber-au/bootstrap-status.json"

if ! hermes -p "$PROFILE" plugins enable cyber-au; then
  if [ ! -f "$PROFILE_HOME/plugins/cyber-au/plugin.yaml" ] && [ ! -f "$REPO_ROOT/plugins/cyber-au/plugin.yaml" ]; then
    printf '%s\n' "The cyber-au plugin skeleton is not in this checkout. Plugin enable was skipped. That ticket is separate." >&2
  else
    die "Could not enable the cyber-au plugin."
  fi
fi

init_store() {
  bin=$PROFILE_HOME/mcp/.venv/bin/cyberau-mcp
  if [ ! -x "$bin" ]; then
    printf '%s\n' "cyberau-mcp store init is not available yet. The intel store is a separate ticket." >&2
    return 0
  fi
  set +e
  "$bin" store init >/dev/null 2>&1
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf '%s\n' "Initialised the intel store."
    load_snapshot kev "$PROFILE_HOME/mcp/cisa-kev/data/kev.json"
    load_snapshot ism "$PROFILE_HOME/mcp/asd-ism/data"
    load_snapshot e8 "$PROFILE_HOME/mcp/asd-e8/data"
    load_snapshot attack "$PROFILE_HOME/mcp/attack/data"
    return 0
  fi
  printf '%s\n' "cyberau-mcp store init is not available yet. The intel store is a separate ticket." >&2
}

load_snapshot() {
  name=$1
  path=$2
  if [ ! -e "$path" ]; then
    return 0
  fi
  "$PROFILE_HOME/mcp/.venv/bin/cyberau-mcp" store load "$name" "$path"
}

init_store

run_doctor() {
  if [ -f "$REPO_ROOT/plugins/cyber-au/cli.py" ] && grep -q doctor "$REPO_ROOT/plugins/cyber-au/cli.py"; then
    if [ "$OFFLINE" -eq 1 ]; then
      hermes -p "$PROFILE" cyber-au doctor --offline
    else
      hermes -p "$PROFILE" cyber-au doctor
    fi
    return 0
  fi
  printf '%s\n' "hermes cyber-au doctor is not in this checkout. The doctor check is a separate ticket." >&2
}

run_doctor

printf '%s\n' "Bootstrap finished for $PROFILE."
