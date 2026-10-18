#!/bin/sh
# Idempotent cyber-au profile bootstrap. Safe to run more than once.
# Connector reference data stays in its source directory. The intel store
# holds observations, advisories and vulnerabilities, not framework controls.
set -eu

PROFILE=${CYBERAU_PROFILE:-cyber-au}
PROFILE_HOME=""
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
  --profile <name>       Profile name (default: cyber-au)
  --profile-home <path>  Profile directory (skips hermes lookup)
  --offline              Do not contact the network (uv sync --offline)
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
    --profile-home)
      need_value "$@"
      PROFILE_HOME=$2
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

if [ -z "$PROFILE_HOME" ]; then
  PROFILE_HOME=$(profile_home)
fi

python311() {
  if [ -n "${CYBERAU_PYTHON:-}" ]; then
    printf '%s\n' "$CYBERAU_PYTHON"
    return 0
  fi
  for candidate in python3 python3.13 python3.12 python3.11; do
    if command -v "$candidate" >/dev/null 2>&1 &&
      "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

if [ ! -f "$PROFILE_HOME/mcp/pyproject.toml" ]; then
  PYTHON=$(python311) || die "bootstrap.sh needs Python 3.11 or newer on PATH"
  exec "$PYTHON" "$REPO_ROOT/plugins/cyber-au/cli.py" migrate --profile-home "$PROFILE_HOME"
fi
mkdir -p "$PROFILE_HOME/plugin-data/cyber-au/audit"
chmod 700 "$PROFILE_HOME/plugin-data/cyber-au/audit"
# The store, audit log and connector state live in the profile, as render_config
# tells every server. Without this, store init follows HERMES_HOME instead.
CYBERAU_DATA_DIR=$PROFILE_HOME/plugin-data/cyber-au
export CYBERAU_DATA_DIR

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
  uv sync --project "$PROFILE_HOME/mcp" --all-packages --frozen --offline --no-editable
else
  uv sync --project "$PROFILE_HOME/mcp" --all-packages --frozen --no-editable
fi

# cyber-au doctor compares this stamp with mcp/uv.lock to spot a stale venv.
lock_sha=$("$PROFILE_HOME/mcp/.venv/bin/python" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$PROFILE_HOME/mcp/uv.lock")
printf '%s\n' "$lock_sha" > "$PROFILE_HOME/mcp/.venv/.cyberau-lock-sha256"

PYTHON=${CYBERAU_PYTHON:-}
if [ -z "$PYTHON" ] && [ -x "$PROFILE_HOME/mcp/.venv/bin/python" ]; then
  PYTHON=$PROFILE_HOME/mcp/.venv/bin/python
fi
if [ -z "$PYTHON" ]; then
  PYTHON=$(command -v python3) || die "python3 is required to render config.yaml"
fi

# The cyber-au plugin runs inside the Hermes process, so the python_dependencies
# in plugin.yaml go into Hermes's interpreter, not the connector venv. Without
# PyYAML there the plugin fails to register and `hermes cyber-au` is missing.
install_plugin_dependencies() {
  hermes_py=${HERMES_PYTHON:-}
  if [ -z "$hermes_py" ]; then
    hermes_bin=$(command -v hermes) || return 0
    hermes_py=$(dirname -- "$hermes_bin")/python
  fi
  if [ ! -x "$hermes_py" ]; then
    printf '%s\n' "Could not find the Python that runs Hermes. Install the plugin dependencies from plugins/cyber-au/plugin.yaml into it by hand." >&2
    return 0
  fi
  manifest=$PROFILE_HOME/plugins/cyber-au/plugin.yaml
  [ -f "$manifest" ] || manifest=$REPO_ROOT/plugins/cyber-au/plugin.yaml
  [ -f "$manifest" ] || return 0
  deps=$("$PYTHON" -c 'import sys, yaml; print("\n".join(yaml.safe_load(open(sys.argv[1])).get("python_dependencies") or []))' "$manifest")
  [ -n "$deps" ] || return 0
  offline_flag=
  [ "$OFFLINE" -eq 1 ] && offline_flag=--offline
  printf '%s\n' "$deps" | while IFS= read -r dep; do
    [ -n "$dep" ] || continue
    if ! uv pip install --quiet ${offline_flag:+"$offline_flag"} --python "$hermes_py" "$dep"; then
      printf '%s\n' "Could not install $dep for Hermes. Install it into $hermes_py by hand." >&2
    fi
  done
}

install_plugin_dependencies

"$PYTHON" "$SCRIPT_DIR/render_config.py" \
  --profile-home "$PROFILE_HOME" \
  --servers "$SERVERS_YAML" \
  --config "$PROFILE_HOME/config.yaml" \
  --env-file "$PROFILE_HOME/.env" \
  --managed "$PROFILE_HOME/plugin-data/cyber-au/managed-servers.json" \
  --status "$PROFILE_HOME/plugin-data/cyber-au/bootstrap-status.json"

if ! hermes -p "$PROFILE" plugins enable cyber-au; then
  if [ ! -f "$PROFILE_HOME/plugins/cyber-au/plugin.yaml" ] && [ ! -f "$REPO_ROOT/plugins/cyber-au/plugin.yaml" ]; then
    printf '%s\n' "The cyber-au plugin manifest is missing. Reinstall the distribution." >&2
  else
    die "Could not enable the cyber-au plugin."
  fi
fi

init_store() {
  bin=$PROFILE_HOME/mcp/.venv/bin/cyberau-mcp
  [ -x "$bin" ] || die "cyberau-mcp is missing. Re-run bootstrap to create the connector environment."
  "$bin" store init || die "Could not initialise the intel store. Fix the error above and re-run bootstrap."
  printf '%s\n' "Initialised the intel store."
  kev=$PROFILE_HOME/mcp/cisa-kev/data/kev.json
  if [ -f "$kev" ]; then
    "$bin" store ingest-kev "$kev" || die "Could not load the KEV snapshot. Fix the error above."
  else
    printf '%s\n' "No local KEV snapshot. Run cyberau-mcp refresh --sources kev --store when online."
  fi
  require_reference "$PROFILE_HOME/mcp/asd-ism/data" 'releases.json' ISM
  require_reference "$PROFILE_HOME/mcp/asd-essentials/data" 'e8-maturity-*.json' 'Essential Eight maturity'
  require_reference "$PROFILE_HOME/mcp/asd-essentials/data" 'essentials-*.json' 'Essential Eight guidance'
  printf '%s\n' "ISM and Essential Eight reference files are read by their connectors, not imported as threat intel."
  printf '%s\n' "ATT&CK is fetched by its connector when online; bootstrap does not import an ATT&CK snapshot."
}

require_reference() {
  directory=$1
  pattern=$2
  label=$3
  [ -d "$directory" ] || die "$label reference directory is missing: $directory. Reinstall the distribution."
  for reference in "$directory"/$pattern; do
    [ ! -f "$reference" ] || return 0
  done
  die "$label reference files are missing in $directory. Reinstall the distribution."
}

init_store

run_doctor() {
  if [ -f "$REPO_ROOT/plugins/cyber-au/cli.py" ] && grep -q doctor "$REPO_ROOT/plugins/cyber-au/cli.py"; then
    set +e
    hermes -p "$PROFILE" cyber-au doctor --offline
    set -e
    return 0
  fi
  printf '%s\n' "cyber-au doctor is missing. Reinstall the distribution to restore offline diagnostics." >&2
}

run_doctor

"$PYTHON" "$REPO_ROOT/plugins/cyber-au/cli.py" migrate --profile-home "$PROFILE_HOME" ||
  printf '%s\n' "Store migration was skipped." >&2

printf '%s\n' "Bootstrap finished for $PROFILE."
