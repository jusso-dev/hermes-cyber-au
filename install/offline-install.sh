#!/bin/sh
# Install cyber-au from an unpacked offline bundle. No network calls.
#
# Runs from the bundle root (tools/release/offline_bundle.py copies this file to
# install-offline.sh). Steps:
#   1. check every file against SHA256SUMS
#   2. install the profile with install.sh --offline --skip-bootstrap
#   3. build mcp/.venv with pip install --no-index --find-links wheels/<platform>
#   4. install the plugin's Hermes-side dependencies the same way
#   5. set CYBERAU_OFFLINE=1 in the profile .env
#   6. run bootstrap.sh --offline --venv-ready
# Hermes itself must already be installed: this script will not download it.
set -eu

PROFILE=${CYBERAU_PROFILE:-cyber-au}
PROFILE_HOME=
PLATFORM=
NONINTERACTIVE=0
YES=0
ALLOW_ROOT=0
SKIP_VERIFY=0

usage() {
  cat <<'EOF'
Usage: install-offline.sh [options]

Install cyber-au from this offline bundle with no network access. Hermes must
already be installed. The connector venv needs a Python version the bundle was
built for (requirements/python-versions.txt, 3.12 by default).

Options:
  --profile <name>       Profile name (default: CYBERAU_PROFILE, else cyber-au)
  --profile-home <path>  Install into this profile directory (skips hermes lookup)
  --platform <name>      Wheel directory to use (default: from uname -m)
  --non-interactive      Do not prompt
  --yes                  Answer yes to prompts
  --allow-root           Permit root. Meant for CI images.
  --skip-verify          Do not check SHA256SUMS (not recommended)
  -h, --help             Show this help
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
    --platform)
      need_value "$@"
      PLATFORM=$2
      shift 2
      ;;
    --non-interactive)
      NONINTERACTIVE=1
      shift
      ;;
    --yes)
      YES=1
      shift
      ;;
    --allow-root)
      ALLOW_ROOT=1
      shift
      ;;
    --skip-verify)
      SKIP_VERIFY=1
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

case $PROFILE in
  ''|-*|*[!A-Za-z0-9._-]*)
    die "Invalid profile name: $PROFILE. Use letters, digits, dot, dash and underscore."
    ;;
esac

unset CDPATH
BUNDLE=$(cd -- "$(dirname -- "$0")" && pwd)
[ -f "$BUNDLE/bundle.json" ] || die "bundle.json is missing. Run this script from an unpacked offline bundle."
[ -f "$BUNDLE/profile/distribution.yaml" ] || die "profile/distribution.yaml is missing from the bundle."

# Belt and braces: nothing below should reach the network, and pip and uv are
# told so directly as well.
CYBERAU_OFFLINE=1
PIP_NO_INDEX=1
PIP_DISABLE_PIP_VERSION_CHECK=1
UV_OFFLINE=1
UV_NO_INDEX=1
export CYBERAU_OFFLINE PIP_NO_INDEX PIP_DISABLE_PIP_VERSION_CHECK UV_OFFLINE UV_NO_INDEX

if [ "$(id -u)" -eq 0 ] && [ "$ALLOW_ROOT" -ne 1 ]; then
  die "Refusing to run as root. Re-run as a normal user, or pass --allow-root."
fi

verify_sums() {
  if [ "$SKIP_VERIFY" -eq 1 ]; then
    printf '%s\n' "Skipping SHA256SUMS check (--skip-verify)." >&2
    return 0
  fi
  [ -f "$BUNDLE/SHA256SUMS" ] || die "SHA256SUMS is missing. The bundle is incomplete."
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$BUNDLE" && sha256sum --quiet --strict -c SHA256SUMS) ||
      die "SHA256SUMS check failed. The bundle was changed or is incomplete. Nothing was installed."
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$BUNDLE" && shasum -a 256 --quiet --strict -c SHA256SUMS) ||
      die "SHA256SUMS check failed. The bundle was changed or is incomplete. Nothing was installed."
  else
    die "Neither sha256sum nor shasum is available to check the bundle."
  fi
  printf '%s\n' "Bundle files match SHA256SUMS."
}

pick_platform() {
  if [ -n "$PLATFORM" ]; then
    printf '%s\n' "$PLATFORM"
    return 0
  fi
  case $(uname -m) in
    x86_64|amd64) printf '%s\n' linux_x86_64 ;;
    aarch64|arm64) printf '%s\n' linux_aarch64 ;;
    *) return 1 ;;
  esac
}

pick_python() {
  versions=$(tr -s ' \n' ' ' <"$BUNDLE/requirements/python-versions.txt")
  if [ -n "${CYBERAU_PYTHON:-}" ]; then
    printf '%s\n' "$CYBERAU_PYTHON"
    return 0
  fi
  for version in $versions; do
    for candidate in "python$version" python3; do
      command -v "$candidate" >/dev/null 2>&1 || continue
      found=$("$candidate" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null) || continue
      if [ "$found" = "$version" ]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    done
  done
  return 1
}

profile_config_path() {
  hermes -p "$PROFILE" config path 2>/dev/null | awk 'NF { line = $0 } END { print line }'
}

resolve_profile_home() {
  if [ -n "$PROFILE_HOME" ]; then
    return 0
  fi
  config_path=$(profile_config_path) || config_path=
  [ -n "$config_path" ] || die "Could not find the profile directory for $PROFILE. Pass --profile-home."
  PROFILE_HOME=$(dirname "$config_path")
}

install_profile() {
  if [ -n "$PROFILE_HOME" ] && [ -f "$PROFILE_HOME/distribution.yaml" ]; then
    printf '%s\n' "Profile files already present at $PROFILE_HOME."
    return 0
  fi
  if [ -n "$PROFILE_HOME" ]; then
    # No Hermes profile command: copy the profile tree directly.
    mkdir -p "$PROFILE_HOME"
    cp -R "$BUNDLE/profile/." "$PROFILE_HOME/"
    return 0
  fi
  extra=
  [ "$NONINTERACTIVE" -eq 1 ] && extra="$extra --non-interactive"
  [ "$YES" -eq 1 ] && extra="$extra --yes"
  [ "$ALLOW_ROOT" -eq 1 ] && extra="$extra --allow-root"
  set -f
  # shellcheck disable=SC2086
  sh "$BUNDLE/profile/install/install.sh" --profile "$PROFILE" --offline \
    --no-hermes-install --skip-bootstrap $extra
  set +f
}

build_venv() {
  wheels=$1
  python=$2
  mcp=$PROFILE_HOME/mcp
  [ -f "$mcp/pyproject.toml" ] || die "$mcp/pyproject.toml is missing. The profile install did not finish."
  if [ -d "$mcp/.venv" ]; then
    printf '%s\n' "Replacing $mcp/.venv."
    rm -rf "$mcp/.venv"
  fi
  "$python" -m venv "$mcp/.venv" || die "Could not create $mcp/.venv with $python."
  venv_python=$mcp/.venv/bin/python
  pip_install() {
    "$venv_python" -m pip install --quiet --no-index --find-links "$wheels" "$@"
  }
  pip_install --require-hashes -r "$BUNDLE/requirements/runtime.txt" ||
    die "Installing the locked runtime wheels failed. Check that $wheels matches this machine."
  pip_install --require-hashes -r "$BUNDLE/requirements/build.txt" ||
    die "Installing the build backend wheels failed."
  set --
  while IFS= read -r member; do
    [ -n "$member" ] || continue
    set -- "$@" -e "$mcp/$member"
  done <"$BUNDLE/requirements/workspace.txt"
  [ $# -gt 0 ] || die "requirements/workspace.txt lists no connectors."
  pip_install --no-deps --no-build-isolation "$@" ||
    die "Installing the connector packages failed."
  # bootstrap.sh and doctor read this stamp to confirm the venv matches the lock.
  "$venv_python" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
    "$mcp/uv.lock" >"$mcp/.venv/.cyberau-lock-sha256"
}

install_plugin_dependencies() {
  wheels=$1/plugin
  [ -s "$BUNDLE/requirements/plugin.txt" ] || return 0
  hermes_py=${HERMES_PYTHON:-}
  if [ -z "$hermes_py" ]; then
    hermes_bin=$(command -v hermes) || return 0
    hermes_py=$(dirname -- "$hermes_bin")/python
  fi
  if [ ! -x "$hermes_py" ]; then
    printf '%s\n' "Could not find the Python that runs Hermes. Install requirements/plugin.txt into it from $wheels by hand." >&2
    return 0
  fi
  if "$hermes_py" -m pip --version >/dev/null 2>&1; then
    "$hermes_py" -m pip install --quiet --no-index --find-links "$wheels" -r "$BUNDLE/requirements/plugin.txt" && return 0
  elif command -v uv >/dev/null 2>&1; then
    uv pip install --quiet --offline --no-index --find-links "$wheels" --python "$hermes_py" \
      -r "$BUNDLE/requirements/plugin.txt" && return 0
  fi
  printf '%s\n' "Could not install the plugin dependencies into $hermes_py. Install requirements/plugin.txt from $wheels by hand." >&2
}

copy_snapshots() {
  # intel/ is not distribution-owned, so Hermes does not copy it into the profile.
  src=$BUNDLE/profile/intel/snapshots
  [ -d "$src" ] || return 0
  mkdir -p "$PROFILE_HOME/intel/snapshots"
  for file in "$src"/public-*.sqlite.zst; do
    [ -f "$file" ] || continue
    cp "$file" "$PROFILE_HOME/intel/snapshots/"
  done
}

mark_offline() {
  # render_config.py copies CYBERAU_OFFLINE=1 from the profile .env onto every
  # connector, and Hermes loads it for the plugin and doctor.
  env_file=$PROFILE_HOME/.env
  if [ -f "$env_file" ] && grep -q '^CYBERAU_OFFLINE=' "$env_file"; then
    return 0
  fi
  if [ ! -f "$env_file" ]; then
    (umask 077 && : >"$env_file")
  fi
  printf '%s\n' 'CYBERAU_OFFLINE=1' >>"$env_file"
  chmod 600 "$env_file"
  printf '%s\n' "Set CYBERAU_OFFLINE=1 in $env_file."
}

verify_sums

PLATFORM=$(pick_platform) || die "No wheels for $(uname -m). Pass --platform with a directory under $BUNDLE/wheels."
WHEELS=$BUNDLE/wheels/$PLATFORM
[ -d "$WHEELS" ] || die "This bundle has no wheels for $PLATFORM. Build one with --platform $PLATFORM."
[ -f "$BUNDLE/requirements/python-versions.txt" ] || die "requirements/python-versions.txt is missing from the bundle."
PYTHON=$(pick_python) || die "This bundle has wheels for Python $(tr -s '\n' ' ' <"$BUNDLE/requirements/python-versions.txt")only. Install one of those, or set CYBERAU_PYTHON."
printf '%s\n' "Installing offline with $PLATFORM wheels and $("$PYTHON" -V 2>&1)."

if [ -z "$PROFILE_HOME" ]; then
  command -v hermes >/dev/null 2>&1 || die "Hermes is not installed. Install Hermes first; this script will not download it."
fi
install_profile
resolve_profile_home
printf '%s\n' "Profile directory: $PROFILE_HOME"

copy_snapshots
build_venv "$WHEELS" "$PYTHON"
install_plugin_dependencies "$WHEELS"
mark_offline

boot=
[ "$NONINTERACTIVE" -eq 1 ] && boot="$boot --non-interactive"
[ "$YES" -eq 1 ] && boot="$boot --yes"
set -f
# shellcheck disable=SC2086
sh "$PROFILE_HOME/install/bootstrap.sh" --profile "$PROFILE" --profile-home "$PROFILE_HOME" \
  --offline --venv-ready $boot
set +f

printf '%s\n' "Offline install finished for $PROFILE."
printf '%s\n' "Live-only sources report unavailable while CYBERAU_OFFLINE=1. Refresh data with: cyberau-mcp datapack import <pack>"
