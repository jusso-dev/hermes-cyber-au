#!/bin/sh
# One command from a bare Linux, macOS or WSL2 machine to a cyber-au profile.
# Hermes 0.22.2 profile install does not accept github.com/owner/repo@ref
# (it shallow-clones the default branch). A requested ref is cloned first,
# then installed from that directory.
set -eu

PROFILE=cyber-au
REF=
NO_HERMES_INSTALL=0
OFFLINE=0
NONINTERACTIVE=0
YES=0
ALLOW_ROOT=0

HERMES_INSTALL_URL=https://hermes-agent.nousresearch.com/install.sh
REPO_URL=https://github.com/jusso-dev/hermes-cyber-au.git

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Install Hermes (unless it is already there), install the cyber-au profile,
and bootstrap connectors.

Options:
  --profile <name>       Profile name (default: cyber-au, or CYBERAU_PROFILE)
  --ref <tag|sha>        Git ref to install (or CYBERAU_REF). Offline uses the
                         local checkout only when HEAD is already that ref.
  --no-hermes-install    Do not run the upstream Hermes installer
  --offline              Install from this checkout. No network calls.
  --non-interactive      Do not prompt
  --yes                  Answer yes to the Hermes installer prompt
  --allow-root           Permit root. Meant for CI images.
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
    --profile=*)
      PROFILE=${1#--profile=}
      [ -n "$PROFILE" ] || die "missing value for --profile"
      shift
      ;;
    --ref)
      need_value "$@"
      REF=$2
      shift 2
      ;;
    --ref=*)
      REF=${1#--ref=}
      [ -n "$REF" ] || die "missing value for --ref"
      shift
      ;;
    --no-hermes-install)
      NO_HERMES_INSTALL=1
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
    --allow-root)
      ALLOW_ROOT=1
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
if [ -n "${CYBERAU_REF:-}" ]; then
  REF=$CYBERAU_REF
fi

OS_NAME=$(uname -s)
ARCH_NAME=$(uname -m)
case $OS_NAME in
  Linux|Darwin) ;;
  *)
    die "This installer supports Linux, macOS and WSL2. Detected $OS_NAME $ARCH_NAME."
    ;;
esac
if [ -r /proc/version ] && grep -qi microsoft /proc/version; then
  printf '%s\n' "Detected WSL ($ARCH_NAME)."
else
  printf '%s\n' "Detected $OS_NAME $ARCH_NAME."
fi

if [ "$(id -u)" -eq 0 ] && [ "$ALLOW_ROOT" -ne 1 ]; then
  die "Refusing to run as root. Re-run as a normal user, or pass --allow-root."
fi

unset CDPATH
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
CHECKOUT=
if [ -f "$REPO_ROOT/distribution.yaml" ]; then
  CHECKOUT=$REPO_ROOT
fi

hermes_install_display() {
  if [ -n "${HERMES_INSTALL_CHANNEL:-}" ]; then
    printf '%s\n' "HERMES_INSTALL_CHANNEL=$HERMES_INSTALL_CHANNEL curl -fsSL $HERMES_INSTALL_URL | bash"
  else
    printf '%s\n' "curl -fsSL $HERMES_INSTALL_URL | bash"
  fi
}

run_hermes_installer() {
  # Reached only after the command has been shown and accepted.
  # HERMES_INSTALL_CHANNEL is inherited by the upstream script when set.
  curl -fsSL "$HERMES_INSTALL_URL" | bash
}

ensure_hermes() {
  if command -v hermes >/dev/null 2>&1; then
    return 0
  fi
  display=$(hermes_install_display)
  printf '%s\n' "Hermes is not installed. The upstream installer is:"
  printf '%s\n' "  $display"
  if [ "$OFFLINE" -eq 1 ]; then
    die "--offline will not download Hermes."
  fi
  if [ "$NO_HERMES_INSTALL" -eq 1 ]; then
    die "Install Hermes yourself, or re-run without --no-hermes-install."
  fi
  if [ "$YES" -ne 1 ]; then
    if [ "$NONINTERACTIVE" -eq 1 ] || [ ! -t 0 ]; then
      die "Re-run with --yes to run that installer, or install Hermes yourself."
    fi
    printf 'Run the Hermes installer now? [y/N] '
    read -r answer || die "Stopped before installing Hermes."
    case $answer in
      y|Y|yes|YES) ;;
      *)
        die "Stopped before installing Hermes."
        ;;
    esac
  fi
  run_hermes_installer
  command -v hermes >/dev/null 2>&1 || die "The Hermes installer finished but hermes is not on PATH."
}

read_version() {
  output=$(hermes --version 2>&1) || true
  printf '%s\n' "$output" | awk 'match($0, /[0-9]+\.[0-9]+\.[0-9]+/) { print substr($0, RSTART, RLENGTH); exit }'
}

read_requires() {
  manifest=$1
  awk '
    $1 == "hermes_requires:" {
      gsub(/["'\'']/, "", $2)
      if (match($2, /^(>=|<=|==|>|<|=)/)) {
        op = substr($2, RSTART, RLENGTH)
        ver = substr($2, RLENGTH + 1)
      } else {
        op = ">="
        ver = $2
      }
      printf "%s %s\n", op, ver
      exit
    }
  ' "$manifest"
}

version_ok() {
  current=$1
  op=$2
  required=$3
  awk -v cur="$current" -v op="$op" -v req="$required" 'BEGIN {
    split(cur, a, ".")
    split(req, b, ".")
    cmp = 0
    for (i = 1; i <= 3; i++) {
      av = a[i] + 0
      bv = b[i] + 0
      if (av < bv) { cmp = -1; break }
      if (av > bv) { cmp = 1; break }
    }
    ok = 0
    if (op == ">=" && cmp >= 0) ok = 1
    if (op == ">" && cmp > 0) ok = 1
    if (op == "<=" && cmp <= 0) ok = 1
    if (op == "<" && cmp < 0) ok = 1
    if ((op == "==" || op == "=") && cmp == 0) ok = 1
    exit ok ? 0 : 1
  }'
}

check_hermes_version() {
  manifest=$1
  [ -f "$manifest" ] || die "No distribution.yaml at $manifest"
  spec=$(read_requires "$manifest")
  [ -n "$spec" ] || die "distribution.yaml has no hermes_requires."
  op=$(printf '%s\n' "$spec" | awk '{ print $1 }')
  required=$(printf '%s\n' "$spec" | awk '{ print $2 }')
  current=$(read_version)
  [ -n "$current" ] || die "Could not read a version from hermes --version."
  if ! version_ok "$current" "$op" "$required"; then
    die "This distribution requires Hermes $op$required, but you have $current."
  fi
  printf '%s\n' "Hermes $current satisfies $op$required."
}

profile_config_path() {
  hermes -p "$PROFILE" config path 2>/dev/null | awk 'NF { line = $0 } END { print line }'
}

profile_ready() {
  config_path=$(profile_config_path) || config_path=
  [ -n "$config_path" ] || return 1
  [ -f "$config_path" ]
}

clone_at_ref() {
  dest=$1
  ref=$2
  # stdout stays clean: the caller captures only the directory path.
  git init "$dest" >&2
  git -C "$dest" remote add origin "$REPO_URL" >&2
  git -C "$dest" fetch --depth 1 origin "$ref" >&2
  git -C "$dest" checkout --detach FETCH_HEAD >&2
}

resolve_source() {
  if [ "$OFFLINE" -eq 1 ]; then
    [ -n "$CHECKOUT" ] || die "--offline needs the installer to be inside a cyber-au checkout."
    if [ -n "$REF" ]; then
      head=$(git -C "$CHECKOUT" rev-parse HEAD 2>/dev/null || true)
      if [ "$head" != "$REF" ]; then
        die "--offline cannot fetch $REF. The local checkout is ${head:-unknown}."
      fi
    fi
    printf '%s\n' "$CHECKOUT"
    return 0
  fi
  if [ -z "$REF" ] && [ -n "$CHECKOUT" ]; then
    printf '%s\n' "$CHECKOUT"
    return 0
  fi
  dest=$(mktemp -d)
  CLONE_DIR=$dest
  export GIT_TERMINAL_PROMPT=0
  if [ -n "$REF" ]; then
    clone_at_ref "$dest" "$REF"
  else
    git clone --depth 1 "$REPO_URL" "$dest" >&2
  fi
  printf '%s\n' "$dest"
}

install_profile() {
  source_dir=$1
  if [ "$YES" -eq 1 ] || [ "$NONINTERACTIVE" -eq 1 ]; then
    hermes profile install "$source_dir" --name "$PROFILE" --alias --yes
  else
    hermes profile install "$source_dir" --name "$PROFILE" --alias
  fi
}

run_bootstrap() {
  script=$1
  extra=
  if [ "$OFFLINE" -eq 1 ]; then
    extra="$extra --offline"
  fi
  if [ "$NONINTERACTIVE" -eq 1 ]; then
    extra="$extra --non-interactive"
  fi
  if [ "$YES" -eq 1 ]; then
    extra="$extra --yes"
  fi
  set -f
  # shellcheck disable=SC2086
  "$script" --profile "$PROFILE" $extra
  set +f
}

bootstrap_script() {
  if [ -n "${SOURCE:-}" ] && [ -f "$SOURCE/install/bootstrap.sh" ]; then
    printf '%s\n' "$SOURCE/install/bootstrap.sh"
    return 0
  fi
  if [ -f "$SCRIPT_DIR/bootstrap.sh" ]; then
    printf '%s\n' "$SCRIPT_DIR/bootstrap.sh"
    return 0
  fi
  config_path=$(profile_config_path || true)
  if [ -n "$config_path" ]; then
    saved=$(dirname "$config_path")/plugin-data/cyber-au/install/bootstrap.sh
    if [ -f "$saved" ]; then
      printf '%s\n' "$saved"
      return 0
    fi
  fi
  die "bootstrap.sh was not found. Re-run from a checkout, or allow a network clone."
}

CLONE_DIR=
trap 'if [ -n "$CLONE_DIR" ]; then rm -rf "$CLONE_DIR"; fi' EXIT INT TERM

ensure_hermes

SOURCE=
if profile_ready; then
  printf '%s\n' "Profile $PROFILE is already installed. Running bootstrap."
  if [ -n "$CHECKOUT" ] && [ -f "$CHECKOUT/distribution.yaml" ]; then
    check_hermes_version "$CHECKOUT/distribution.yaml"
  else
    config_path=$(profile_config_path)
    check_hermes_version "$(dirname "$config_path")/distribution.yaml"
  fi
else
  SOURCE=$(resolve_source)
  check_hermes_version "$SOURCE/distribution.yaml"
  install_profile "$SOURCE"
fi

run_bootstrap "$(bootstrap_script)"
