#!/usr/bin/env bats
# Argument parsing, root refusal, version gate and idempotence.
# Uses a fake hermes and a fake uv. Does not run a network installer.

setup_file() {
  REPO="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  export REPO
  if ! uv run --project "$REPO/mcp" --offline python -c 'import yaml' >/dev/null 2>&1; then
    uv sync --project "$REPO/mcp" --frozen
  fi
  CYBERAU_REAL_PYTHON="$(uv run --project "$REPO/mcp" python -c 'import sys; print(sys.executable)')"
  export CYBERAU_REAL_PYTHON
}

setup() {
  WORK="$(mktemp -d)"
  export HOME="$WORK/home"
  mkdir -p "$HOME" "$WORK/bin"
  export HERMES_FAKE_LOG="$WORK/hermes.log"
  export UV_LOG="$WORK/uv.log"
  export CURL_LOG="$WORK/curl.log"
  export GIT_LOG="$WORK/git.log"
  export CYBERAU_REPO="$REPO"
  export CYBERAU_PYTHON="$CYBERAU_REAL_PYTHON"
  : >"$HERMES_FAKE_LOG"
  : >"$UV_LOG"
  : >"$CURL_LOG"
  : >"$GIT_LOG"
  install_fake_hermes
  install_fake_uv
  install_fake_curl
  export PATH="$WORK/bin:/usr/bin:/bin"
}

teardown() {
  rm -rf "$WORK"
}

install_fake_hermes() {
  cat >"$WORK/bin/hermes" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${HERMES_FAKE_LOG:?}"
profile=cyber-au
source_dir=
prev=
for arg in "$@"; do
  case $prev in
    -p|--name) profile=$arg ;;
  esac
  if [ "$prev" = "install" ] && [ "${arg#--}" = "$arg" ]; then
    source_dir=$arg
  fi
  prev=$arg
  case $arg in
    --version|-V)
      printf '%s\n' "Hermes Agent ${HERMES_FAKE_VERSION:-0.22.2}"
      exit 0
      ;;
  esac
done
home="$HOME/.hermes/profiles/$profile"
case " $* " in
  *" config path "*)
    printf '%s\n' "$home/config.yaml"
    exit 0
    ;;
  *" plugins enable "*)
    if [ "${HERMES_FAKE_ENABLE_FAIL:-0}" = "1" ]; then
      printf '%s\n' "plugin not found" >&2
      exit 1
    fi
    exit 0
    ;;
  *" cyber-au doctor "*)
    printf '%s\n' "doctor is not implemented" >&2
    exit 1
    ;;
esac
if [ -n "$source_dir" ]; then
  mkdir -p "$home/mcp" "$home/plugins/cyber-au" "$home/plugin-data/cyber-au"
  cp "$source_dir/distribution.yaml" "$home/distribution.yaml"
  cp "$source_dir/config.yaml" "$home/config.yaml"
  cp "$source_dir/mcp/servers.yaml" "$home/mcp/servers.yaml"
  cp "$source_dir/mcp/pyproject.toml" "$home/mcp/pyproject.toml"
  cp "$source_dir/mcp/uv.lock" "$home/mcp/uv.lock"
  cp "$source_dir/mcp/egress-allowlist.yaml" "$home/mcp/egress-allowlist.yaml"
  mkdir -p "$home/mcp/asd-ism/data" "$home/mcp/asd-essentials/data"
  printf '{}\n' > "$home/mcp/asd-ism/data/releases.json"
  printf '{}\n' > "$home/mcp/asd-essentials/data/e8-maturity-test.json"
  printf '{}\n' > "$home/mcp/asd-essentials/data/essentials-test.json"
  if [ "${STORE_FAKE_KEV:-0}" = "1" ]; then
    mkdir -p "$home/mcp/cisa-kev/data"
    printf '{}\n' > "$home/mcp/cisa-kev/data/kev.json"
  fi
  exit 0
fi
printf '%s\n' "unhandled hermes command: $*" >&2
exit 1
EOF
  chmod +x "$WORK/bin/hermes"
}

install_fake_uv() {
  cat >"$WORK/bin/uv" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${UV_LOG:?}"
project=
prev=
for arg in "$@"; do
  if [ "$prev" = "--project" ]; then
    project=$arg
  fi
  prev=$arg
done
[ "$1" = "sync" ] || exit 1
mkdir -p "$project/.venv/bin"
ln -sf "${CYBERAU_REAL_PYTHON:?}" "$project/.venv/bin/python"
printf '%s\n' 'frozen' >"$project/.venv/.cyberau-sync-stamp"
cat >"$project/.venv/bin/cyberau-mcp" <<'STUB'
#!/bin/sh
if [ "${STORE_FAKE_FAIL:-}" = "$2" ]; then
  printf '%s\n' "synthetic store failure: $2" >&2
  exit 7
fi
exit 0
STUB
chmod +x "$project/.venv/bin/cyberau-mcp"
exit 0
EOF
  chmod +x "$WORK/bin/uv"
}

install_fake_curl() {
  cat >"$WORK/bin/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${CURL_LOG:?}"
printf '%s\n' "curl must not run from the installer tests" >&2
exit 99
EOF
  chmod +x "$WORK/bin/curl"
}

install_fake_id_root() {
  cat >"$WORK/bin/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-u" ]; then
  printf '%s\n' 0
  exit 0
fi
exit 1
EOF
  chmod +x "$WORK/bin/id"
}

install_fake_git() {
  cat >"$WORK/bin/git" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${GIT_LOG:?}"
if [ "${1:-}" = "clone" ] || [ "${1:-}" = "fetch" ]; then
  printf '%s\n' "refusing network git $*" >&2
  exit 99
fi
if [ "${1:-}" = "-C" ]; then
  dest=$2
  shift 2
  if [ "${1:-}" = "rev-parse" ]; then
    printf '%s\n' "0123456789abcdef"
    exit 0
  fi
  if [ "${1:-}" = "fetch" ]; then
    exit 0
  fi
  if [ "${1:-}" = "checkout" ]; then
    repo=${CYBERAU_REPO:?}
    mkdir -p "$dest/install" "$dest/mcp" "$dest/plugins/cyber-au"
    cp "$repo/distribution.yaml" "$dest/distribution.yaml"
    cp "$repo/config.yaml" "$dest/config.yaml"
    cp "$repo/install/bootstrap.sh" "$dest/install/bootstrap.sh"
    cp "$repo/install/render_config.py" "$dest/install/render_config.py"
    cp "$repo/mcp/servers.yaml" "$dest/mcp/servers.yaml"
    cp "$repo/mcp/pyproject.toml" "$dest/mcp/pyproject.toml"
    cp "$repo/mcp/uv.lock" "$dest/mcp/uv.lock"
    cp "$repo/mcp/egress-allowlist.yaml" "$dest/mcp/egress-allowlist.yaml"
  fi
  exit 0
fi
if [ "${1:-}" = "init" ]; then
  mkdir -p "$2"
  exit 0
fi
exit 0
EOF
  chmod +x "$WORK/bin/git"
}

@test "help lists the install flags" {
  run "$REPO/install/install.sh" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--profile"* ]]
  [[ "$output" == *"--offline"* ]]
  [[ "$output" == *"--no-hermes-install"* ]]
  [[ "$output" == *"--allow-root"* ]]
}

@test "unknown option fails" {
  run "$REPO/install/install.sh" --not-a-flag
  [ "$status" -eq 1 ]
  [[ "$output" == *"unknown option"* ]]
}

@test "refuses to run as root" {
  install_fake_id_root
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -eq 1 ]
  [[ "$output" == *"Refusing to run as root"* ]]
  ! grep -q "profile install" "$HERMES_FAKE_LOG"
}

@test "allow-root continues when id is root" {
  install_fake_id_root
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes --allow-root
  [ "$status" -eq 0 ]
  grep -q "profile install" "$HERMES_FAKE_LOG"
}

@test "version gate stops when Hermes is too old" {
  export HERMES_FAKE_VERSION=0.22.1
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -eq 1 ]
  [[ "$output" == *"requires Hermes >=0.22.2, but you have 0.22.1"* ]]
  ! grep -q "profile install" "$HERMES_FAKE_LOG"
}

@test "version gate accepts the required Hermes version" {
  export HERMES_FAKE_VERSION=0.22.2
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"satisfies >=0.22.2"* ]]
  grep -q "profile install" "$HERMES_FAKE_LOG"
}

@test "--profile overrides CYBERAU_PROFILE" {
  export CYBERAU_PROFILE=from-env
  run "$REPO/install/install.sh" --profile from-flag --offline --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  grep -q -- "--name from-flag" "$HERMES_FAKE_LOG"
  ! grep -q -- "--name from-env" "$HERMES_FAKE_LOG"
}

@test "CYBERAU_PROFILE applies when --profile is not given" {
  export CYBERAU_PROFILE=from-env
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  grep -q -- "--name from-env" "$HERMES_FAKE_LOG"
}

@test "--ref overrides CYBERAU_REF" {
  install_fake_git
  export CYBERAU_REF=from-env
  run "$REPO/install/install.sh" --ref v0.1.0 --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  grep -q "fetch --depth 1 origin v0.1.0" "$GIT_LOG"
  ! grep -q "from-env" "$GIT_LOG"
}

@test "missing Hermes does not pipe the installer into a shell" {
  rm -f "$WORK/bin/hermes"
  run "$REPO/install/install.sh" --non-interactive
  [ "$status" -eq 1 ]
  [[ "$output" == *"https://raw.githubusercontent.com/NousResearch/hermes-agent/"* ]]
  [[ "$output" == *"checked against sha256"* ]]
  [ ! -s "$CURL_LOG" ]
}

@test "--hermes-latest shows the moving upstream installer" {
  rm -f "$WORK/bin/hermes"
  run "$REPO/install/install.sh" --hermes-latest --non-interactive
  [ "$status" -eq 1 ]
  [[ "$output" == *"https://hermes-agent.nousresearch.com/install.sh"* ]]
  [ ! -s "$CURL_LOG" ]
}

@test "offline does not download Hermes or call git" {
  rm -f "$WORK/bin/hermes"
  install_fake_git
  run "$REPO/install/install.sh" --offline --non-interactive --yes
  [ "$status" -eq 1 ]
  [[ "$output" == *"--offline will not download Hermes"* ]]
  [ ! -s "$CURL_LOG" ]
  [ ! -s "$GIT_LOG" ]
}

@test "ref clones locally then installs that directory" {
  install_fake_git
  run "$REPO/install/install.sh" --ref v0.1.0 --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  grep -q "fetch --depth 1 origin v0.1.0" "$GIT_LOG"
  grep -q "profile install" "$HERMES_FAKE_LOG"
  ! grep -q 'hermes-cyber-au@' "$HERMES_FAKE_LOG"
  ! grep -q 'git clone' "$GIT_LOG"
}

@test "the temporary clone is removed when the install finishes" {
  install_fake_git
  mkdir -p "$WORK/tmp"
  TMPDIR="$WORK/tmp" run "$REPO/install/install.sh" --ref v0.1.0 --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  [ -z "$(ls -A "$WORK/tmp")" ]
}

@test "a ref or profile that looks like an option is refused" {
  run "$REPO/install/install.sh" --ref=--upload-pack=x --offline --no-hermes-install
  [ "$status" -eq 1 ]
  [[ "$output" == *"Invalid ref"* ]]
  run "$REPO/install/install.sh" --profile ../escape --offline --no-hermes-install
  [ "$status" -eq 1 ]
  [[ "$output" == *"Invalid profile name"* ]]
}

@test "offline ref does not fetch" {
  install_fake_git
  run "$REPO/install/install.sh" --offline --ref deadbeef --no-hermes-install --non-interactive --yes
  [ "$status" -eq 1 ]
  [[ "$output" == *"--offline cannot fetch deadbeef"* ]]
  ! grep -q "fetch" "$GIT_LOG"
  [ ! -s "$CURL_LOG" ]
}

@test "running install twice does not change config or the lock" {
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  home="$HOME/.hermes/profiles/cyber-au"
  hash_config="$(cksum "$home/config.yaml")"
  hash_lock="$(cksum "$home/mcp/uv.lock")"
  hash_stamp="$(cksum "$home/mcp/.venv/.cyberau-sync-stamp")"
  [[ "$output" == *"hermes cyber-au doctor is not in this checkout"* ]]
  [[ "$output" == *"The doctor check is a separate ticket."* ]]
  [[ "$output" == *"NVD_API_KEY is unset"* ]]
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  [ "$(cksum "$home/config.yaml")" = "$hash_config" ]
  [ "$(cksum "$home/mcp/uv.lock")" = "$hash_lock" ]
  [ "$(cksum "$home/mcp/.venv/.cyberau-sync-stamp")" = "$hash_stamp" ]
  [ "$(grep -c "profile install" "$HERMES_FAKE_LOG")" -eq 1 ]
  [[ "$output" == *"already installed"* ]]
}

@test "an optional nvd key stays a placeholder without disabling the connector" {
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  home="$HOME/.hermes/profiles/cyber-au"
  printf '%s\n' 'NVD_API_KEY=test-only-not-a-secret' >"$home/.env"
  run "$REPO/install/bootstrap.sh" --profile cyber-au --offline --non-interactive
  [ "$status" -eq 0 ]
  ! grep -q 'test-only-not-a-secret' "$home/config.yaml"
  grep -q 'NVD_API_KEY: "\${NVD_API_KEY}"' "$home/config.yaml" || grep -q 'NVD_API_KEY: ${NVD_API_KEY}' "$home/config.yaml"
  "$CYBERAU_REAL_PYTHON" - <<PY
import yaml
from pathlib import Path
loaded = yaml.safe_load(Path("$home/config.yaml").read_text())
assert loaded["mcp_servers"]["nvd"].get("enabled", True) is True
assert loaded["mcp_servers"]["nvd"]["env"]["NVD_API_KEY"] == "\${NVD_API_KEY}"
PY
}

@test "plugin enable failure stops installation when the plugin exists" {
  export HERMES_FAKE_ENABLE_FAIL=1
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"Could not enable the cyber-au plugin."* ]]
}

@test "the Hermes installer pipe lives only in the confirmed function" {
  awk '
    /run_hermes_installer\(\)/ { in_fn = 1 }
    in_fn && /curl -fsSL "\$HERMES_INSTALL_URL" \| bash/ { found++ }
    in_fn && /^}/ { in_fn = 0 }
    END { exit(found == 1 ? 0 : 1) }
  ' "$REPO/install/install.sh"
}


@test "store initialisation error is visible and fails bootstrap" {
  export STORE_FAKE_FAIL=init
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"synthetic store failure: init"* ]]
}

@test "KEV import error is visible and fails bootstrap" {
  export STORE_FAKE_KEV=1 STORE_FAKE_FAIL=ingest-kev
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"synthetic store failure: ingest-kev"* ]]
}

@test "missing required reference files fail bootstrap" {
  run "$REPO/install/install.sh" --offline --no-hermes-install --non-interactive --yes
  [ "$status" -eq 0 ]
  rm "$HOME/.hermes/profiles/cyber-au/mcp/asd-essentials/data/e8-maturity-test.json"
  run "$REPO/install/bootstrap.sh" --profile cyber-au --offline --non-interactive
  [ "$status" -ne 0 ]
  [[ "$output" == *"Essential Eight maturity reference files are missing"* ]]
}
