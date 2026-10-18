#!/bin/sh
# Runs once when the dev container or Codespace is created.
# Installs the cyber-au profile from this checkout with no keys, copies any
# Codespaces secrets into the profile .env (names only are printed), runs the
# offline doctor, and shows the demo triage.
set -eu

cd "$(dirname -- "$0")/.."

sh install/install.sh --no-hermes-install --non-interactive --yes

PROFILE_HOME=$(dirname "$(hermes -p cyber-au config path)")

# Codespaces secrets arrive as environment variables. Keep them out of the
# repository: they go only into the profile .env inside this container.
copied=$(python3 .devcontainer/env_from_secrets.py distribution.yaml "$PROFILE_HOME/.env")
printf '%s\n' "$copied"
case $copied in
  Copied*)
    # Turn on the matching connectors. The first bootstrap filled the uv
    # cache, so this pass stays offline and fast.
    sh install/bootstrap.sh --profile cyber-au --non-interactive --offline
    ;;
esac

hermes -p cyber-au cyber-au doctor --offline || true
hermes -p cyber-au cyber-au demo triage

cat <<'EOF'

Ready. Next steps:
  hermes -p cyber-au model            choose a model provider
  hermes -p cyber-au chat             start a chat, then paste an example prompt
  hermes -p cyber-au cyber-au demo prompts
EOF
