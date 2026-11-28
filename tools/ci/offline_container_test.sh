#!/bin/bash
# Install an offline bundle inside a container started with --network none.
#
#   bash tools/ci/offline_container_test.sh <directory holding cyber-au-offline-*.tar.gz>
#
# The image is Python 3.12 on Debian, pinned by digest. Hermes is not in it, so a
# small stand-in answers the few hermes commands the installer uses. What this
# proves is that the bundle's wheels, profile and scripts install and bootstrap
# with no network: pip, uv and the connectors have nothing to reach.
# Run it by hand the same way. It needs Docker and the bundle, nothing else.
set -euo pipefail

# python:3.12-slim multi-arch index digest, read 28 November 2026.
IMAGE=${CYBERAU_OFFLINE_TEST_IMAGE:-python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b}

dir=${1:?usage: offline_container_test.sh <bundle directory>}
bundle=$(find "$dir" -maxdepth 1 -name 'cyber-au-offline-*.tar.gz' | head -n 1)
[ -n "$bundle" ] || { echo "no cyber-au-offline-*.tar.gz in $dir" >&2; exit 1; }
bundle=$(cd "$(dirname "$bundle")" && pwd)/$(basename "$bundle")

docker run --rm --network none \
  -v "$bundle:/bundle.tar.gz:ro" \
  --entrypoint bash "$IMAGE" -euo pipefail -c '
    useradd -m analyst
    cat >/usr/local/bin/hermes <<"EOF"
#!/bin/sh
# Stand-in for the Hermes CLI. Profile install copies the profile tree.
profile=cyber-au; prev=; src=
for arg in "$@"; do
  case $prev in -p|--name) profile=$arg ;; esac
  [ "$prev" = install ] && src=$arg
  case $arg in --version) echo "Hermes Agent 99.0.0"; exit 0 ;; esac
  prev=$arg
done
home=$HOME/.hermes/profiles/$profile
case " $* " in
  *" config path "*) echo "$home/config.yaml"; exit 0 ;;
  *" plugins enable "*|*" cyber-au doctor "*|*" cron "*) exit 0 ;;
esac
if [ -n "$src" ]; then mkdir -p "$home" && cp -R "$src/." "$home/" && exit 0; fi
echo "unhandled: $*" >&2; exit 1
EOF
    chmod 755 /usr/local/bin/hermes
    su analyst -c "
      set -eu
      cd \$HOME
      tar -xzf /bundle.tar.gz
      cd cyber-au-offline-*
      HERMES_PYTHON=/usr/local/bin/python3 ./install-offline.sh --non-interactive --yes
      home=\$HOME/.hermes/profiles/cyber-au
      CYBERAU_OFFLINE=1 \$home/mcp/.venv/bin/cyberau-mcp health kev --offline
      grep -q CYBERAU_OFFLINE \$home/config.yaml
      echo offline install ok
    "
  '
