#!/bin/sh
# Seed the named cyber-au profile onto the data volume, then hand off to the
# upstream s6 entrypoint. This does not rewrite the default profile.
set -eu

SEED=/opt/cyber-au/profile
DEST=/opt/data/profiles/cyber-au

if [ ! -f "$DEST/distribution.yaml" ] && [ -d "$SEED" ]; then
    mkdir -p /opt/data/profiles
    cp -a "$SEED" "$DEST"
    chown -R hermes:hermes "$DEST"
fi

# A fresh volume has no operator config yet. Point it at cyber-au.
# An existing default profile (config.yaml or SOUL.md) keeps its own selection.
if [ ! -e /opt/data/active_profile ] \
    && [ ! -e /opt/data/config.yaml ] \
    && [ ! -e /opt/data/SOUL.md ] \
    && [ -f "$DEST/distribution.yaml" ]; then
    printf '%s\n' cyber-au > /opt/data/active_profile
    chown hermes:hermes /opt/data/active_profile
    chmod 644 /opt/data/active_profile
fi

exec /opt/hermes/docker/entrypoint-dispatch.sh "$@"
