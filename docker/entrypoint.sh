#!/bin/sh
# Seed the named cyber-au profile onto the data volume, then hand off to the
# upstream s6 entrypoint. This does not rewrite the default profile.
set -eu

SEED=/opt/cyber-au/profile
DEST=/opt/data/profiles/cyber-au

# Only seed when the profile directory is absent. An existing directory with no
# distribution.yaml is an operator's own profile; cp -a into it would nest the
# seed as $DEST/profile. Copy to a temp name and rename so an interrupted boot
# cannot leave a half-seeded profile that the next boot skips.
if [ ! -e "$DEST" ] && [ -d "$SEED" ]; then
    mkdir -p /opt/data/profiles
    rm -rf "$DEST.seeding"
    cp -a "$SEED" "$DEST.seeding"
    chown -R hermes:hermes "$DEST.seeding"
    mv "$DEST.seeding" "$DEST"
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

# The cyber-au plugin imports connector packages. They live in the profile
# virtualenv, not in the Hermes interpreter.
site=$(echo /opt/data/profiles/cyber-au/mcp/.venv/lib/python*/site-packages)
if [ -d "$site" ]; then
    PYTHONPATH="${site}${PYTHONPATH:+:$PYTHONPATH}"
    export PYTHONPATH
fi

exec /opt/hermes/docker/entrypoint-dispatch.sh "$@"
