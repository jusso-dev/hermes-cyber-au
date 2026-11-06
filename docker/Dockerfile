# Hermes Agent image with the cyber-au distribution preinstalled.
# Runtime user and data volume checked against NousResearch/hermes-agent
# Dockerfile at d923a5e (v0.22.2):
#   useradd -u 10000 -m -d /opt/data hermes
#   ENV HERMES_HOME=/opt/data
#   VOLUME ["/opt/data"]
#   USER root
# PID 1 stays root so s6-overlay can start. Supervised processes drop to
# hermes (UID 10000) with s6-setuidgid. Do not set USER hermes here.

# Base and tool images are pinned by digest. A tag can be moved; a digest
# cannot. HERMES_DIGEST is the multi-arch index digest of
# nousresearch/hermes-agent:v0.22.2. When HERMES_VERSION changes, update
# HERMES_DIGEST in the same commit (tests/test_docker_pins.py checks the
# version named on the next line matches HERMES_VERSION).
# HERMES_DIGEST version: v0.22.2
ARG HERMES_VERSION=v0.22.2
ARG HERMES_DIGEST=sha256:36099926da316742423544e055d4734777105ffe6341873af5459b957d0c2919

# uv 0.13.1 from Astral's published image, pinned by index digest. This
# replaces piping https://astral.sh/uv/install.sh into a shell.
FROM ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 AS uv

FROM nousresearch/hermes-agent:${HERMES_VERSION}@${HERMES_DIGEST}

ARG HERMES_VERSION
ARG VERSION=0.1.0
ARG REVISION=unknown
ARG SOURCE_URL=https://github.com/jusso-dev/hermes-cyber-au

LABEL org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=uv /uv /uvx /usr/local/bin/
COPY --chmod=0755 docker/entrypoint.sh /opt/cyber-au/entrypoint.sh
COPY --chown=hermes:hermes . /opt/cyber-au/src

# Install into the named profile only. Hermes refuses to install a
# distribution as the default profile. The first CLI run still seeds that
# home, so the build deletes those files and leaves the base image's
# dotfiles plus profiles/cyber-au. The seed is also kept outside /opt/data
# because the upstream image declares that path as a volume.
# The upstream image does not ship uv. It is copied from the pinned uv
# image above, then bootstrap downloads the locked connector wheels. A later
# air-gapped bootstrap can still pass --offline.
RUN uv --version \
    && hermes profile install /opt/cyber-au/src --name cyber-au --yes \
    && uv pip install --python /opt/hermes/.venv/bin/python 'pyyaml>=6,<7' 'stix2>=3,<4' \
    && chown -R hermes:hermes /opt/data \
    && if [ -f /opt/cyber-au/src/install/bootstrap.sh ]; then \
         runuser -u hermes -- sh /opt/cyber-au/src/install/bootstrap.sh --profile cyber-au --non-interactive; \
       fi \
    && rm -rf /opt/cyber-au/profile \
    && cp -a /opt/data/profiles/cyber-au /opt/cyber-au/profile \
    && find /opt/data -mindepth 1 -maxdepth 1 \
         ! -name profiles ! -name .bash_logout ! -name .bashrc ! -name .profile \
         -exec rm -rf {} + \
    && rm -rf /opt/cyber-au/src/tickets /opt/cyber-au/src/docs \
    && find /opt/cyber-au/src /opt/cyber-au/profile \
         \( -path '*/.venv/*' -o -path '*/site-packages/*' \) -prune -o \
         \( -name .env -o -name auth.json -o -name credentials.json -o -name '*.pem' -o -name '*.key' \) \
         -print > /tmp/credential-files \
    && if [ -s /tmp/credential-files ]; then \
         echo "credential-shaped paths:" >&2; \
         cat /tmp/credential-files >&2; \
         if grep -Ev '/\.env$' /tmp/credential-files | grep -q .; then \
           echo "refusing to bake a credential file into the image" >&2; \
           exit 1; \
         fi; \
         if grep -Ev '^[[:space:]]*(#.*)?$' /opt/cyber-au/profile/.env 2>/dev/null \
            | grep -Ev '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=[[:space:]]*$' \
            | grep -Ev '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=\$\{[A-Za-z_][A-Za-z0-9_]*\}[[:space:]]*$' \
            | grep -q .; then \
           echo "refusing to bake a filled .env into the image" >&2; \
           exit 1; \
         fi; \
       fi \
    && chown -R hermes:hermes /opt/cyber-au/profile

ENV HERMES_PROFILE=cyber-au

ENTRYPOINT ["/opt/cyber-au/entrypoint.sh"]
