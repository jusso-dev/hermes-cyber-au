# Development container for trying hermes-cyber-au with nothing installed locally.
# Hermes comes from the upstream image. Both images are pinned by digest; the
# tags are for people. A Dependabot or manual bump changes tag and digest together.
FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

FROM nousresearch/hermes-agent:v0.22.2@sha256:36099926da316742423544e055d4734777105ffe6341873af5459b957d0c2919

COPY --from=uv /uv /uvx /usr/local/bin/

# The cyber-au plugin imports PyYAML and stix2 inside the Hermes interpreter.
# docker/Dockerfile does the same. Versions match plugins/cyber-au/plugin.yaml.
RUN uv pip install --python /opt/hermes/.venv/bin/python 'pyyaml>=6,<7' 'stix2>=3,<4'

# The upstream entrypoint starts s6 and Hermes. A dev container only needs a
# shell, so clear it. The user is the image's own hermes user (UID 10000,
# home /opt/data, which is also HERMES_HOME).
ENTRYPOINT []
USER hermes
ENV HERMES_HOME=/opt/data \
    PATH=/opt/data/.local/bin:/opt/hermes/bin:/opt/hermes/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
