---
key: "install-docker"
title: "Docker image: FROM nousresearch/hermes-agent with the distribution preinstalled"
labels: ["type:feature", "area:install", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-install"
---
## Outcome
`docker run -it --rm -v cyberau:/opt/data ghcr.io/jusso-dev/hermes-cyber-au:<version> chat` starts the agent with every connector ready and no secrets baked in.

## Context
Upstream image `nousresearch/hermes-agent` (tags include `v0.22.2`, `stable`, `latest`). Docker installs do not support `hermes update`; you run a new image ([`website/docs/getting-started/platform-support.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/getting-started/platform-support.md), [`website/docs/user-guide/docker.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/docker.md)). The entrypoint is `/opt/hermes/docker/entrypoint-dispatch.sh` ([`Dockerfile`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/Dockerfile)), and per-profile gateways are supervised by s6-overlay.

## Files
- `docker/Dockerfile`
- `docker/compose.yaml` (agent plus optional gateway, named volume, `.env` file)
- `docker/README.md`

## Dockerfile sketch
```dockerfile
ARG HERMES_VERSION=v0.22.2
FROM nousresearch/hermes-agent:${HERMES_VERSION}
COPY --chown=hermes:hermes . /opt/cyber-au/src
RUN hermes profile install /opt/cyber-au/src --name cyber-au --yes \
 && /opt/cyber-au/src/install/bootstrap.sh --profile cyber-au --non-interactive --offline \
 && rm -rf /opt/cyber-au/src/tickets /opt/cyber-au/src/docs
ENV HERMES_PROFILE=cyber-au
```
Check the image's runtime user name and the data volume path in the upstream Dockerfile before writing the `COPY --chown` and volume lines; do not assume `hermes` or `/opt/data`.

## Acceptance criteria
- [ ] Image builds in CI from the checkout and runs `cyber-au doctor --offline` green.
- [ ] `docker history` and `docker save | tar -t` show no `.env`, tokens or fixtures with secrets.
- [ ] Container runs as the upstream non-root user.
- [ ] Keys passed with `--env-file` reach the keyed MCP servers (checked by doctor).
- [ ] Image labels: `org.opencontainers.image.source`, `.version`, `.licenses=Apache-2.0`, `.revision`.
- [ ] Trivy or Grype scan has no critical findings introduced by our layer.

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).

## Out of scope
Kubernetes manifests.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
