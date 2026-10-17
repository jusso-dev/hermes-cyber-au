# cyber-au Docker image

The image is `nousresearch/hermes-agent` with this distribution installed as the named profile `cyber-au`. It does not rewrite the default profile's `config.yaml`, `SOUL.md` or `.env`.

Checked against NousResearch/hermes-agent at `43faacf` (v0.22.2):

| Fact | Value |
|---|---|
| Base tag | `v0.22.2` (`ARG HERMES_VERSION`) |
| Runtime user | `hermes`, UID 10000, home `/opt/data` |
| Data volume | `/opt/data` (`HERMES_HOME`) |
| Process model | PID 1 is root so s6-overlay can start. The agent then runs as `hermes`. |
| Upstream entrypoint | `/opt/hermes/docker/entrypoint-dispatch.sh` |

Docker installs do not support `hermes update`. Run a newer image instead.

## Build

From the repository root:

```bash
docker build -f docker/Dockerfile \
  --build-arg REVISION="$(git rev-parse HEAD)" \
  -t ghcr.io/jusso-dev/hermes-cyber-au:0.1.0 \
  .
```

`REVISION` is the git commit recorded in `org.opencontainers.image.revision`. The other labels are `org.opencontainers.image.source`, `org.opencontainers.image.version` and `org.opencontainers.image.licenses=Apache-2.0`.

The build context ignores `.env`, key files, `tickets/` and `docs/`. The Dockerfile also deletes `tickets/` and `docs/` from the copied source, and it refuses to finish if a `.env`, `auth.json`, `credentials.json`, `.pem` or `.key` file is present. `.env.template` is the empty placeholder and is copied into the profile as `.env.EXAMPLE`.

`install/bootstrap.sh` is run with `--profile cyber-au --non-interactive --offline` when that script is in the checkout. This tree does not ship it yet, so the image build stops after `hermes profile install`.

## Run

```bash
docker run -it --rm \
  -v cyberau:/opt/data \
  --env-file .env \
  ghcr.io/jusso-dev/hermes-cyber-au:0.1.0 \
  chat
```

`--env-file` is optional. Omit it, or pass an empty file, when you have no keys. On a new volume the entrypoint selects the `cyber-au` profile. If the volume already has a default `config.yaml` or `SOUL.md`, that selection is left alone. Use `hermes -p cyber-au` for the distribution profile in that case. The entrypoint seeds `profiles/cyber-au` only when that directory is absent, so an existing profile of that name on the volume is never overwritten, and a new image does not upgrade a profile already on the volume. `HERMES_PROFILE` only labels the profile identity (for example kanban authorship). It does not select a profile; `active_profile` and `-p` do.

Keys are read from the container environment or from the profile `.env` on the volume (`/opt/data/profiles/cyber-au/.env`). Nothing in the image is a real key. Copy `.env.template` from the repository, fill in your own values, and pass that file. Do not commit it.

```bash
docker run --rm ghcr.io/jusso-dev/hermes-cyber-au:0.1.0 \
  -p cyber-au cyber-au doctor --offline
```

`cyber-au doctor` is provided by the plugin. Until that command exists, this returns Hermes's unknown-command error.

## Compose

`docker/compose.yaml` defines two services and one named volume, `cyberau`, mounted at `/opt/data`.

```bash
cp .env.template docker/.env   # optional; leave values blank
docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml run --rm agent
docker compose -f docker/compose.yaml --profile gateway up gateway
```

The agent service runs `chat`. The gateway service is off unless you select the `gateway` profile. It runs `gateway run` for `cyber-au` and publishes port 8642 on `127.0.0.1` only. Both services read `docker/.env` when that file exists. Compose variable substitution can also read a `.env` next to the compose file; do not put real keys in the repository.
