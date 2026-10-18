# cyber-au Docker image

The image is `nousresearch/hermes-agent` with this distribution installed as the named profile `cyber-au`. It does not rewrite the default profile's `config.yaml`, `SOUL.md` or `.env`.

Checked against NousResearch/hermes-agent at `43faacf` (v0.22.2):

| Fact | Value |
|---|---|
| Base tag | `v0.22.2` (`ARG HERMES_VERSION`), pinned by digest (`ARG HERMES_DIGEST`) |
| Runtime user | `hermes`, UID 10000, home `/opt/data` |
| Data volume | `/opt/data` (`HERMES_HOME`) |
| Process model | PID 1 is root so s6-overlay can start. The agent then runs as `hermes`. |
| Upstream entrypoint | `/opt/hermes/docker/entrypoint-dispatch.sh` |

Docker installs do not support `hermes update`. Run a newer image instead.

## Compose

`docker/compose.yaml` defines two services and one named volume, `cyberau`, mounted at `/opt/data`. Run these from the repository root:

```bash
cp .env.template docker/.env   # optional; fill in only the keys you have
docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml run --rm agent
docker compose -f docker/compose.yaml --profile gateway up gateway
```

By default compose builds the image from your checkout and tags it `hermes-cyber-au:local`. `run` also builds it when it is missing, but running `build` first shows the progress. The first build takes several minutes because it downloads the base image and the connector wheels.

To use a published release instead of a local build, set `CYBERAU_IMAGE`:

```bash
CYBERAU_IMAGE=ghcr.io/jusso-dev/hermes-cyber-au:2026.10.24 \
  docker compose -f docker/compose.yaml run --rm agent
```

Replace the date with a tag from the [releases page](https://github.com/jusso-dev/hermes-cyber-au/releases). If that tag cannot be pulled, compose builds from the checkout instead.

The agent service runs `chat`. The gateway service is off unless you select the `gateway` profile. It runs `gateway run` for `cyber-au` and publishes port 8642 on `127.0.0.1` only. Both services read `docker/.env` when that file exists. Compose variable substitution can also read a `.env` next to the compose file; do not put real keys in the repository.

## Published images

The weekly release workflow pushes `ghcr.io/jusso-dev/hermes-cyber-au:<YYYY.MM.DD>`, the same CalVer tag as the GitHub release. There is no `latest` tag. Until the first release is out, build locally.

## Build

From the repository root:

```bash
docker build -f docker/Dockerfile \
  --build-arg REVISION="$(git rev-parse HEAD)" \
  -t hermes-cyber-au:local \
  .
```

`REVISION` is the commit recorded in `org.opencontainers.image.revision`. The other labels are `org.opencontainers.image.source`, `org.opencontainers.image.version` and `org.opencontainers.image.licenses=Apache-2.0`.

The base image, uv and connector wheels are pinned:

| Input | Pin |
|---|---|
| Base image | `nousresearch/hermes-agent:${HERMES_VERSION}@${HERMES_DIGEST}`. The digest wins over the tag, so change both together. `tests/test_docker_pins.py` fails when the version named beside the digest does not match `HERMES_VERSION`. |
| uv | Copied from `ghcr.io/astral-sh/uv:<version>@sha256:...`. No install script is piped into a shell. |
| Connector wheels | `install/bootstrap.sh` syncs the locked `mcp/uv.lock`. |

To find the digest for a new Hermes tag, run `docker buildx imagetools inspect nousresearch/hermes-agent:<tag>` and copy the top-level `Digest`.

Hermes version upgrades require a manual pin update. The weekly job stops with an
explicit error instead of changing a tag while leaving its digest or installer on
the old release. Update `tools/hermes_pin.txt`, `distribution.yaml`, both image
pins in `docker/Dockerfile` and `.devcontainer/Dockerfile`, and the installer
version, commit and checksum in `install/install.sh` together. Verify each
upstream artifact and run the install checks before merging the upgrade.

The build context ignores `.env`, key files, `tickets/` and `docs/`. The Dockerfile also deletes `tickets/` and `docs/` from the copied source, and it refuses to finish if a `.env`, `auth.json`, `credentials.json`, `.pem` or `.key` file is present. `.env.template` is the empty placeholder and is copied into the profile as `.env.EXAMPLE`.

`install/bootstrap.sh` runs with `--profile cyber-au --non-interactive` during the build, so the image carries the locked connector environment.

## Run

```bash
docker run -it --rm \
  -v cyberau:/opt/data \
  --env-file .env \
  hermes-cyber-au:local \
  chat
```

Use `ghcr.io/jusso-dev/hermes-cyber-au:<YYYY.MM.DD>` in place of `hermes-cyber-au:local` to run a published release. `--env-file` is optional. Omit it, or pass an empty file, when you have no keys. On a new volume the entrypoint selects the `cyber-au` profile. If the volume already has a default `config.yaml` or `SOUL.md`, that selection is left alone. Use `hermes -p cyber-au` for the distribution profile in that case. The entrypoint seeds `profiles/cyber-au` only when that directory is absent, so an existing profile of that name on the volume is never overwritten, and a new image does not upgrade a profile already on the volume. `HERMES_PROFILE` only labels the profile identity (for example kanban authorship). It does not select a profile; `active_profile` and `-p` do.

Keys are read from the container environment or from the profile `.env` on the volume (`/opt/data/profiles/cyber-au/.env`). Nothing in the image is a real key. Copy `.env.template` from the repository, fill in your own values, and pass that file. Do not commit it.

```bash
docker run --rm hermes-cyber-au:local \
  -p cyber-au cyber-au doctor --offline
```
