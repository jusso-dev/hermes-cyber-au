# Codespaces and dev containers

Try the profile without installing anything on your own machine. The repository has a dev container in `.devcontainer/` that works in GitHub Codespaces and in VS Code with the Dev Containers extension.

## Open it

- **Codespaces:** on the repository page, choose **Code**, then **Codespaces**, then **Create codespace on main**. Or use the badge in the README.
- **VS Code:** clone the repository, open it, and run **Dev Containers: Reopen in Container**. You need Docker on that machine.

## What happens on create

The container is built from `.devcontainer/Dockerfile`:

- Base image `nousresearch/hermes-agent:v0.22.2`, pinned by digest. Hermes is already installed.
- `uv` 0.13.1 copied from `ghcr.io/astral-sh/uv`, pinned by digest.
- PyYAML and stix2 installed into the Hermes interpreter for the cyber-au plugin.
- You work as the image's `hermes` user. `HERMES_HOME` is `/opt/data`.

Then `.devcontainer/post-create.sh` runs once:

1. `sh install/install.sh --no-hermes-install --non-interactive --yes` installs the `cyber-au` profile from the checkout and bootstraps the connectors that need no key.
2. Optional Codespaces secrets are copied into the profile `.env` (see below).
3. `hermes -p cyber-au cyber-au doctor --offline` reports the profile health.
4. `hermes -p cyber-au cyber-au demo triage` prints a demo triage, so the first answer is already on screen.

It takes a few minutes. The output is in the Codespaces creation log. To run it again, use `sh .devcontainer/post-create.sh`. It is safe to repeat.

## Next steps in the terminal

```bash
hermes -p cyber-au model                 # choose a model provider
hermes -p cyber-au chat                  # then paste a prompt from the first hour page
hermes -p cyber-au cyber-au demo prompts # the ten example prompts
```

The example prompts are in [Your first hour](first-hour.md). Start the chat from `/workspaces/hermes-cyber-au` so the `examples/` paths resolve.

## Keys in Codespaces

No key is needed. To add one, make it a Codespaces secret for this repository in your GitHub settings (**Settings**, **Codespaces**, **Secrets**). The dev container suggests four optional names: `ABUSECH_AUTH_KEY`, `NVD_API_KEY`, `OTX_API_KEY` and `GREYNOISE_API_KEY`. Any name listed in `env_requires` in `distribution.yaml` is accepted.

On create, `.devcontainer/env_from_secrets.py` copies the secrets that are set into the profile `.env` at `/opt/data/profiles/cyber-au/.env` with mode 600, prints only their names, and re-runs bootstrap so the matching connectors turn on. A name already in that file is left alone. Secrets never go into the repository or the image.

If you add a secret after the codespace exists, rebuild the container, or run:

```bash
python3 .devcontainer/env_from_secrets.py distribution.yaml /opt/data/profiles/cyber-au/.env
sh install/bootstrap.sh --profile cyber-au --non-interactive
```

## Limits

- The model provider is still your choice and needs its own sign-in or key. Keep that key in a Codespaces secret or enter it in `hermes -p cyber-au model`. Do not commit it.
- Profile data lives in `/opt/data`, inside the container. Rebuilding the container starts a fresh profile.
- The pinned digests are bumped together with the Hermes pin in `docker/Dockerfile`. A test checks that both name the same Hermes version.
