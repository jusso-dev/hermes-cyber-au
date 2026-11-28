# Offline and air-gapped install

Teams on networks that cannot reach PyPI, GitHub or feed sites can install cyber-au from one release file and refresh shipped data by importing a signed data pack. Nothing in this workflow submits, posts or changes an external system.

## What a release ships

The weekly release ([supply chain](supply-chain.md)) adds two files to the GitHub release:

| File | What it is | How it is signed |
|---|---|---|
| `cyber-au-offline-<version>.tar.gz` | The install bundle: the profile, current snapshots, Linux wheels and the offline installer | Sigstore keyless attestation from the release workflow, plus `SHA256SUMS` inside the bundle |
| `cyber-au-datapack-<version>.tar.gz` | A data pack: shipped connector snapshots and public intel store snapshots | Ed25519 signature from the maintainer's data pack key. Only present once that key is configured |

The bundle holds:

- `profile/`: the distribution-owned files Hermes installs, including `mcp/<connector>/data/` snapshots and any `intel/snapshots/public-*.sqlite.zst` present at release time.
- `requirements/runtime.txt`: `uv export --frozen` of `mcp/uv.lock`, with SHA-256 hashes. pip refuses any wheel that does not match.
- `requirements/build.txt`: the build backend (hatchling, editables) for the editable connector installs, hashed and held to the lock's versions.
- `wheels/linux_x86_64/` and `wheels/linux_aarch64/`: wheels for Python 3.12 on glibc 2.17 or newer (manylinux2014 up to manylinux_2_28). `wheels/<platform>/plugin/` holds the plugin's Hermes-side dependency (PyYAML) for Python 3.11 to 3.14.
- `install-offline.sh`, `bundle.json` (release, lock hash, platforms, wheel counts) and `SHA256SUMS`.

## Before you carry it across

On a connected machine, check the release attestation, then copy the file to removable media:

```bash
gh attestation verify cyber-au-offline-<version>.tar.gz --repo jusso-dev/hermes-cyber-au
```

The attestation ties the file to the release workflow run that built it. Keep the verification output with your change record if your process needs one.

## Install on the offline host

The host needs:

- Linux on x86_64 or aarch64 with glibc 2.17 or newer.
- Python 3.12 with the `venv` module (on Debian and Ubuntu, `python3.12-venv`).
- Hermes already installed at the version in `distribution.yaml` `hermes_requires`. The bundle does not carry Hermes and the installer will not download it. Install Hermes from your own approved mirror or image first.

Then:

```bash
tar -xzf cyber-au-offline-<version>.tar.gz
cd cyber-au-offline-<version>
./install-offline.sh --non-interactive --yes
```

The installer:

1. Checks every file against `SHA256SUMS` and stops before installing anything if one differs.
2. Runs `install/install.sh --offline --skip-bootstrap` from the bundled profile, so Hermes installs the profile from the local copy.
3. Copies the public intel snapshots into the profile's `intel/snapshots/`.
4. Builds `mcp/.venv` with `pip install --no-index --find-links wheels/<platform>`, first the hashed runtime wheels, then the build backend, then each connector as an editable install with no dependency resolution.
5. Installs PyYAML into the Python that runs Hermes from `wheels/<platform>/plugin/`.
6. Adds `CYBERAU_OFFLINE=1` to the profile `.env` (mode 600).
7. Runs `install/bootstrap.sh --offline --venv-ready`, the same bootstrap a connected install runs, but without `uv sync`.

`PIP_NO_INDEX`, `UV_OFFLINE` and `UV_NO_INDEX` are set for the whole run. Options: `--profile`, `--profile-home`, `--platform`, `--allow-root` and `--skip-verify` (not recommended). Run `./install-offline.sh --help` for the full list.

## What offline mode looks like

With `CYBERAU_OFFLINE=1`, bootstrap writes the variable onto every connector in `config.yaml`. Connectors answer from their HTTP cache and from shipped snapshots only. A source with neither returns no rows and an `unavailable` warning. It never returns an empty result that looks like an all-clear.

`hermes -p cyber-au cyber-au doctor` reports offline mode as its own check:

```text
warn  mode.offline  offline mode (CYBERAU_OFFLINE=1); live-only sources answer from cache or report unavailable: attack, epss, greynoise, ...
```

The list names every enabled source that has no shipped snapshot. Doctor runs only the offline connector probe in this mode, never the live one. To go back online, delete the `CYBERAU_OFFLINE` line from `.env` and re-run `install/bootstrap.sh`.

## Refresh data with a signed data pack

A data pack carries files under `mcp/<connector>/data/` and `intel/snapshots/public-*.sqlite.zst`, and nothing else. It never carries code, config, credentials or the intel store itself.

Check the release file on the connected side as above, carry it across, then on the offline host:

```bash
~/.hermes/profiles/cyber-au/mcp/.venv/bin/cyberau-mcp datapack verify cyber-au-datapack-<version>.tar.gz
~/.hermes/profiles/cyber-au/mcp/.venv/bin/cyberau-mcp datapack import cyber-au-datapack-<version>.tar.gz
```

`verify` writes nothing. `import` checks the signature against the trusted public key before it reads any file, checks each file's size and SHA-256 against the signed manifest in a staging directory inside the profile, then moves the files into place. It refuses, and writes nothing, when:

- the pack has no signature, or the signature does not match the trusted key (a changed manifest, or a pack signed by another key);
- a file differs from its manifest entry, or the pack carries a file the manifest does not list;
- any path is absolute, contains `..`, or falls outside `mcp/<connector>/data/` and `intel/snapshots/`;
- a member is a link, device or other special file, or a destination directory is a symlink;
- the pack is older than the last one imported (pass `--allow-older` to accept it on purpose).

The last import is recorded in `plugin-data/cyber-au/datapack-state.json`. Public intel snapshots land in `intel/snapshots/` beside the store. Import does not load them into the intel store or change it.

### Where the public key lives

`import` and `verify` read the trusted public key from, in order:

1. `--public-key <file>`
2. `CYBERAU_DATAPACK_PUBKEY` in the environment
3. `mcp/datapack-signing.pub` in the profile

The repository does not ship `mcp/datapack-signing.pub` yet. Until the maintainer publishes one, get the public key through a channel you trust (not the same media as the pack), and pass it with `--public-key` or set `CYBERAU_DATAPACK_PUBKEY` in the profile `.env`. With no key configured, import refuses every pack.

## Maintainer: the data pack signing key

Generate the key pair once, on a trusted machine, outside every git checkout:

```bash
mkdir -p ~/secure/cyber-au && chmod 700 ~/secure/cyber-au
uv run --project mcp cyberau-mcp datapack keygen \
  --private ~/secure/cyber-au/datapack.key \
  --public ~/secure/cyber-au/datapack-signing.pub
```

Set `CYBERAU_DATAPACK_KEY_PASSPHRASE` in your shell first to encrypt the private key. `keygen` writes the private key with mode 600, refuses to overwrite a file, and refuses a path inside a git checkout.

- The private key stays with the maintainer. Never commit it, never paste it into an issue, and never copy it to an offline host.
- To sign packs in the release workflow, store the private key PEM as the repository secret `CYBERAU_DATAPACK_SIGNING_KEY`, and the passphrase, if any, as `CYBERAU_DATAPACK_KEY_PASSPHRASE`. Without the secret the release skips the data pack.
- Publish the public key by committing `datapack-signing.pub` as `mcp/datapack-signing.pub`, and state its key id (printed by `keygen` and recorded in every pack manifest) in the release notes.
- To sign by hand: `cyberau-mcp datapack build --key <private key> --out <pack>`. `--include <path>` limits the pack to chosen files.

If the key is lost or exposed, generate a new pair, replace the secret and `mcp/datapack-signing.pub`, and tell offline sites to replace their trusted key before the next import.

## Test the bundle with no network

`tests/release/test_offline_bundle.py` builds a bundle from a small distribution with the download steps replaced, then runs `install-offline.sh` against a fake wheelhouse. `curl`, `wget`, `git` and `uv` are stubs that fail, and the proxy variables point at a closed port. The full test suite runs it with `--block-network`.

The release workflow's `offline-install` job installs the real bundle in `python:3.12-slim` (pinned by digest) with `docker run --network none`. It is informational: a failure shows on the run but does not block the release. To run the same check by hand on a machine with Docker:

```bash
bash tools/ci/offline_container_test.sh <directory holding cyber-au-offline-*.tar.gz>
```

Build a bundle locally, on Linux, with:

```bash
uv run --project mcp --frozen python tools/release/offline_bundle.py --version <version> --out dist/
```

Build it on Linux: pip evaluates platform markers against the machine it runs on. The builder needs a Python with pip on `PATH`, or `CYBERAU_PIP_PYTHON` pointing at one.

## Limits

- Hermes is not in the bundle. Its own offline install is outside this distribution.
- Wheels cover Linux x86_64 and aarch64 with Python 3.12. Other Pythons need a bundle built with `--python-version`. macOS and Windows are not covered.
- A data pack refreshes shipped snapshots only. Sources with no snapshot stay unavailable offline, and doctor says so.
- Upstream redistribution terms still apply to every snapshot in a bundle or pack. The bundle carries the same snapshots as the release tarball and no more. Check a connector's `SOURCE.md` before passing its data to another organisation.
