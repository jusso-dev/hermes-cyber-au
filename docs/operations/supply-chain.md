# Supply chain

Installers can check what they are running and where it came from.

## Install a release tag

Use `install.sh --ref <tag>`:

```bash
bash install/install.sh --ref <tag>
```

The branch `main` is not a release. A tag names the commit that the release notes, the SBOM and the attestation refer to.

## Lockfile

`mcp/uv.lock` pins every distribution and records its SHA-256. CI installs with `uv sync --frozen`. The release job runs `uv run --frozen`. An install that does not match the lock fails.

Direct dependencies in `mcp/pyproject.toml` carry an upper bound. Dependabot opens weekly pull requests for the uv lock under `mcp/` and for GitHub Actions. The schedule is Monday 09:00 Australia/Sydney, in `.github/dependabot.yml`.

## SBOM

`tools/release/package.py` exports the locked runtime requirements (`uv export --frozen`, development dependencies omitted) and runs `cyclonedx-py requirements` on that export. The CycloneDX JSON it writes is `cyber-au-<version>.cdx.json`. The release workflow attaches that file, the tarball, the notes, `provenance.json` and `SHA256SUMS` to the GitHub release. In a git checkout the tarball holds only tracked files, so local caches and untracked files cannot enter a release.

`provenance.json` records the release version, the distribution version, the git commit when the tree is a git checkout, whether a tracked file differs from that commit (`git_dirty`), and the SHA-256 of `mcp/uv.lock`. It also records the `cyclonedx-py` version that wrote the SBOM.

## Attestation

`ci/workflows/weekly-release.yml` is the release job. A maintainer copies it to `.github/workflows/` before GitHub will run it. When it runs, `actions/attest-build-provenance` attests the files in `dist/` after the packaging step has written them. The image is built, pushed and attested only when `docker/Dockerfile` exists, which it does not yet. When the run pushes the container image, the same action attests that image using the digest from `docker push`.

GitHub Actions produces the attestation from the workflow identity. This repository does not contain a signing key.

After you download a published asset, check it with:

```bash
gh attestation verify cyber-au-<version>.tar.gz --repo jusso-dev/hermes-cyber-au
gh attestation verify cyber-au-<version>.cdx.json --repo jusso-dev/hermes-cyber-au
```

Verification applies to a file that workflow has attested.

## Review before you update

The release notes list every changed line in `SOUL.md`, every changed skill under `skills/`, and every changed cron job in `cron/jobs.json`. Read them before `hermes profile update`. New cron jobs arrive paused. `SOUL.md` and skills apply on the next chat.
