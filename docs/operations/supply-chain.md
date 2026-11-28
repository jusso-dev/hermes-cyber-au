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

`.github/workflows/weekly-release.yml` is the release job. When it runs, `actions/attest-build-provenance` attests the files in `dist/` after the packaging step has written them. The image is built, pushed and attested only when `docker/Dockerfile` exists, which it does not yet. When the run pushes the container image, the same action attests that image using the digest from `docker push`.

GitHub Actions produces the attestation from the workflow identity. This repository does not contain a signing key.

The offline install bundle (`cyber-au-offline-<version>.tar.gz`) is one of the attested files. Data packs carry a separate Ed25519 signature that an offline host can check without reaching Sigstore. The private key for it is held by the maintainer, never in this repository. See [offline install](offline.md).

After you download a published asset, check it with:

```bash
gh attestation verify cyber-au-<version>.tar.gz --repo jusso-dev/hermes-cyber-au
gh attestation verify cyber-au-<version>.cdx.json --repo jusso-dev/hermes-cyber-au
```

Verification applies to a file that workflow has attested.

## Review before you update

The release notes list every changed line in `SOUL.md`, every changed skill under `skills/`, and every changed cron job in `cron/jobs.json`. Read them before `hermes profile update`. New cron jobs arrive paused. `SOUL.md` and skills apply on the next chat.

## Known dependency advisories

**DiskCache unsafe pickle (CVE-2025-69872, GHSA-w8v5-vhqr-4h9v), issue #180.** `mcp/uv.lock` pins `pysigma==1.5.1`, which depends on `diskcache==5.6.3`. GitHub lists no patched `diskcache` release. pySigma 2.0.2 and later replace it with the `diskcache-community` fork (`>=5.8.1,<6`), which adds `SafeDisk` and refuses pickled entries, and pySigma 2 opens its ATT&CK and D3FEND caches with `SafeDisk`.

The upgrade cannot be resolved yet. Checked against PyPI on 28 November 2026:

| Package | Latest release | pySigma it accepts |
|---|---|---|
| `pysigma-backend-elasticsearch` | 2.1.1 | `>=1.4.0,<2.0.0` |
| `pysigma-backend-kusto` | 1.0.1 | `>=1.0.0,<2.0.0` |
| `pysigma-backend-splunk` | 3.0.1 | `>=2.0.1,<3.0.0` |

The Elasticsearch backend has merged pySigma 2 support upstream (SigmaHQ/pySigma-backend-elasticsearch pull request 235) but has not released it. The Kusto backend has no pySigma 2 release or open change. The Sigma connector converts to all three targets, so moving to pySigma 2 now would mean dropping Kusto and Lucene conversion. That is not done.

Until both backends publish pySigma 2 releases, the limitation stays: the connector never imports DiskCache itself, and points pySigma's cache at a private, mode 700 directory under the connector data directory, so no other user can plant an entry for it to load (`mcp/sigma/src/cyberau_sigma/source.py`, `_private_pysigma_cache`). When the backends release, raise `pysigma` to `>=2.0.2,<3`, move the three backend pins, run `uv lock --project mcp`, confirm `diskcache==` is gone from `mcp/uv.lock`, and run `mcp/sigma/tests`.

