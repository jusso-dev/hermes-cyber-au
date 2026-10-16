---
key: "ci-release"
title: "CI: weekly-release.yml: weekly release packaging (CalVer tag, tarball, SBOM, provenance, GHCR image)"
labels: ["type:task", "area:ci", "area:release", "priority:p1"]
milestone: "v0.2"
parent: "epic-ci"
---
## Outcome
`weekly-release.yml` is in place and green, doing what its title says.

## Context
Runs CI, skips if nothing changed since the last tag, builds the distribution tarball and SBOM with `tools/release/package.py`, attests provenance, pushes `ghcr.io/jusso-dev/hermes-cyber-au:<YYYY.MM.DD>` and creates a GitHub release with generated notes. Manual runs default to `dry_run: true`. Note `distribution.yaml` `version` is SemVer for Hermes; the CalVer tag is the release name, and the mapping is documented in `docs/operations/releases.md`.

The GitHub token used for this repo cannot push files under `.github/workflows/`, so the YAML lives here and in `ci/workflows/weekly-release.yml`, and Justin adds it by hand (see the "add workflow files" ticket).

## Proposed `.github/workflows/weekly-release.yml`
```yaml
# Proposed: .github/workflows/weekly-release.yml
# Weekly release packaging: CalVer tag, release notes, distribution tarball, SBOM,
# checksums, and a Docker image pushed to GHCR. Friday 23:00 UTC is Saturday 10:00 AEDT.
name: weekly-release

on:
  schedule:
    - cron: "0 23 * * 5"
  workflow_dispatch:
    inputs:
      dry_run:
        type: boolean
        default: true

permissions:
  contents: read

jobs:
  ci:
    uses: ./.github/workflows/ci.yml

  package:
    needs: ci
    runs-on: ubuntu-latest
    permissions:
      contents: write
      packages: write
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: python -m pip install "uv<1"
      - name: Skip if nothing changed since the last tag
        id: changes
        run: |
          last=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
          if [ -n "$last" ] && [ -z "$(git log "$last"..HEAD --oneline)" ]; then
            echo "skip=true" >> "$GITHUB_OUTPUT"
          fi
      - name: Compute version
        if: steps.changes.outputs.skip != 'true'
        id: ver
        run: echo "version=$(TZ=Australia/Sydney date +%Y.%m.%d)" >> "$GITHUB_OUTPUT"
      - name: Build distribution tarball, SBOM and checksums
        if: steps.changes.outputs.skip != 'true'
        run: |
          uv run --project mcp python tools/release/package.py --version "${{ steps.ver.outputs.version }}" --out dist/
          sha256sum dist/* > dist/SHA256SUMS
      - uses: actions/attest-build-provenance@v2
        if: steps.changes.outputs.skip != 'true'
        with:
          subject-path: dist/*
      - name: Build and push image
        if: steps.changes.outputs.skip != 'true' && inputs.dry_run != true
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          echo "$GH_TOKEN" | docker login ghcr.io -u "${{ github.actor }}" --password-stdin
          image="ghcr.io/${{ github.repository }}:${{ steps.ver.outputs.version }}"
          docker build -f docker/Dockerfile -t "$image" .
          docker push "$image"
      - name: Tag and publish release
        if: steps.changes.outputs.skip != 'true' && inputs.dry_run != true
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          v="v${{ steps.ver.outputs.version }}"
          gh release create "$v" dist/* --title "$v" --generate-notes --target "${{ github.sha }}"
```

## Acceptance criteria
- [ ] File passes `actionlint` (it does today: `actionlint` 1.7.12, 0 errors).
- [ ] Every third-party action is pinned to a full commit SHA before merge, with the version in a comment.
- [ ] Every script the workflow calls exists and has tests.
- [ ] One successful run recorded (link in the PR), or for scheduled jobs a `workflow_dispatch` run.
- [ ] No secret is echoed; secrets are passed only as env to the step that needs them.

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
