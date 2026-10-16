---
key: "ci-nightly-intel"
title: "CI: nightly-intel-refresh.yml: refresh threat intel snapshots and feed catalogue"
labels: ["type:task", "area:ci", "area:intel-store", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-ci"
---
## Outcome
`nightly-intel-refresh.yml` is in place and green, doing what its title says.

## Context
Refreshes public snapshots (ASD feeds, KEV, EPSS, AusCERT, ATT&CK, Feodo) every night, adds keyed sources only when their repository secret exists, validates the snapshots and opens a data PR. Needs `cyberau-mcp refresh` from the shared library and the store snapshot command.

The GitHub token used for this repo cannot push files under `.github/workflows/`, so the YAML lives here and in `ci/workflows/nightly-intel-refresh.yml`, and Justin adds it by hand (see the "add workflow files" ticket).

## Proposed `.github/workflows/nightly-intel-refresh.yml`
```yaml
# Proposed: .github/workflows/nightly-intel-refresh.yml
# Refresh public threat intel snapshots and the feed catalogue, then open a data PR.
# 16:00 UTC is 03:00 AEDT and 02:00 AEST.
name: nightly-intel-refresh

on:
  schedule:
    - cron: "0 16 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  refresh:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: python -m pip install "uv<1"
      - run: uv sync --project mcp --all-packages --frozen
      - name: Refresh snapshots (public sources first, keyed sources only when a secret is set)
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          ABUSECH_AUTH_KEY: ${{ secrets.ABUSECH_AUTH_KEY }}
          OTX_API_KEY: ${{ secrets.OTX_API_KEY }}
          CLOUDFLARE_RADAR_API_TOKEN: ${{ secrets.CLOUDFLARE_RADAR_API_TOKEN }}
          CYBERAU_DATA_DIR: ${{ runner.temp }}/cyberau
        run: |
          uv run --project mcp cyberau-mcp refresh \
            --sources asd,kev,epss,auscert,attack,feodo \
            --optional-sources nvd,abusech,otx,radar \
            --snapshot-dir intel/snapshots \
            --catalogue feeds/catalogue.yaml \
            --summary PR_BODY.md
      - name: Validate snapshots
        run: uv run --project mcp pytest -q tests/snapshots --block-network
      - uses: actions/upload-artifact@v4
        with:
          name: intel-refresh
          path: |
            intel/snapshots/
            feeds/catalogue.yaml
            PR_BODY.md

  pr:
    needs: refresh
    uses: ./.github/workflows/data-update-pr.yml
    with:
      artifact: intel-refresh
      branch_prefix: data/intel-refresh
      title: "Refresh threat intel snapshots"
      body_file: PR_BODY.md
    secrets: inherit
    permissions:
      contents: write
      pull-requests: write
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
