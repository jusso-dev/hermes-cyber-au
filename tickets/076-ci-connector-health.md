---
key: "ci-connector-health"
title: "CI: connector-health.yml: endpoint health and schema drift with auto-opened issues"
labels: ["type:task", "area:ci", "area:connectors", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-ci"
---
## Outcome
`connector-health.yml` is in place and green, doing what its title says.

## Context
Probes every connector daily, validates live responses against `schema/*.response.json`, and calls `tools/ci/open_health_issues.py`, which:
- opens one issue per broken connector titled `Connector health: <key> failing`, labelled `type:task`, `area:connectors`, `priority:p1`, `connector-health`;
- comments on the existing issue instead of opening duplicates;
- closes the issue with a comment when the connector recovers (`--close-recovered`);
- includes status code, error class, a schema diff (field added, removed, type changed) and the last good date, but never response bodies from keyed sources.

The GitHub token used for this repo cannot push files under `.github/workflows/`, so the YAML lives here and in `ci/workflows/connector-health.yml`, and Justin adds it by hand (see the "add workflow files" ticket).

## Proposed `.github/workflows/connector-health.yml`
```yaml
# Proposed: .github/workflows/connector-health.yml
# Live health and schema drift check for every connector. Opens one issue per broken
# connector, comments on repeats, and closes the issue when the connector recovers.
# 21:00 UTC is 08:00 AEDT, before the working day.
name: connector-health

on:
  schedule:
    - cron: "0 21 * * *"
  workflow_dispatch:

permissions:
  contents: read
  issues: write

jobs:
  health:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: python -m pip install "uv<1"
      - run: uv sync --project mcp --all-packages --frozen
      - name: Probe every connector and validate live responses against stored schemas
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          ABUSECH_AUTH_KEY: ${{ secrets.ABUSECH_AUTH_KEY }}
          OTX_API_KEY: ${{ secrets.OTX_API_KEY }}
          GREYNOISE_API_KEY: ${{ secrets.GREYNOISE_API_KEY }}
          CLOUDFLARE_RADAR_API_TOKEN: ${{ secrets.CLOUDFLARE_RADAR_API_TOKEN }}
          CYBERAU_DATA_DIR: ${{ runner.temp }}/cyberau
        run: |
          set +e
          uv run --project mcp cyberau-mcp health --all --live --schema-drift --json health.json
          echo "exit=$?" >> "$GITHUB_ENV"
      - uses: actions/upload-artifact@v4
        with:
          name: connector-health
          path: health.json
      - name: Open, update or close health issues
        env:
          GH_TOKEN: ${{ github.token }}
        run: python3 tools/ci/open_health_issues.py --kind connector --input health.json --close-recovered
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
