---
key: "ci-skill-regen"
title: "CI: skill-data-regen.yml: regenerate ISM, Essential Eight, Essentials and obligations data from source; re-check advisory parsers"
labels: ["type:task", "area:ci", "area:skills", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-ci"
---
## Outcome
`skill-data-regen.yml` is in place and green, doing what its title says.

## Context
Rebuilds `mcp/ism/data` from the ISM OSCAL releases (keeping two), `mcp/e8/data` from the E8 baselines and the Essentials pages, `mcp/aureg/data` weekly, ATT&CK and Sigma on new releases, then regenerates skill reference files. Separately runs `cyberau-mcp parser-check` against live ASD, AusCERT, Essentials and obligations pages and opens an issue per failing parser.

The GitHub token used for this repo cannot push files under `.github/workflows/`, so the YAML lives here and in `ci/workflows/skill-data-regen.yml`, and Justin adds it by hand (see the "add workflow files" ticket).

## Proposed `.github/workflows/skill-data-regen.yml`
```yaml
# Proposed: .github/workflows/skill-data-regen.yml
# Regenerate bundled skill data from source (ISM OSCAL, Essential Eight and ASD Essentials,
# AU reporting obligations, ATT&CK, Sigma) and re-check every advisory parser against live pages.
# 17:00 UTC daily is 04:00 AEDT.
name: skill-data-regen

on:
  schedule:
    - cron: "0 17 * * *"
  workflow_dispatch:
    inputs:
      force:
        description: Rebuild even if upstream versions did not change
        type: boolean
        default: false

permissions:
  contents: read
  issues: write

jobs:
  regen:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    outputs:
      parser_failures: ${{ steps.parsers.outputs.failures }}
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: python -m pip install "uv<1"
      - run: uv sync --project mcp --all-packages --frozen
      - name: ISM from OSCAL (latest release plus the one before)
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: uv run --project mcp cyberau-mcp regen ism --keep 2 ${{ inputs.force && '--force' || '' }}
      - name: Essential Eight maturity data and ASD Essentials chapters
        run: uv run --project mcp cyberau-mcp regen e8 ${{ inputs.force && '--force' || '' }}
      - name: AU reporting obligations (weekly, Mondays Sydney time)
        run: |
          if [ "$(TZ=Australia/Sydney date +%u)" = "1" ] || [ "${{ inputs.force }}" = "true" ]; then
            uv run --project mcp cyberau-mcp regen aureg
          fi
      - name: ATT&CK and Sigma when a new release exists
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          uv run --project mcp cyberau-mcp regen attack
          uv run --project mcp cyberau-mcp regen sigma
      - name: Rebuild skill reference files from data
        run: uv run --project mcp python tools/build_skill_references.py --write PR_BODY.md
      - name: Re-check advisory parsers against live pages
        id: parsers
        run: |
          set +e
          uv run --project mcp cyberau-mcp parser-check --sources asd,auscert,e8,aureg --json parser-check.json
          echo "failures=$(jq '[.[] | select(.ok == false)] | length' parser-check.json)" >> "$GITHUB_OUTPUT"
          exit 0
      - name: Regression tests on regenerated data
        run: uv run --project mcp pytest -q tests/skills tests/data --block-network
      - uses: actions/upload-artifact@v4
        with:
          name: skill-data
          path: |
            mcp/ism/data/
            mcp/e8/data/
            mcp/aureg/data/
            mcp/attack/data/
            mcp/sigma/data/
            skills/
            PR_BODY.md
      - uses: actions/upload-artifact@v4
        with:
          name: parser-check
          path: parser-check.json

  parser-issue:
    needs: regen
    if: needs.regen.outputs.parser_failures != '0'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/download-artifact@v4
        with:
          name: parser-check
      - name: Open or update one issue per failing parser
        env:
          GH_TOKEN: ${{ github.token }}
        run: python3 tools/ci/open_health_issues.py --kind parser --input parser-check.json

  pr:
    needs: regen
    uses: ./.github/workflows/data-update-pr.yml
    with:
      artifact: skill-data
      branch_prefix: data/skill-regen
      title: "Regenerate skill data from source"
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
