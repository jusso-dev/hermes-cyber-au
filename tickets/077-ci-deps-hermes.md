---
key: "ci-deps-hermes"
title: "CI: deps-and-hermes-bump.yml: weekly dependency and Hermes version bump"
labels: ["type:task", "area:ci", "area:release", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-ci"
---
## Outcome
`deps-and-hermes-bump.yml` is in place and green, doing what its title says.

## Context
Upgrades `mcp/uv.lock` within declared bounds, checks `NousResearch/hermes-agent` releases, bumps the pinned Hermes version everywhere through `tools/hermes_pin.py` (single source `tools/hermes_pin.txt`, written into `distribution.yaml` `hermes_requires`, `docker/Dockerfile` `HERMES_VERSION`, `ci.yml` `HERMES_IMAGE`), re-verifies every fact in `docs/research/hermes-structure.md` with `tools/ci/verify_hermes_facts.py` (each fact is a check: file exists, symbol exists, string present, against the new tag), runs CI and opens a PR. Current pin: v0.22.2.

The GitHub token used for this repo cannot push files under `.github/workflows/`, so the YAML lives here and in `ci/workflows/deps-and-hermes-bump.yml`, and Justin adds it by hand (see the "add workflow files" ticket).

## Proposed `.github/workflows/deps-and-hermes-bump.yml`
```yaml
# Proposed: .github/workflows/deps-and-hermes-bump.yml
# Weekly: upgrade the uv lockfile within declared bounds, check for a new Hermes release,
# bump the pinned Docker image, CI image and hermes_requires floor, run CI, and open a PR.
# Monday 22:00 UTC is Tuesday 09:00 AEDT.
name: deps-and-hermes-bump

on:
  schedule:
    - cron: "0 22 * * 1"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  bump:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: python -m pip install "uv<1"
      - name: Upgrade Python dependencies within bounds
        run: uv lock --project mcp --upgrade
      - name: Check latest Hermes release
        id: hermes
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          latest=$(gh api repos/NousResearch/hermes-agent/releases/latest --jq .tag_name)
          current=$(python3 tools/hermes_pin.py get)
          echo "latest=$latest" >> "$GITHUB_OUTPUT"
          echo "current=$current" >> "$GITHUB_OUTPUT"
      - name: Bump Hermes pins and re-verify documented structure
        if: steps.hermes.outputs.latest != steps.hermes.outputs.current
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          python3 tools/hermes_pin.py set "${{ steps.hermes.outputs.latest }}"
          # Re-check every fact in docs/research/hermes-structure.md against the new tag.
          uv run --project mcp python tools/ci/verify_hermes_facts.py --tag "${{ steps.hermes.outputs.latest }}" --report hermes-facts.md
      - name: Write PR body
        run: |
          {
            echo "Weekly dependency and Hermes bump."
            echo
            echo "Hermes: ${{ steps.hermes.outputs.current }} -> ${{ steps.hermes.outputs.latest }}"
            echo
            echo '```'
            git diff --stat
            echo '```'
            [ -f hermes-facts.md ] && cat hermes-facts.md
          } > PR_BODY.md
      - uses: actions/upload-artifact@v4
        with:
          name: deps-bump
          path: |
            mcp/uv.lock
            distribution.yaml
            docker/Dockerfile
            tools/hermes_pin.txt
            PR_BODY.md

  ci:
    needs: bump
    uses: ./.github/workflows/ci.yml

  pr:
    needs: [bump, ci]
    uses: ./.github/workflows/data-update-pr.yml
    with:
      artifact: deps-bump
      branch_prefix: deps/weekly
      title: "Weekly dependency and Hermes bump"
      body_file: PR_BODY.md
      labels: "type:task,area:ci,area:release"
      allowed_paths: '^(mcp/uv\.lock|distribution\.yaml|docker/Dockerfile|tools/hermes_pin\.txt|PR_BODY\.md)$'
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
