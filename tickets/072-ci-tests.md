---
key: "ci-tests"
title: "CI: ci.yml: lint, offline tests, plugin doctor, distribution install smoke test"
labels: ["type:task", "area:ci", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-ci"
---
## Outcome
`ci.yml` is in place and green, doing what its title says.

## Context
Runs on every PR and push to `main`. The `hermes` job uses the upstream image `nousresearch/hermes-agent:v0.22.2` to run `hermes plugins doctor --ci` ([`website/docs/developer-guide/plugins/index.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/developer-guide/plugins/index.md)) and `hermes profile install` from the checkout. Supporting scripts to write in this ticket: `tools/ci/validate_repo.py` (skill frontmatter, `distribution.yaml`, catalogue schema, allowlist drift) and `tools/ci/style_check.py` (em dashes, emojis, banned private names list kept in a CI secret or a hashed list, Australian spelling hints).

The GitHub token used for this repo cannot push files under `.github/workflows/`, so the YAML lives here and in `ci/workflows/ci.yml`, and Justin adds it by hand (see the "add workflow files" ticket).

## Proposed `.github/workflows/ci.yml`
```yaml
# Proposed: .github/workflows/ci.yml
# Lint, offline tests with recorded fixtures, plugin doctor and a distribution install smoke test.
name: ci

on:
  pull_request:
  push:
    branches: [main]
  workflow_call:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

env:
  HERMES_IMAGE: nousresearch/hermes-agent:v0.22.2   # bumped by deps-and-hermes-bump.yml

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: python -m pip install "uv<1"
      - run: uv sync --project mcp --all-packages --frozen
      - run: uv run --project mcp ruff check .
      - run: uv run --project mcp ruff format --check .
      - name: Validate skills, manifests and catalogue
        run: uv run --project mcp python tools/ci/validate_repo.py
      - name: House style (Australian English, no em dashes, no emojis, no private names)
        run: uv run --project mcp python tools/ci/style_check.py

  test:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: python -m pip install "uv<1"
      - run: uv sync --project mcp --all-packages --frozen
      - name: Unit and fixture tests (network blocked)
        run: uv run --project mcp pytest -q --block-network --record-mode=none --cov=cyberau_common --cov-report=xml
      - name: STIX export validates
        run: uv run --project mcp pytest -q tests/intel/test_stix_export.py --block-network
      - uses: actions/upload-artifact@v4
        with:
          name: coverage
          path: coverage.xml

  hermes:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v7
      - name: Plugin doctor
        run: |
          docker run --rm -v "$PWD:/src:ro" "$HERMES_IMAGE" plugins doctor /src/plugins/cyber-au --ci
      - name: Distribution install smoke test
        run: |
          docker run --rm -v "$PWD:/src:ro" -e HERMES_HOME=/tmp/hh "$HERMES_IMAGE" \
            profile install /src --name cyber-au-ci --yes
      - name: Bootstrap and doctor inside the image
        run: |
          docker run --rm -v "$PWD:/src:ro" --entrypoint bash "$HERMES_IMAGE" -lc '
            set -euo pipefail
            hermes profile install /src --name cyber-au-ci --yes
            /src/install/bootstrap.sh --profile cyber-au-ci --non-interactive --offline
            hermes -p cyber-au-ci cyber-au doctor --offline --json'
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
