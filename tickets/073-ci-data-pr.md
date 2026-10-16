---
key: "ci-data-pr"
title: "CI: data-update-pr.yml: reusable auto-PR workflow for data updates"
labels: ["type:task", "area:ci", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-ci"
---
## Outcome
`data-update-pr.yml` is in place and green, doing what its title says.

## Context
Every scheduled data job hands its changed files to this reusable workflow, which refuses paths outside the data directories, commits to a dated branch and opens or updates a single PR. It never pushes to `main`. Pull requests opened with `GITHUB_TOKEN` do not trigger other workflows, so CI will not run on them; set the optional `DATA_PR_TOKEN` secret (a GitHub App token or fine-grained token limited to this repo with contents and pull request write) to get CI on data PRs.

The GitHub token used for this repo cannot push files under `.github/workflows/`, so the YAML lives here and in `ci/workflows/data-update-pr.yml`, and Justin adds it by hand (see the "add workflow files" ticket).

## Proposed `.github/workflows/data-update-pr.yml`
```yaml
# Proposed: .github/workflows/data-update-pr.yml
# Reusable workflow. Callers regenerate data into the working tree, upload it as an artifact,
# and this workflow commits it to a dated branch and opens or updates one pull request.
# It never pushes to main.
name: data-update-pr

on:
  workflow_call:
    inputs:
      artifact:
        description: Artifact holding the changed files (paths relative to repo root)
        required: true
        type: string
      branch_prefix:
        required: true
        type: string
      title:
        required: true
        type: string
      body_file:
        description: Path inside the artifact to a Markdown PR body
        required: true
        type: string
      labels:
        required: false
        type: string
        default: "type:task,area:ci"
      allowed_paths:
        description: Extended regex of paths the caller may change
        required: false
        type: string
        default: '^(mcp/[a-z0-9-]+/data/|feeds/|intel/snapshots/|skills/[a-z0-9-]+/references/|PR_BODY\.md$)'
    secrets:
      DATA_PR_TOKEN:
        description: Optional fine-grained token or GitHub App token so the PR triggers CI. Falls back to GITHUB_TOKEN.
        required: false

permissions:
  contents: write
  pull-requests: write

jobs:
  pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          token: ${{ secrets.DATA_PR_TOKEN || github.token }}
      - uses: actions/download-artifact@v4
        with:
          name: ${{ inputs.artifact }}
          path: .
      - name: Refuse unexpected paths
        env:
          ALLOWED: ${{ inputs.allowed_paths }}
        run: |
          git status --porcelain --untracked-files=all | awk '{print $2}' > changed.txt
          if grep -vE "$ALLOWED" changed.txt; then
            echo "Data update touched files outside the data paths. Refusing." >&2
            exit 1
          fi
      - name: Commit, push and open or update the pull request
        env:
          GH_TOKEN: ${{ secrets.DATA_PR_TOKEN || github.token }}
          BRANCH_PREFIX: ${{ inputs.branch_prefix }}
          TITLE: ${{ inputs.title }}
          BODY_FILE: ${{ inputs.body_file }}
          LABELS: ${{ inputs.labels }}
        run: |
          set -euo pipefail
          if git diff --quiet && [ -z "$(git ls-files --others --exclude-standard | grep -v '^changed.txt$' || true)" ]; then
            echo "No change. No pull request."
            exit 0
          fi
          branch="${BRANCH_PREFIX}/$(TZ=Australia/Sydney date +%F)"
          git config user.name "cyber-au data bot"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git checkout -B "$branch"
          git add -A -- . ':!changed.txt' ':!PR_BODY.md'
          git commit -m "$TITLE"
          git push --force-with-lease origin "$branch"
          existing=$(gh pr list --head "$branch" --json number --jq '.[0].number // empty')
          if [ -n "$existing" ]; then
            gh pr edit "$existing" --body-file "$BODY_FILE"
          else
            gh pr create --base main --head "$branch" --title "$TITLE" --body-file "$BODY_FILE" --label "$LABELS"
          fi
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
