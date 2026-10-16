---
key: "ci-justin-add-workflows"
title: "Justin: add the proposed workflow files and repository secrets by hand"
labels: ["type:task", "area:ci", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-ci"
---
## Outcome
The workflows under `ci/workflows/` are live in `.github/workflows/`, with the secrets they read.

## Why this is manual
The automation token for this repo cannot create or update files under `.github/workflows/` (it lacks the `workflow` scope). A person with that permission has to add them.

## Steps
0. Retire the two workflows left over from the earlier skill pack. They still sit in `.github/workflows/` on `main` and fail against the new tree, because both run `pip install -e .` and there is no `pyproject.toml` any more:
   - `.github/workflows/daily-refresh.yml` ("knowledge refresh"): scheduled `0 19 * * *` and `0 20 * * *` UTC, plus manual dispatch. It runs `scripts/cyber_au_refresh.py` and opens `knowledge-refresh/<date>` PRs.
   - `.github/workflows/pr.yml` ("checks"): runs on every pull request and every push to `main`.
   Disable both straight away (`gh workflow disable "knowledge refresh"` and `gh workflow disable checks`, or Actions tab > workflow > Disable), then delete both files in the same PR as step 3 (`git rm .github/workflows/daily-refresh.yml .github/workflows/pr.yml`). The earlier versions stay on the `legacy-skills-pack` branch. Delete the stale `knowledge-refresh/*` branches when you're ready.
1. Wait until the scripts each workflow calls exist (see the linked CI tickets), or add `ci.yml` first and the rest as their scripts land.
2. Pin third-party actions to commit SHAs.
3. From a local clone with a token or SSH key that has the workflow permission:
```bash
mkdir -p .github/workflows
git mv ci/workflows/*.yml .github/workflows/
git commit -m "Add CI and scheduled data workflows"
git push origin HEAD:add-workflows
gh pr create --title "Add CI and scheduled data workflows" --body "Moves the proposed workflows into .github/workflows."
```
4. Add repository secrets (Settings > Secrets and variables > Actions). All optional; jobs skip the matching sources when a secret is missing:

| Secret | Used by | How to get it |
|---|---|---|
| `NVD_API_KEY` | nightly refresh, connector health | https://nvd.nist.gov/developers/request-an-api-key |
| `ABUSECH_AUTH_KEY` | nightly refresh, connector health | https://auth.abuse.ch/ |
| `OTX_API_KEY` | nightly refresh, connector health | OTX account settings |
| `GREYNOISE_API_KEY` | connector health | GreyNoise account |
| `CLOUDFLARE_RADAR_API_TOKEN` | nightly refresh, connector health | Custom token, Account > Radar > Read only |
| `DATA_PR_TOKEN` | data-update-pr | GitHub App or fine-grained token, this repo only, contents and pull requests write |

5. Settings > Actions > General: allow GitHub Actions to create pull requests; workflow permissions read by default.
6. Create the `connector-health` label.
7. Enable private vulnerability reporting.

## Acceptance criteria
- [ ] `daily-refresh.yml` and `pr.yml` are gone from `main` and no longer run.
- [ ] All seven workflows visible in the Actions tab.
- [ ] `ci.yml` green on `main`.
- [ ] One manual run of each scheduled workflow completes or fails only for a documented missing-script reason.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
