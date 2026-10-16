from common import *

ED = "epic-docs"
EC = "epic-ci"


def wf(name: str) -> str:
    return "```yaml\n" + (WORKFLOWS / name).read_text().rstrip() + "\n```"


def docs():
    rows = [
        ("docs-site", "Docs structure and site (MkDocs Material) published from docs/", "p1", M_V01, """
## In scope
- `mkdocs.yml`, `docs/index.md`, sections: Getting started, Skills, Connectors, Routines, Intel store, Security, Operations, Contributing, Reference.
- Australian English spell check (`codespell` with an en-AU word list) and the house style check (no em dashes, no emojis).
- Published to GitHub Pages by a docs job (proposed YAML added to `ci.yml` in the workflows ticket).

## Acceptance criteria
- [ ] `mkdocs build --strict` passes.
- [ ] Every page has an owner ticket and a last-verified date.
"""),
        ("docs-quickstart", "Quick start: install, add keys, first triage, first briefing in 15 minutes", "p0", M_V01, f"""
## In scope
`docs/getting-started/quickstart.md`: install (`install.sh` or `hermes profile install github.com/jusso-dev/hermes-cyber-au --alias`), `cp .env.EXAMPLE .env`, which free keys to get first (abuse.ch, NVD), `{PROFILE} chat`, run `incident-triage` on the bundled sample alert, resume the morning briefing job.

## Acceptance criteria
- [ ] Followed verbatim on a clean VM by someone who did not write it; time recorded.
- [ ] Every command output pasted from a real run against Hermes {HERMES_RELEASE}.
"""),
        ("docs-connector-reference", "Generated connector reference pages and README connector table", "p1", M_V01, """
## In scope
- `tools/build_connector_docs.py` renders `docs/connectors/<key>.md` from `SOURCE.md`, tool input schemas and `feeds/catalogue.yaml`.
- Same script renders the README connector table between `<!-- connectors:start -->` and `<!-- connectors:end -->`.
- CI fails when generated files are stale.

## Acceptance criteria
- [ ] Every connector has a page with auth, env vars, rate limits, cache, tools and schemas, terms and attribution.
"""),
        ("docs-skill-reference", "Skill reference pages with worked examples", "p2", M_V02, """
## In scope
One page per skill: when to use it, inputs, outputs, an end-to-end example from the eval set with real (fixture) output, limits.

## Acceptance criteria
- [ ] Examples are produced by the eval harness, not hand-written.
"""),
        ("docs-data-licensing", "Data sources, licences and attribution page", "p0", M_V01, """
## In scope
`docs/reference/data-sources.md`: for each source the licence or terms, required attribution text (NVD notice, MITRE ATT&CK, Sigma DRL 1.1, Cloudflare Radar, abuse.ch fair use, OTX terms, ASD content), commercial use notes, and how the distribution complies. `NOTICE` file updated to match.

## Acceptance criteria
- [ ] Every connector's `SOURCE.md` terms line links to this page.
- [ ] Each licence statement links to the upstream terms page and records the date it was checked.
"""),
        ("docs-contributing-security", "CONTRIBUTING, SECURITY policy, code of conduct, issue and PR templates", "p1", M_V01, """
## In scope
- `CONTRIBUTING.md`: dev setup with uv, adding a connector (`cyberau-mcp new`), recording fixtures safely, house style.
- `SECURITY.md`: private vulnerability reporting through GitHub Security Advisories, supported versions, response targets.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- `.github/ISSUE_TEMPLATE/` (connector request, bug, skill request) and `PULL_REQUEST_TEMPLATE.md`. These are not workflow files, so the normal token can push them; confirm before relying on that.

## Acceptance criteria
- [ ] Private vulnerability reporting enabled on the repo (Justin, repo settings).
"""),
    ]
    out = []
    for key, title, pr, ms, body in rows:
        out.append(dict(key=key, parent=ED, milestone=ms, labels=["type:docs", "area:docs", f"priority:{pr}"],
                        title=f"Docs: {title}", body=dedent(f"## Outcome\n{title}.\n") + "\n" + dedent(body) + f"\n\n## Constraints\n{COMMON_CONSTRAINTS}"))
    return out


def ci():
    items = [
        ("ci-tests", "ci.yml: lint, offline tests, plugin doctor, distribution install smoke test", "ci.yml", "p0", M_V01, ["area:ci"], f"""
Runs on every PR and push to `main`. The `hermes` job uses the upstream image `nousresearch/hermes-agent:{HERMES_RELEASE}` to run `hermes plugins doctor --ci` ({hsrc('website/docs/developer-guide/plugins/index.md')}) and `hermes profile install` from the checkout. Supporting scripts to write in this ticket: `tools/ci/validate_repo.py` (skill frontmatter, `distribution.yaml`, catalogue schema, allowlist drift) and `tools/ci/style_check.py` (em dashes, emojis, banned private names list kept in a CI secret or a hashed list, Australian spelling hints)."""),
        ("ci-data-pr", "data-update-pr.yml: reusable auto-PR workflow for data updates", "data-update-pr.yml", "p0", M_V01, ["area:ci"], """
Every scheduled data job hands its changed files to this reusable workflow, which refuses paths outside the data directories, commits to a dated branch and opens or updates a single PR. It never pushes to `main`. Pull requests opened with `GITHUB_TOKEN` do not trigger other workflows, so CI will not run on them; set the optional `DATA_PR_TOKEN` secret (a GitHub App token or fine-grained token limited to this repo with contents and pull request write) to get CI on data PRs."""),
        ("ci-nightly-intel", "nightly-intel-refresh.yml: refresh threat intel snapshots and feed catalogue", "nightly-intel-refresh.yml", "p0", M_V01, ["area:ci", "area:intel-store"], """
Refreshes public snapshots (ASD feeds, KEV, EPSS, AusCERT, ATT&CK, Feodo) every night, adds keyed sources only when their repository secret exists, validates the snapshots and opens a data PR. Needs `cyberau-mcp refresh` from the shared library and the store snapshot command."""),
        ("ci-skill-regen", "skill-data-regen.yml: regenerate ISM, Essential Eight, Essentials and obligations data from source; re-check advisory parsers", "skill-data-regen.yml", "p0", M_V01, ["area:ci", "area:skills"], """
Rebuilds `mcp/ism/data` from the ISM OSCAL releases (keeping two), `mcp/e8/data` from the E8 baselines and the Essentials pages, `mcp/aureg/data` weekly, ATT&CK and Sigma on new releases, then regenerates skill reference files. Separately runs `cyberau-mcp parser-check` against live ASD, AusCERT, Essentials and obligations pages and opens an issue per failing parser."""),
        ("ci-connector-health", "connector-health.yml: endpoint health and schema drift with auto-opened issues", "connector-health.yml", "p0", M_V01, ["area:ci", "area:connectors"], """
Probes every connector daily, validates live responses against `schema/*.response.json`, and calls `tools/ci/open_health_issues.py`, which:
- opens one issue per broken connector titled `Connector health: <key> failing`, labelled `type:task`, `area:connectors`, `priority:p1`, `connector-health`;
- comments on the existing issue instead of opening duplicates;
- closes the issue with a comment when the connector recovers (`--close-recovered`);
- includes status code, error class, a schema diff (field added, removed, type changed) and the last good date, but never response bodies from keyed sources."""),
        ("ci-deps-hermes", "deps-and-hermes-bump.yml: weekly dependency and Hermes version bump", "deps-and-hermes-bump.yml", "p1", M_V01, ["area:ci", "area:release"], f"""
Upgrades `mcp/uv.lock` within declared bounds, checks `NousResearch/hermes-agent` releases, bumps the pinned Hermes version everywhere through `tools/hermes_pin.py` (single source `tools/hermes_pin.txt`, written into `distribution.yaml` `hermes_requires`, `docker/Dockerfile` `HERMES_VERSION`, `ci.yml` `HERMES_IMAGE`), re-verifies every fact in `docs/research/hermes-structure.md` with `tools/ci/verify_hermes_facts.py` (each fact is a check: file exists, symbol exists, string present, against the new tag), runs CI and opens a PR. Current pin: {HERMES_RELEASE}."""),
        ("ci-release", "weekly-release.yml: weekly release packaging (CalVer tag, tarball, SBOM, provenance, GHCR image)", "weekly-release.yml", "p1", M_V02, ["area:ci", "area:release"], """
Runs CI, skips if nothing changed since the last tag, builds the distribution tarball and SBOM with `tools/release/package.py`, attests provenance, pushes `ghcr.io/jusso-dev/hermes-cyber-au:<YYYY.MM.DD>` and creates a GitHub release with generated notes. Manual runs default to `dry_run: true`. Note `distribution.yaml` `version` is SemVer for Hermes; the CalVer tag is the release name, and the mapping is documented in `docs/operations/releases.md`."""),
    ]
    out = []
    for key, title, fname, pr, ms, areas, intro in items:
        body = dedent(f"""
## Outcome
`{fname}` is in place and green, doing what its title says.

## Context
{dedent(intro)}

The GitHub token used for this repo cannot push files under `.github/workflows/`, so the YAML lives here and in `ci/workflows/{fname}`, and Justin adds it by hand (see the "add workflow files" ticket).

## Proposed `.github/workflows/{fname}`
{wf(fname)}

## Acceptance criteria
- [ ] File passes `actionlint` (it does today: `actionlint` 1.7.12, 0 errors).
- [ ] Every third-party action is pinned to a full commit SHA before merge, with the version in a comment.
- [ ] Every script the workflow calls exists and has tests.
- [ ] One successful run recorded (link in the PR), or for scheduled jobs a `workflow_dispatch` run.
- [ ] No secret is echoed; secrets are passed only as env to the step that needs them.

## Constraints
{COMMON_CONSTRAINTS}
""")
        out.append(dict(key=key, parent=EC, milestone=ms, labels=["type:task", *areas, f"priority:{pr}"],
                        title=f"CI: {title}", body=body))

    out.append(dict(key="ci-justin-add-workflows", parent=EC, milestone=M_V01,
        labels=["type:task", "area:ci", "priority:p0"],
        title="Justin: add the proposed workflow files and repository secrets by hand",
        body=dedent(f"""
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
""")))
    return out


def tickets():
    return docs() + ci()
