---
key: "sec-supply-chain"
title: "Supply chain: pinned deps, SBOM, provenance, signed releases, update review"
labels: ["type:task", "area:security", "area:release", "priority:p1"]
milestone: "v0.2"
parent: "epic-security"
---
## Outcome
Installers can check what they are running and where it came from.

## Context
Hermes distributions are unsigned and installed from git ([`website/docs/user-guide/profile-distributions.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/profile-distributions.md), "Security and trust"). Cron jobs arrive paused, but SOUL and skills are live on first chat.

## In scope
- `uv.lock` committed, hashes enforced (`--frozen`).
- CycloneDX SBOM per release (`cyclonedx-py` against the lock), attached to the release.
- GitHub artifact attestations (`actions/attest-build-provenance`) for the tarball and image.
- Release notes list every changed skill, SOUL line and cron job, so updaters can review before `hermes profile update`.
- `install.sh --ref <tag>` recommended in docs over `main`.
- Dependabot config `.github/dependabot.yml` for pip (uv) and GitHub Actions, weekly. The file already exists from the earlier skill pack (GitHub Actions only, weekly); extend it rather than adding a second one:
```yaml
version: 2
updates:
  - package-ecosystem: "uv"
    directory: "/mcp"
    schedule: {interval: "weekly", day: "monday", time: "09:00", timezone: "Australia/Sydney"}
    open-pull-requests-limit: 5
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: {interval: "weekly", day: "monday", time: "09:00", timezone: "Australia/Sydney"}
```
(Check that Dependabot supports the `uv` ecosystem name at implementation time; fall back to `pip`.)

## Acceptance criteria
- [ ] `gh attestation verify` succeeds for a release asset.
- [ ] SBOM lists every runtime dependency in the lock.
- [ ] Release notes generator test covers SOUL, skills and cron diffs.

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
