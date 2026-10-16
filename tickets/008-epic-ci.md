---
key: "epic-ci"
title: "Epic: GitHub Actions, data automation and releases"
labels: ["type:epic", "area:ci", "area:release", "priority:p0"]
milestone: "v0.1 MVP"
parent: "roadmap"
---
## Outcome
CI, nightly intel refresh, skill data regeneration, connector health with auto issues, dependency and Hermes bumps, weekly releases, auto-PRs.

## Sub-issues
Linked as GitHub sub-issues. Checklist mirrors them by milestone.

### v0.1 MVP
- [ ] {{ref:ci-tests}} CI: ci.yml: lint, offline tests, plugin doctor, distribution install smoke test (p0)
- [ ] {{ref:ci-data-pr}} CI: data-update-pr.yml: reusable auto-PR workflow for data updates (p0)
- [ ] {{ref:ci-nightly-intel}} CI: nightly-intel-refresh.yml: refresh threat intel snapshots and feed catalogue (p0)
- [ ] {{ref:ci-skill-regen}} CI: skill-data-regen.yml: regenerate ISM, Essential Eight, Essentials and obligations data from source; re-check advisory parsers (p0)
- [ ] {{ref:ci-connector-health}} CI: connector-health.yml: endpoint health and schema drift with auto-opened issues (p0)
- [ ] {{ref:ci-deps-hermes}} CI: deps-and-hermes-bump.yml: weekly dependency and Hermes version bump (p1)
- [ ] {{ref:ci-justin-add-workflows}} Justin: add the proposed workflow files and repository secrets by hand (p0)

### v0.2
- [ ] {{ref:ci-release}} CI: weekly-release.yml: weekly release packaging (CalVer tag, tarball, SBOM, provenance, GHCR image) (p1)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
