# asd-ism

- Upstream: https://github.com/AustralianCyberSecurityCentre/ism-oscal
- Auth: none. Optional GITHUB_TOKEN for the GitHub releases API.
- Rate limit: at most 10 GitHub requests an hour in this connector. Raw release files are cached for 7 days. The release list is cached for 12 hours.
- Terms: The ism-oscal README states Creative Commons Attribution 4.0 International and © Commonwealth of Australia 2024, except the Coat of Arms, the ASD logo, and where otherwise stated. The cyber.gov.au copyright page says to attribute website material as © Commonwealth of Australia 2026. Record the release tag and SHA-256 with every answer. This connector is not endorsed by ASD. See [Data sources, licences and attribution](../../docs/reference/data-sources.md).
- Verified: 2026-10-17
- Egress hosts: api.github.com, raw.githubusercontent.com

OSCAL control ids look like `ism-1173`. Numeric forms `1173` and `ISM-1173` normalise to that id, zero-padded to four digits. Principle ids such as `ism-principle-gov-01` are used as published.

The shipped data is the full upstream `ISM_catalog.json` and all eight baseline profiles for the two newest releases, `v2026.09.4` and `v2026.06.18`, retrieved on 18 October 2026. `data/releases.json` records the release list and its `retrieved_on` date. Baseline membership comes from the OSCAL profile `with-ids` list. For a release that is not shipped, the profile is fetched from GitHub.

The fallback ladder is a live fetch, then the HTTP cache, then the shipped copy, then an empty result with an `unavailable` warning. A shipped catalogue for a named release is a published, unchanging document, so it is served with `cache: snapshot` and a warning that names its retrieval date. The shipped release list decides which release is the latest, so it is refused once it is more than 180 days old (`SNAPSHOT_MAX_AGE_DAYS`). Then a call without `release` returns the `unavailable` warning, and a call that names a release still works. `CYBERAU_ISM_SNAPSHOT` points at a directory laid out like `data/`. It is the operator's choice, so it is used as is with no age check. The tests use it with small excerpts under `tests/fixtures/`.

`cyberau-mcp regen ism --fetch` (run by the skill data workflow) downloads the newest two releases again through this connector's egress policy and rewrites `data/`.
