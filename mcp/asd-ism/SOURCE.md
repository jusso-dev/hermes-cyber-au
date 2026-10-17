# asd-ism

- Upstream: https://github.com/AustralianCyberSecurityCentre/ism-oscal
- Auth: none. Optional GITHUB_TOKEN for the GitHub releases API.
- Rate limit: at most 10 GitHub requests an hour in this connector. Raw release files are cached for 7 days. The release list is cached for 12 hours.
- Terms: The ism-oscal README states Creative Commons Attribution 4.0 International and © Commonwealth of Australia 2024, except the Coat of Arms, the ASD logo, and where otherwise stated. The cyber.gov.au copyright page says to attribute website material as © Commonwealth of Australia 2026. Record the release tag and SHA-256 with every answer. This connector is not endorsed by ASD. See [Data sources, licences and attribution](../../docs/reference/data-sources.md).
- Verified: 2026-10-17
- Egress hosts: api.github.com, raw.githubusercontent.com

OSCAL control ids look like `ism-1173`. Numeric forms `1173` and `ISM-1173` normalise to that id, zero-padded to four digits. Principle ids such as `ism-principle-gov-01` are used as published.

The shipped catalogues are 20-control excerpts of `v2026.06.18` and `v2026.09.4`, retrieved on 17 October 2026. Baseline membership for the excerpt comes from the OSCAL profile `with-ids` list.
