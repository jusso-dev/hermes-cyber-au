# Data sources, licences and attribution

This distribution's own code is under the Apache License, Version 2.0. See [LICENSE](../../LICENSE). Data fetched by a connector stays under that source's terms. This page records the licence or terms, the attribution text, commercial use, and how the distribution complies.

Each statement below links to the upstream page and records the date it was checked. Short notices are repeated in [NOTICE](../../NOTICE). The wording here is a summary. It is not a copy of a full licence.

## NIST National Vulnerability Database

Connector: [`mcp/nvd`](../../mcp/nvd/SOURCE.md).

- Terms: [NVD Terms of Use](https://nvd.nist.gov/developers/terms-of-use). The same check covered [Getting Started](https://nvd.nist.gov/developers/start-here).
- Checked: 17 October 2026. The terms text was read from the NVD site bundle served for those URLs.

The Getting Started page says NIST publications are in the public domain under Title 17 of the United States Code. The Terms of Use are conditions on API access, not a separate SPDX licence. They ask any service that uses the API to display a notice, and they say the NVD name must not be used to imply endorsement of a product, service, or entity, whether commercial or not. If API content is modified, it must not be attributed to the NVD. Access is subject to the rate limits published at [nvd.nist.gov/developers](https://nvd.nist.gov/developers). Exceeding those limits can block access.

The Terms of Use notice is: "This product uses the NVD API but is not endorsed or certified by the NVD."

Getting Started and the general FAQ use a longer sentence. This distribution shows that longer sentence on every NVD result:

> This product uses data from the NVD API but is not endorsed or certified by the NVD.

Commercial use of the data is allowed. The NVD name must not be used to imply that the NVD endorses this project or a commercial product. An API key, when set, is the operator's own key.

Compliance: the notice above is the connector's attribution string. Descriptions are returned as data inside the result envelope. The connector keeps to the published rate limits: 5 requests per rolling 30 seconds without a key, and 50 with a key.

## CISA Known Exploited Vulnerabilities

Connector: [`mcp/cisa-kev`](../../mcp/cisa-kev/SOURCE.md).

- Terms: [KEV licence notice](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt), which states Creative Commons Zero 1.0. Legal code: [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/legalcode).
- Checked: 17 October 2026.

The notice at the top of that file, before the CC0 legal code, says:

> The KEV database is distributed under the Creative Commons 0 1.0 License. You may use this data in any legal manner but note that information provided at any 3rd party links included in the KEV database are bound by the policies and licenses of those 3rd party websites. Use of the information does not authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an endorsement by CISA or DHS.

CC0 does not require a copyright notice. This distribution still names the source and keeps the catalogue's `dateAdded` field. The attribution string is:

> CISA Known Exploited Vulnerabilities catalog. US Government work.

Commercial use is allowed ("any legal manner"). The CISA logo and the DHS seal are not used. Links inside a KEV record stay under the terms of those other sites.

Compliance: the attribution string is returned with each result. Records keep `dateAdded`. The catalogue JSON is downloaded at most once every 6 hours.

## FIRST EPSS

Connector: [`mcp/first-epss`](../../mcp/first-epss/SOURCE.md).

- Terms: [EPSS FAQ](https://www.first.org/epss/faq) ("Is EPSS free to use?"). Access details: [Get the Data](https://www.first.org/epss/data). Home page: [first.org/epss](https://www.first.org/epss/).
- Checked: 17 October 2026.

The FAQ says EPSS scores are published freely by CSV and API, with no registration, and that attribution is requested when EPSS data is used in publications or products. It points to Get the Data for attribution guidance. On 17 October 2026 that data page described API and CSV access and did not include a citation sentence or a named licence. The EPSS home page had no Usage Agreement heading. The site footer claims copyright for the Forum of Incident Response and Security Teams, Inc.

No licence name is recorded here beyond those pages. This distribution's attribution string is:

> FIRST EPSS. Cite the model version and the score date.

Commercial use is not forbidden by the pages checked. Attribution is still requested for a product. The public API is for lookup, not for bulk copies of every score. The connector batches at most 100 CVEs per call and stays under 1,000 requests a minute.

Compliance: every EPSS result carries the attribution string. Callers are told to cite the model version and the score date from the response.

## ASD ACSC alerts, advisories and publications

Connector: [`mcp/asd-acsc`](../../mcp/asd-acsc/SOURCE.md).

- Terms: [Copyright | Cyber.gov.au](https://www.cyber.gov.au/about-us/copyright). Licence: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). Legal code: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/legalcode).
- Checked: 17 October 2026.

The copyright page says material on the website is provided under CC BY 4.0, except:

- the Commonwealth Coat of Arms
- the Australian Cyber Security Centre logo
- content supplied by third parties
- other material specifically not provided under a CC BY 4.0 licence

Attribution required by that page:

> © Commonwealth of Australia 2026

Attribute the material to the Australian Signals Directorate. Third-party copyright stays with the third party.

CC BY 4.0 allows commercial use when the attribution is kept and the excluded material is left out. This project is not endorsed by ASD. The Coat of Arms and the ACSC logo are not included.

The attribution string is:

> Commonwealth of Australia material from ASD's ACSC (cyber.gov.au). Confirm the current licence at https://www.cyber.gov.au/about-us/copyright. This connector is not endorsed by ASD.

Compliance: the attribution string is returned with each result. The offline test snapshot is synthetic. Live items, when a fetch succeeds, remain Commonwealth material under the copyright page.

## Information Security Manual (ISM) OSCAL

Connector: [`mcp/asd-ism`](../../mcp/asd-ism/SOURCE.md).

- Terms: copyright section of the [ism-oscal README](https://github.com/AustralianCyberSecurityCentre/ism-oscal). The README points to [cyber.gov.au/ism/oscal](https://www.cyber.gov.au/ism/oscal) as the authoritative source. The site-wide statement is the [cyber.gov.au copyright page](https://www.cyber.gov.au/about-us/copyright). Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- Checked: 17 October 2026.

GitHub's licence API reported no licence file for `AustralianCyberSecurityCentre/ism-oscal` on that date. The README copyright notice says © Commonwealth of Australia 2024, and that material in that publication is under CC BY 4.0 except the Coat of Arms, the Australian Signals Directorate logo, and where otherwise stated.

The cyber.gov.au copyright page, checked the same day, says website material is attributed as © Commonwealth of Australia 2026. Both notices are recorded. The distribution does not choose between them.

The attribution string is:

> Information Security Manual content is published by the Australian Signals Directorate. This connector is not endorsed by ASD.

Commercial use of the CC BY 4.0 material is allowed with attribution. The Coat of Arms and the ASD logo are not included. Shipped catalogues are 20-control excerpts of releases `v2026.06.18` and `v2026.09.4`, not the full manual.

Compliance: every answer records the release tag and the source SHA-256. The attribution string states that ASD publishes the content and does not endorse this connector.

## Sources not in this checkout

These sources are named in the data-licensing work. They have no `SOURCE.md` on this branch. No licence is recorded for them here.

- MITRE ATT&CK is not in this checkout.
- Sigma is not in this checkout.
- Cloudflare Radar is not in this checkout.
- abuse.ch is not in this checkout.
- AlienVault OTX is not in this checkout.
