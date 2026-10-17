# hermes-cyber-au

A planned [Hermes Agent](https://github.com/NousResearch/hermes-agent) distribution for Australian cyber security teams.

Install it once and you get an analyst assistant that knows the ISM, the Essential Eight and the new ASD Essentials, reads ASD's ACSC and AusCERT as they publish, pulls in global threat intel, keeps a local intel store, and writes you a briefing before you've finished your coffee. It proposes actions. It doesn't take them.

> **Status: planned.** Nothing is implemented yet. This repository holds the design and the build plan as GitHub issues. Start with the roadmap issue, then the epics.

## What it will do

- **Triage incidents** with Australian context: ASD's ACSC categorisation, ATT&CK mapping, containment proposals, and a check for NDB, SOCI and ransomware payment reporting triggers.
- **Enrich indicators** across abuse.ch, OTX, GreyNoise, Shodan InternetDB, crt.sh and Cloudflare Radar, deduplicated into one verdict with sources.
- **Assess Essential Eight maturity and ASD Essentials progress** from evidence you supply, including M365-Secure reports. Both frameworks, because ASD is running them side by side during the transition.
- **Look up ISM controls** by id, keyword or baseline, from the release that was in force on the date you ask about. If a control isn't in the snapshot, it says "I don't know".
- **Prioritise vulnerabilities** with KEV, EPSS, CVSS, ASD and AusCERT mentions, your asset list, and Essential Eight patching timeframes.
- **Digest ASD's ACSC advisories** and AusCERT bulletins since the last digest, grouped by what to do today, this week, and what to know.
- **Analyse phishing**: headers, SPF, DKIM and DMARC, lookalike domains of Australian brands, hash lookups. No detonation.
- **Hunt with Sigma and KQL** for Microsoft Sentinel and Defender, with offline query checks.
- **Walk through an OAIC Notifiable Data Breach assessment** and draft the statement. A person submits it.
- **Decide SOCI Act reportability** and compute the 12 and 72 hour deadlines in Sydney time.
- **Write executive and board briefings** in plain Australian English.
- **Run routines**: hourly feed ingest, a 07:30 Sydney briefing, a KEV watch against your assets, and a weekly executive summary. All arrive paused so you choose what runs.

## How it fits together

| Piece | Where | What it is |
|---|---|---|
| Profile distribution | `distribution.yaml`, `SOUL.md`, `config.yaml` | Installed with `hermes profile install`, updated with `hermes profile update` |
| Skills | `skills/<name>/SKILL.md` | The eleven workflows above |
| Connectors | `mcp/<source>/` | Read-only stdio MCP servers on a shared HTTP client with an egress allowlist, caching and rate limiting |
| Plugin | `plugins/cyber-au/` | Intel store tools, audit log hooks, untrusted-content guards, the `cyber-au` command |
| Intel store | `plugin-data/cyber-au/intel.sqlite` | SQLite with canonical dedupe and STIX 2.1 export |
| Routines | `cron/jobs.json`, `scripts/` | Scheduled jobs, shipped paused |
| Automation | `ci/workflows/` | Proposed GitHub Actions: CI, nightly intel refresh, skill data regeneration, connector health, dependency and Hermes bumps, weekly releases |

The Hermes details behind this design (manifest fields, what an update replaces, MCP config, plugin hooks, cron rules) are written up with sources in [docs/research/hermes-structure.md](docs/research/hermes-structure.md).

## Planned install

```bash
# Once v0.1 ships. Not yet.
hermes profile install github.com/jusso-dev/hermes-cyber-au --alias
cp ~/.hermes/profiles/cyber-au/.env.EXAMPLE ~/.hermes/profiles/cyber-au/.env
cyber-au chat
```

It works with no API keys using public sources. Each free key you add (abuse.ch, NVD, OTX, GreyNoise, a Cloudflare Radar read token) turns on more sources.

## Connectors

<!-- connectors:start -->
Connectors with a `SOURCE.md` in this checkout. Planned sources without a connector directory are listed in [docs/research/connectors.md](docs/research/connectors.md).

| Connector | Server | Auth | Default | Docs |
|---|---|---|---|---|
| ASD ACSC alerts, advisories and publications | `asd` | none | on | [docs/connectors/asd-acsc.md](docs/connectors/asd-acsc.md) |
| Information Security Manual OSCAL catalogue | `ism` | `GITHUB_TOKEN` (optional) | on | [docs/connectors/asd-ism.md](docs/connectors/asd-ism.md) |
| CISA Known Exploited Vulnerabilities catalogue | `kev` | none | on | [docs/connectors/cisa-kev.md](docs/connectors/cisa-kev.md) |
| FIRST EPSS scores | `epss` | none | on | [docs/connectors/first-epss.md](docs/connectors/first-epss.md) |
| NIST National Vulnerability Database CVE API | `nvd` | `NVD_API_KEY` (optional) | on | [docs/connectors/nvd.md](docs/connectors/nvd.md) |
<!-- connectors:end -->

Full detail, including what was verified and when: [docs/research/connectors.md](docs/research/connectors.md).

## Premium feeds (paid, bring your own licence)

Teams that already pay for commercial intel can plug it in. First up in v0.2 are Recorded Future (identity exposure, dark web and ransomware brand alerts, domain abuse) and Flare (leaked credentials, stealer logs, leak and ransomware sites), both with optional use of the vendor's own MCP server, plus UpGuard (identity breaches, data leaks and typosquats; an Australian vendor). Later connectors cover infostealer and breach exposure (Hudson Rock, SpyCloud) and more threat intel platforms with dark web and leak site monitoring (Flashpoint, Intel 471, Google Threat Intelligence DTM, CrowdStrike Recon, SOCRadar, DarkOwl). The free ransomware.live tracker adds leak site claims naming Australian organisations.

- Every premium connector is off by default. You bring your own licence key through the profile `.env`; nothing is bundled.
- Each vendor has terms flags: what may be cached, stored, exported as STIX or shared. Defaults are conservative until your contract says otherwise.
- Quota and budget limits stop runaway spend.
- Exposure data can contain personal information. It is redacted, kept for 90 days by default, and never sent anywhere automatically. Nothing contacts the OAIC, ASD, victims or vendors for you.
- An "AU org exposure" skill and a paused alert routine match findings against a watchlist of your own domains, ABNs and brands.

The paid connectors described in this section are tracked in [docs/research/connectors.md](docs/research/connectors.md) until each one has a connector directory in this checkout.

## Safety

- Read-only by default. Anything that sends, blocks, posts or submits needs a person to approve it.
- Content from feeds is treated as data, never as instructions.
- Secrets live in your profile `.env` and are referenced as `${VAR}`. Nothing secret is shipped, logged or exported.
- Connectors can only reach the hosts listed for them.
- Every tool call is written to a hash-chained audit log.

## Not affiliated

This project is independent. It is not affiliated with or endorsed by the Australian Signals Directorate, the Australian Cyber Security Centre, the OAIC, the Cyber and Infrastructure Security Centre, Nous Research or any data provider. Its output is guidance, not legal advice or a formal assessment.

## Related projects

This repository used to hold a smaller Hermes skill and plugin pack for Australian cyber guidance. It is now a full Hermes profile distribution: connectors, a local intel store, scheduled routines and agent security controls, as well as skills. It is not a skill pack any more.

- **The earlier skill pack** is kept unchanged on the [`legacy-skills-pack`](https://github.com/jusso-dev/hermes-cyber-au/tree/legacy-skills-pack) branch and the [`legacy-skills-pack-final`](https://github.com/jusso-dev/hermes-cyber-au/releases/tag/legacy-skills-pack-final) tag (commit `02b500c49ca08f5d558107e58a42a9c68a617566`). If you installed it from this repository, pin to that commit, for example `hermes plugins install jusso-dev/hermes-cyber-au --force --ref 02b500c49ca08f5d558107e58a42a9c68a617566` (Hermes takes a full 40 character commit SHA for `--ref`), or move to the maintained copy below.
- [jusso-dev/hermes-skills](https://github.com/jusso-dev/hermes-skills): where the skill pack now lives and gets updates. Install it with `hermes plugins install jusso-dev/hermes-skills/plugins/hermes-cyber-au`. How this distribution reuses it is tracked in an issue.
- [AustralianCyberSecurityCentre/ism-oscal](https://github.com/AustralianCyberSecurityCentre/ism-oscal): ISM in OSCAL, the source for ISM and Essential Eight data.

## Licence

Apache License 2.0. See [LICENSE](LICENSE). Data from each source stays under that source's terms; see the data licensing issue and, once written, `docs/reference/data-sources.md`.
