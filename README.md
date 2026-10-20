# hermes-cyber-au

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/jusso-dev/hermes-cyber-au)

A [Hermes Agent](https://github.com/NousResearch/hermes-agent) distribution for Australian cyber security teams.

Install it once and you get an analyst assistant that knows the ISM, the Essential Eight and ASD Essentials, reads ASD's ACSC and AusCERT, pulls in global threat intel, keeps a local intel store, and can write a briefing. It proposes actions. It does not take them.

`main` contains the connectors, skills, intel store, plugin, routines, and Docker image recipe. There is no release tag yet. Choose a model in Hermes before a chat or a briefing can run. Scheduled jobs arrive paused. Hindsight stays off until `HINDSIGHT_BASE_URL` is set.

## What it does

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
- **Run PSPF threat and risk assessments and draft security risk management plans** (SRMPs) for an entity, a system, the internet-facing estate (Technology Security Risk Management Plan), a facility or a project. Threats come from the intel connectors with sources, ratings come from your risk matrix (or a labelled default), and the plan is checked against the PSPF Release 2026 security plan elements, risk tolerance, risk stewards and review dates. Acceptance and approval stay with the Accountable Authority or Authorising Officer.
- **Write executive and board briefings** in plain Australian English.
- **Run routines**: hourly feed ingest, a 07:30 Sydney briefing, a KEV watch against your assets, and a weekly executive summary. All arrive paused so you choose what runs.

## How it fits together

| Piece | Where | What it is |
|---|---|---|
| Profile distribution | `distribution.yaml`, `SOUL.md`, `config.yaml` | Installed with `hermes profile install`, updated with `hermes profile update` |
| Skills | `skills/<name>/SKILL.md` | Triage, enrichment, essentials, ISM lookup, vulnerability priority, ACSC digest, phishing, hunting, NDB, SOCI, PSPF risk assessment and SRMP, executive briefing, daily briefing, and AU org exposure |
| Connectors | `mcp/<source>/` | Read-only stdio MCP servers on a shared HTTP client with an egress allowlist, caching and rate limiting |
| Plugin | `plugins/cyber-au/` | Intel store tools, audit log hooks, untrusted-content guards, `cyber-au doctor`, update, and migrate |
| Intel store | `plugin-data/cyber-au/intel.sqlite` | SQLite with canonical dedupe, retention, and STIX 2.1 export |
| Roles | `profiles/overlays/` | Watcher, analyst, skeptic, briefer, and librarian. Hermes installs one home, so each role is a separate install plus an overlay. See [profiles/README.md](profiles/README.md). |
| Routines | `cron/jobs.json`, `scripts/` | Scheduled jobs. Hermes pauses them on install. See [docs/operations/routines.md](docs/operations/routines.md). |
| Image | `docker/` | `nousresearch/hermes-agent` with this profile installed. See [docker/README.md](docker/README.md). |
| Automation | `.github/workflows/` | Checks run on every pull request and push to `main`. Nightly intel refresh, connector health, skill data regeneration, weekly dependency and Hermes bumps, and weekly releases run on schedules; data changes arrive as pull requests. |

The Hermes details behind this design (manifest fields, what an update replaces, MCP config, plugin hooks, cron rules) are written up with sources in [docs/research/hermes-structure.md](docs/research/hermes-structure.md).

## Quick start

You need Linux, macOS or WSL2 with `git`, `curl`, Python 3.11 or newer and [uv](https://docs.astral.sh/uv/). On Debian or Ubuntu also install `libatomic1`, which the Hermes installer needs. Hermes 0.22.2 or newer is installed for you if it is missing. No key is needed.

```bash
git clone https://github.com/jusso-dev/hermes-cyber-au.git
cd hermes-cyber-au
bash install/install.sh                           # Hermes if missing, the profile, keyless connectors
hermes -p cyber-au cyber-au doctor --offline      # public connectors show as enabled
hermes -p cyber-au cyber-au demo triage           # a sourced answer now: no keys, no model, DEMO data
hermes -p cyber-au model                          # choose a model provider
hermes -p cyber-au chat                           # then ask one of the prompts below
```

`demo triage` triages a synthetic sample alert offline and labels all of its output as demo. It never reads or writes your real intel store. The full walk-through, with output from a clean Ubuntu 24.04 container, is in [docs/getting-started/quickstart.md](docs/getting-started/quickstart.md). To try it with nothing installed, open the repository in GitHub Codespaces or a VS Code dev container: see [docs/getting-started/codespaces.md](docs/getting-started/codespaces.md).

`main` is not a release tag. For a pinned install use `bash install/install.sh --ref <tag>`. Supply-chain checks are in [docs/operations/supply-chain.md](docs/operations/supply-chain.md). Scheduled jobs arrive paused; `hermes -p cyber-au cron resume cyberau-morning-brief` turns on the 07:30 Sydney briefing. Details are in [docs/operations/routines.md](docs/operations/routines.md).

## What can I ask it?

No keys needed. Run the chat from the root of your checkout so the `examples/` paths resolve. The files in [examples/](examples/) are synthetic demo data.

- Triage the alert in examples/edr-alert.json. It is demo data.
- Is CVE-2023-4966 in the CISA KEV catalogue, and what is its EPSS score?
- Which ISM controls cover multi-factor authentication for privileged users? Cite the ISM release.
- What does Essential Eight Maturity Level 2 require for patching applications?
- Using examples/incident-timeline.md, could this be an eligible data breach under the NDB scheme, and when does the 30 day assessment window end?
- Do a PSPF threat and risk assessment of APP-DEMO-07 in examples/assets.csv and draft its security risk management plan. Our risk tolerance is medium.

Eleven prompts, the skill each one uses and what a good answer looks like are in [docs/getting-started/first-hour.md](docs/getting-started/first-hour.md).

## Connectors

<!-- connectors:start -->
Connectors with a `SOURCE.md` in this checkout. Planned sources without a connector directory are listed in [docs/research/connectors.md](docs/research/connectors.md).

| Connector | Server | Auth | Default | Docs |
|---|---|---|---|---|
| Abuse.ch connector: URLhaus, ThreatFox, MalwareBazaar and Feodo Tracker | `abusech` | `ABUSECH_AUTH_KEY` | off: licence terms | [docs/connectors/abusech.md](docs/connectors/abusech.md) |
| AbuseIPDB IP reputation. Reporting an address is not implemented | `abuseipdb` | `ABUSEIPDB_API_KEY` | off: licence terms | [docs/connectors/abuseipdb.md](docs/connectors/abuseipdb.md) |
| ASD ACSC alerts, advisories and publications | `asd` | none | on | [docs/connectors/asd-acsc.md](docs/connectors/asd-acsc.md) |
| ASD Blueprint for Secure Cloud lookup | `blueprint` | none | off: licence terms | [docs/connectors/asd-blueprint.md](docs/connectors/asd-blueprint.md) |
| Essential Eight and ASD Essentials connector | `e8` | none | off: licence terms | [docs/connectors/asd-essentials.md](docs/connectors/asd-essentials.md) |
| Information Security Manual OSCAL catalogue | `ism` | `GITHUB_TOKEN` (optional) | on | [docs/connectors/asd-ism.md](docs/connectors/asd-ism.md) |
| Australian reporting obligations | `aureg` | none | on | [docs/connectors/au-regulatory.md](docs/connectors/au-regulatory.md) |
| AusCERT public security bulletins | `auscert` | none | off: licence terms | [docs/connectors/auscert.md](docs/connectors/auscert.md) |
| CISA Known Exploited Vulnerabilities catalogue | `kev` | none | on | [docs/connectors/cisa-kev.md](docs/connectors/cisa-kev.md) |
| Cloudflare Radar telemetry through the Radar REST API | `cloudflare_radar` | `CLOUDFLARE_RADAR_API_TOKEN` | off: licence terms | [docs/connectors/cloudflare-radar.md](docs/connectors/cloudflare-radar.md) |
| Cloudflare URL Scanner. Submits are Unlisted and approval-gated | `cfscan` | `CLOUDFLARE_URLSCAN_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | off: licence terms | [docs/connectors/cloudflare-urlscanner.md](docs/connectors/cloudflare-urlscanner.md) |
| CrowdStrike Falcon Adversary Intelligence Recon connector | `csrecon` | `FALCON_CLIENT_ID` (optional), `FALCON_CLIENT_SECRET` (optional), `FALCON_BASE_URL` (optional) | off | [docs/connectors/crowdstrike-recon.md](docs/connectors/crowdstrike-recon.md) |
| Crt.sh certificate transparency search | `crtsh` | none | off: licence terms | [docs/connectors/crtsh.md](docs/connectors/crtsh.md) |
| Read RSS and Atom feeds the user turned on in watchlists.yaml, read only | `custom_feeds` | none | on | [docs/connectors/custom-feeds.md](docs/connectors/custom-feeds.md) |
| CVE Program records from the CVE Services API | `cve` | none | on | [docs/connectors/cve-program.md](docs/connectors/cve-program.md) |
| DarkOwl Vision search | `darkowl` | none | off | [docs/connectors/darkowl.md](docs/connectors/darkowl.md) |
| Data.gov.au CKAN catalogue | `datagov` | none | on | [docs/connectors/datagov-au.md](docs/connectors/datagov-au.md) |
| FIRST EPSS scores | `epss` | none | on | [docs/connectors/first-epss.md](docs/connectors/first-epss.md) |
| Flare tools. Tenant searches are the default. Nothing here creates identifiers | `flare` | `FLARE_API_KEY` (optional), `FLARE_TENANT_ID` (optional) | off | [docs/connectors/flare.md](docs/connectors/flare.md) |
| Flashpoint Ignite indicators | `flashpoint` | `FLASHPOINT_API_TOKEN` | off | [docs/connectors/flashpoint.md](docs/connectors/flashpoint.md) |
| github-advisories | `ghsa` | `GITHUB_ADVISORY_TOKEN` | off: requires local setup | [docs/connectors/github-advisories.md](docs/connectors/github-advisories.md) |
| Google Threat Intelligence Digital Threat Monitoring connector | `gtidtm` | `GTI_API_KEY` | off | [docs/connectors/google-ti-dtm.md](docs/connectors/google-ti-dtm.md) |
| GreyNoise Community IP classification | `greynoise` | `GREYNOISE_API_KEY` (optional) | on | [docs/connectors/greynoise.md](docs/connectors/greynoise.md) |
| Read-only, pinned wrap of the official Have I Been Pwned MCP server | `hibp` | `HIBP_API_KEY` | on | [docs/connectors/hibp.md](docs/connectors/hibp.md) |
| MCP tools for Hindsight and the local handoff queue | `hindsight` | `HINDSIGHT_API_KEY` | off | [docs/connectors/hindsight.md](docs/connectors/hindsight.md) |
| Hudson Rock Cavalier connector | `hudsonrock` | `HUDSONROCK_API_KEY` | off | [docs/connectors/hudson-rock.md](docs/connectors/hudson-rock.md) |
| Intel 471 Titan alerts. Watchers are not created or edited | `intel471` | `INTEL471_EMAIL`, `INTEL471_API_KEY` | off | [docs/connectors/intel471.md](docs/connectors/intel471.md) |
| IRAP guidance from cyber.gov.au | `irap` | none | on | [docs/connectors/irap.md](docs/connectors/irap.md) |
| Junction (Microsoft Graph, Defender, Sentinel) | `junction` | none | off | [docs/connectors/junction.md](docs/connectors/junction.md) |
| MISP connector for a user-supplied instance, including AusMISP | `misp` | `MISP_URL`, `MISP_API_KEY` | off | [docs/connectors/misp.md](docs/connectors/misp.md) |
| MITRE ATT&CK (STIX 2.1) connector | `attack` | none | on | [docs/connectors/mitre-attack.md](docs/connectors/mitre-attack.md) |
| NCSC NZ alerts (formerly CERT NZ) | `ncscnz` | none | off: licence terms | [docs/connectors/ncsc-nz.md](docs/connectors/ncsc-nz.md) |
| NIST National Vulnerability Database CVE API | `nvd` | `NVD_API_KEY` (optional) | on | [docs/connectors/nvd.md](docs/connectors/nvd.md) |
| GraphQL client for a user-supplied OpenCTI instance | `opencti` | `OPENCTI_URL`, `OPENCTI_TOKEN` | off | [docs/connectors/opencti.md](docs/connectors/opencti.md) |
| OpenPhish community feed. Never requests the URL under test | `phish` | none | off: licence terms | [docs/connectors/openphish.md](docs/connectors/openphish.md) |
| OSV.dev open source vulnerabilities | `osv` | none | on | [docs/connectors/osv.md](docs/connectors/osv.md) |
| AlienVault OTX indicators and subscribed pulses | `otx` | `OTX_API_KEY` | on | [docs/connectors/otx.md](docs/connectors/otx.md) |
| PhishTank verified-online phishing URL database | `phish` | `PHISHTANK_APP_KEY` (optional) | off: no entry in `mcp/servers.yaml` | [docs/connectors/phishtank.md](docs/connectors/phishtank.md) |
| Status tool for the shared premium interface. It does not call a vendor | `premium` | none | off: no entry in `mcp/servers.yaml` | [docs/connectors/premium.md](docs/connectors/premium.md) |
| Protective Security Policy Framework quotations | `pspf` | none | off: licence terms | [docs/connectors/pspf.md](docs/connectors/pspf.md) |
| Ransomware.live victim claims for Australia | `ransomlive` | `RANSOMWARE_LIVE_API_KEY` (optional) | off: licence terms | [docs/connectors/ransomware-live.md](docs/connectors/ransomware-live.md) |
| Recorded Future tools on the shared premium client | `recordedfuture`, `recordedfuture_mcp` | `RECORDED_FUTURE_API_TOKEN` (optional), `RECORDED_FUTURE_ORG_ID` (optional), `RECORDED_FUTURE_MCP_CLIENT_ID` (optional), `RECORDED_FUTURE_MCP_CLIENT_SECRET` (optional) | off | [docs/connectors/recorded-future.md](docs/connectors/recorded-future.md) |
| Scamwatch homepage alerts | `scamwatch` | none | off: licence terms | [docs/connectors/scamwatch.md](docs/connectors/scamwatch.md) |
| Shodan InternetDB lookups | `internetdb` | none | off: licence terms | [docs/connectors/shodan-internetdb.md](docs/connectors/shodan-internetdb.md) |
| SigmaHQ detection rules | `sigma` | `GITHUB_TOKEN` (optional) | on | [docs/connectors/sigma.md](docs/connectors/sigma.md) |
| SOCRadar company incidents connector | `socradar` | `SOCRADAR_API_KEY`, `SOCRADAR_COMPANY_ID` | off | [docs/connectors/socradar.md](docs/connectors/socradar.md) |
| Spamhaus DROP, DROPv6 and ASN-DROP lists | `drop` | none | off: licence terms | [docs/connectors/spamhaus-drop.md](docs/connectors/spamhaus-drop.md) |
| SpyCloud Enterprise Protection connector | `spycloud` | `SPYCLOUD_API_KEY` | off | [docs/connectors/spycloud.md](docs/connectors/spycloud.md) |
| TAXII 2.1 client for a user-supplied API root | `taxii` | `TAXII_USERNAME`, `TAXII_PASSWORD` | off | [docs/connectors/taxii-ctis.md](docs/connectors/taxii-ctis.md) |
| Assessments from a ThreatSieve instance the operator already runs | `threatsieve` | `THREATSIEVE_API_KEY` (optional) | off: requires local setup | [docs/connectors/threatsieve.md](docs/connectors/threatsieve.md) |
| UpGuard CyberRisk connector | `upguard` | `UPGUARD_API_KEY` | off | [docs/connectors/upguard.md](docs/connectors/upguard.md) |
| virustotal | `virustotal` | `VTAI_TOKEN` | off: licence terms | [docs/connectors/virustotal.md](docs/connectors/virustotal.md) |
<!-- connectors:end -->

Full detail, including what was verified and when: [docs/research/connectors.md](docs/research/connectors.md).

## Dashboard

`dashboard/server.py` is a small read-only web page for a less technical team. It lists each routine with its schedule, delivery target and last recorded status, shows the newest report each routine wrote, lists handoffs, and shows a snapshot of each conversation Hermes has stored. A snapshot is the latest turns in that session. The system prompt and tool arguments are left out, and secret-shaped text is redacted. Sibling profiles under the same `profiles/` directory are included, so the watcher, analyst, skeptic, briefer, and librarian each appear when they have a session store. The page also says whether a chat has been opened. It uses only the Python 3.11+ standard library and never runs a job. The morning briefing is set for 07:30 Australia/Sydney, and jobs do nothing until they are resumed.

```bash
python3 dashboard/server.py --profile ~/.hermes/profiles/cyber-au
```

Then open <http://127.0.0.1:8765/>. Without `--profile` it uses `$CYBERAU_PROFILE_HOME`, else `/opt/data/profiles/cyber-au` if that directory exists, else `~/.hermes/profiles/cyber-au`. `--bind` (default `127.0.0.1`) and `--port` (default `8765`) change where it listens. Handoffs come from `<profile>/handoffs.jsonl` or `$CYBERAU_DATA_DIR/handoffs.jsonl`.

The Sources page (`/sources`) lists every feed in `feeds/catalogue.yaml` with its server state, whether its key was set at the last bootstrap, last success, last error, item count, data age, cache state and licence. It reads files only. See [docs/dashboard.md](docs/dashboard.md).

The dashboard has no login. Keep it on `127.0.0.1`, or on a homelab publish it only on the LAN or Tailscale address, never the public internet. It answers only requests whose `Host` header is the bind address, `localhost`, `127.0.0.1`, `::1`, or a name given with `--allowed-host` (repeatable) or `CYBERAU_DASHBOARD_ALLOWED_HOSTS` (comma separated). Any other host gets 421, which stops a web page reading it through DNS rebinding. `dashboard/Dockerfile` builds a container that serves `/opt/data/profiles/cyber-au` on `0.0.0.0:8765` inside the container:

```bash
docker build -f dashboard/Dockerfile -t cyberau-dashboard .
docker run -d --name cyberau-dashboard -v /path/to/hermes-data:/opt/data:ro \
  -e CYBERAU_DASHBOARD_ALLOWED_HOSTS=192.168.1.10 \
  -p 192.168.1.10:8765:8765 cyberau-dashboard
```

Replace `192.168.1.10` with the host's LAN or Tailscale address, in both places, and add any DNS name you browse to. The container runs as uid 10000, the same user that owns a Hermes home, and the volume should be mounted read-only. Tests: `python3 -m pytest tests/dashboard`.

## Premium feeds (paid, bring your own licence)

Paid connectors are in this checkout and off by default. They cover Recorded Future, Flare, UpGuard, Hudson Rock, SpyCloud, Flashpoint, Intel 471, Google Threat Intelligence DTM, CrowdStrike Recon, SOCRadar, and DarkOwl. The free ransomware.live tracker adds leak-site claims that name Australian organisations.

- Every premium connector is off by default. You bring your own licence key through the profile `.env`; nothing is bundled.
- Each vendor has terms flags: what may be cached, stored, exported as STIX or shared. Defaults are conservative until your contract says otherwise.
- Quota and budget limits stop runaway spend.
- Exposure data can contain personal information. It is redacted, kept for 90 days by default, and never sent anywhere automatically. Nothing contacts the OAIC, ASD, victims or vendors for you.
- An "AU org exposure" skill and a paused alert routine match findings against a watchlist of your own domains, ABNs and brands.

Pages for those connectors are in the table above. Terms flags are under [docs/premium/README.md](docs/premium/README.md).

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

Apache License 2.0. See [LICENSE](LICENSE). Data from each source stays under that source's terms. See [Data sources, licences and attribution](docs/reference/data-sources.md).
