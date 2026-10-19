# Your first hour

Eleven prompts that show what the cyber-au profile is good at. None of them needs a key. Each one names the skill it should load and what a good answer looks like.

Start a chat with `hermes -p cyber-au chat` (or `cyber-au chat`) from the root of your checkout, so the `examples/` paths resolve. If you installed without a checkout, the same files are in `~/.hermes/profiles/cyber-au/examples/`. Use that path in the prompt instead.

The files under `examples/` are **DEMO DATA**: a fictional organisation, RFC 5737 addresses and `example.com` domains. Live lookups about them come back empty, and a good answer says so. The CVE ids in the prompts are real, so KEV and EPSS answers are real and sourced.

Want an answer before you choose a model? Run the offline demo first:

```bash
hermes -p cyber-au cyber-au demo triage
```

It triages `examples/edr-alert.json` against a synthetic demo intel set and labels every part of its output as demo. See [Demo mode](#demo-mode) below.

## The prompts

| # | Skill | Prompt | A good answer |
|---|---|---|---|
| 1 | `incident-triage` | Triage the alert in examples/edr-alert.json. It is demo data. | Restates the alert in Sydney time, defangs 203[.]0[.]113[.]45 and update[.]example[.]net, maps the beacon to T1071.001, gives a local severity with reasons, lists containment as `Proposal:` lines, checks NDB, SOCI and ransomware payment triggers, and ends with `Source:` lines. |
| 2 | `phishing-analysis` | Analyse the email in examples/phishing-email.eml. Is it phishing, and what should we look for in our mail logs? | Points out the SPF and DMARC failures, the Reply-To mismatch and the lookalike payroll domain, lists the indicators defanged, and suggests log searches. It does not open the link or detonate the attachment. |
| 3 | `ioc-enrichment` | Enrich the indicators in examples/iocs.txt and give one verdict per indicator with sources. | One row per indicator with the sources it checked. The documentation-range addresses and example domains come back with no data, and the answer says so instead of guessing. Keyed sources that are off are named as missing. |
| 4 | `vuln-prioritisation` | Is CVE-2023-4966 in the CISA KEV catalogue, and what is its EPSS score? | Yes or no from the live KEV catalogue with the catalogue version, the EPSS score and percentile with its date, and `Source:` lines for both. |
| 5 | `vuln-prioritisation` | Prioritise patching for the assets in examples/assets.csv using KEV, EPSS and the Essential Eight patching timeframes. | Ranks the internet-facing NetScaler and Log4j hosts first because their CVEs are in KEV, gives the Essential Eight timeframe for each, and cites KEV, EPSS and the Essential Eight source. |
| 6 | `ism-control-lookup` | Which ISM controls cover multi-factor authentication for privileged users? Cite the ISM release. | Lists control ids and text from the bundled ISM release with its version. If a control is not in the snapshot it says it does not know. |
| 7 | `essentials-assessment` | What does Essential Eight Maturity Level 2 require for patching applications? | Quotes the Maturity Level 2 requirements for patching applications with timeframes, and cites the Essential Eight maturity model release it used. |
| 8 | `daily-briefing` | Write this morning's briefing from public sources only. | A short briefing in Sydney time from ASD's ACSC, AusCERT and new KEV entries, each item with a source line. Sources that could not be reached are listed as missing. |
| 9 | `ndb-breach-notification` | Using examples/incident-timeline.md, could this be an eligible data breach under the NDB scheme, and when does the 30 day assessment window end? | Says personal information (bank details) may have been accessed, that serious harm has not been ruled out, works out the 30 calendar day assessment window from the awareness time in Sydney time, and says it is not legal advice and that a person decides and submits. |
| 10 | `soci-reporting` | Using examples/incident-timeline.md and examples/assets.csv, does this incident trigger a SOCI Act report? | Notes that the SOCI asset SCADA-DEMO-03 shows no sign of access, explains which facts would open the 12 and 72 hour clocks in Sydney time, and does not submit anything. |
| 11 | `pspf-risk-assessment` | Do a PSPF threat and risk assessment of APP-DEMO-07 in examples/assets.csv and draft its security risk management plan. Our risk tolerance is medium. | Asks for the entity's risk matrix, who set the tolerance and the risk steward, and marks what is not supplied as missing. Looks up Log4j in KEV and the ISM patching control, rates the risk on the labelled default matrix as a proposal for the steward, lists treatments as `Proposal:` lines with owners and due dates, gives the PSPF review dates, and says it is not an IRAP assessment and was not sent. |

`hermes -p cyber-au cyber-au demo prompts` prints the same list.

What every answer should have, whatever the prompt:

- A `Source:` line for each fact that came from a tool or a reference, with a version and a date.
- "Source missing" for a connector that is off or did not answer, instead of a made-up result.
- Proposals, not actions. Nothing is sent, blocked, submitted or posted.
- Feed text treated as data. An instruction found inside an alert, email or feed is reported, not followed.

If an answer has none of that, run `hermes -p cyber-au cyber-au doctor` and check that the connectors show as enabled.

## Demo mode

Demo mode gives you a sourced answer with no keys, no model and no network. It is clearly fake and kept apart from real intelligence.

| Command | What it does |
|---|---|
| `hermes -p cyber-au cyber-au demo triage` | Triages `examples/edr-alert.json` offline and prints a triage record. |
| `hermes -p cyber-au cyber-au demo triage --json` | The same record as JSON, with `"demo": true`. |
| `hermes -p cyber-au cyber-au demo prompts` | Prints the ten prompts above. |
| `hermes -p cyber-au cyber-au demo load` | Writes the synthetic intel set to a separate demo store, `plugin-data/cyber-au/demo/intel-demo.sqlite`. |
| `hermes -p cyber-au cyber-au demo clear` | Deletes that demo store. |

From a checkout with only Python 3.11 or newer, before anything is installed, `python3 plugins/cyber-au/demo triage` and `python3 plugins/cyber-au/demo prompts` work too.

How the demo stays apart from real data:

- `demo triage` reads only files marked `"demo": true`. Point it at a real alert and it refuses, so synthetic intel is never matched against a real alert. Use the `incident-triage` skill in a chat for real alerts.
- `demo triage` never opens a store. It reads `plugins/cyber-au/demo/dataset.json`.
- `demo load` writes to its own file under `plugin-data/cyber-au/demo/`, never to `intel.sqlite`. It refuses to write into a directory that holds a real store, or into a non-empty directory without its `DEMO-DATA.txt` marker. Every record has the source `cyber-au-demo`, the tag `demo` and a note that starts with `DEMO:`.
- Output starts with `DEMO MODE: synthetic data. Nothing below is real threat intelligence.` and ends with a line that says not to act on it or share it as real.

To browse the demo store, pass its path. The real store is not used:

```bash
~/.hermes/profiles/cyber-au/mcp/.venv/bin/cyberau-mcp store search DemoLoader \
  --path ~/.hermes/profiles/cyber-au/plugin-data/cyber-au/demo/intel-demo.sqlite
```

The dashboard and the scheduled briefing do not read the demo store.
