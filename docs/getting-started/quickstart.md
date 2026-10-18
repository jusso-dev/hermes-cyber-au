# Quick start

From a clone to a sourced answer with no keys. You get a demo triage with no keys and no model, then a live answer from public sources once you choose a model.

**When this was run:** 18 October 2026 (Australia/Sydney), in a clean `ubuntu:24.04` container as a normal user, with Hermes Agent v0.22.2. Every command on this page was run there, except the two that need a model provider (`hermes -p cyber-au model` and `chat`). From a bare container to the first demo answer took 704 seconds: 33 for `apt-get`, 514 for `install/install.sh` (Hermes, the profile and the connector environment), and the rest for uv, doctor and the demo. Output below is trimmed. Nothing in it was a key.

Prefer not to install anything? Use [Codespaces or a dev container](codespaces.md) instead.

## 1. Prerequisites

| You need | Why |
|---|---|
| Linux, macOS or WSL2 | `install/install.sh` stops on anything else. |
| `git`, `curl` | Clone, and the Hermes and uv installers. |
| Python 3.11 or newer | Bootstrap and the plugin. |
| [uv](https://docs.astral.sh/uv/) | Bootstrap stops without it. It builds the connector environment. |
| `libatomic1` on Debian or Ubuntu | The Hermes installer's Node runtime needs it. Without it the Hermes install fails. |
| A model provider | Only for `chat` and briefings (step 6). Not needed for steps 1 to 5. |

Hermes 0.22.2 or newer is installed for you in step 3 if `hermes` is not on your PATH.

On Ubuntu 24.04:

```bash
sudo apt-get install -y git curl ca-certificates python3 libatomic1
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv --version
```

```text
uv 0.13.1 (x86_64-unknown-linux-gnu)
```

Read any `curl | sh` installer before you run it.

## 2. Clone

```bash
git clone https://github.com/jusso-dev/hermes-cyber-au.git
cd hermes-cyber-au
```

## 3. Install

```bash
bash install/install.sh
```

This does three things, in order:

1. Installs Hermes with the upstream installer if `hermes` is missing. It shows the command and asks first. Pass `--yes` to skip the question.
2. Installs this checkout as the `cyber-au` profile (`hermes profile install`), with a `cyber-au` shell alias.
3. Runs `install/bootstrap.sh`: builds the connector environment with `uv sync`, writes the connectors into the profile `config.yaml`, enables the plugin, creates the intel store, and runs the doctor.

Run it as a normal user, not root. It is safe to run again. With no keys, only the connectors that need a key stay off:

```text
Keyed connector abuseipdb is disabled because ABUSEIPDB_API_KEY is unset.
Keyed connector ghsa is disabled because GITHUB_ADVISORY_TOKEN is unset.
Keyed connector nvd is disabled because NVD_API_KEY is unset.
Keyed connector otx is disabled because OTX_API_KEY is unset.
...
Bootstrap finished for cyber-au.
```

Open a new shell, or run `export PATH="$HOME/.local/bin:$PATH"`, so `hermes` and `cyber-au` are found:

```text
$ hermes --version
Hermes Agent v0.22.2 (2026.9.24) · stable · local d923a5eb487a
```

Running `hermes profile install` on its own is not enough: it skips bootstrap, so the profile has no connectors. Always use `install/install.sh`, or run `sh install/bootstrap.sh --profile cyber-au` after a manual profile install.

## 4. Check the install

```bash
hermes -p cyber-au cyber-au doctor --offline
hermes -p cyber-au mcp test kev
```

The doctor lists each connector as `enabled` or `disabled`. The public ones, such as `kev`, `epss`, `ism`, `e8`, `asd`, `attack`, `auscert`, `crtsh`, `internetdb` and `drop`, are enabled with no key. `mcp test` starts one of them and lists its tools (check marks removed):

```text
  Testing 'kev'...
  Transport: stdio → /home/analyst/.hermes/profiles/cyber-au/mcp/.venv/bin/cyberau-mcp
  Auth: none
  Connected (6284ms)
  Tools discovered: 3
    kev_lookup                           Check whether CVEs are in the CISA KEV catalogue.
    kev_recent                           KEV entries added in the last N days.
    kev_search                           Search KEV by vendor, product, or keyword.
```

Known issue on 18 October 2026: the doctor still marks many rows `fail` on a fresh install, mostly "set to a literal value" for `CYBERAU_DATA_DIR` and `CYBERAU_EGRESS_ALLOWLIST`, plus missing Essential Eight and ATT&CK snapshot paths and the audit log directory. These come from the doctor checks, not from your install, and the connectors still answer, as `mcp test` shows. `hermes -p cyber-au cyber-au doctor --fix` creates the missing directories.

## 5. First answer: the demo, no keys and no model

```bash
hermes -p cyber-au cyber-au demo triage
```

It triages the synthetic sample alert in `examples/edr-alert.json` against a synthetic demo intel set, offline. Every part of it is labelled demo, and it never reads or writes your real intel store.

```text
DEMO MODE: synthetic data. Nothing below is real threat intelligence.

DEMO triage record: DEMO-EDR-0001 (edr-alert.json)
DEMO alert: Suspected beacon from DemoLoader after a PowerShell download
Detected: 2026-10-17T09:12:00+11:00 (Australia/Sydney). Status: open.
Host: WS-DEMO-042, Staff laptop, criticality medium, SOCI asset no (from the DEMO asset list).

Matches in the DEMO intel set (synthetic records, not real intelligence):
  192[.]0[.]2[.]10: benign, confidence 60, demo record demo-ind-006
  update[.]example[.]net: malicious, confidence 75, demo record demo-ind-002
  80a67057fca09654d9e3c87207428bea1ef73ffd9ecd6ffddaf8964ecccc28b7: malicious, confidence 70, demo record demo-ind-003
  203[.]0[.]113[.]45: malicious, confidence 80, demo record demo-ind-001

ATT&CK:
  T1071.001 Application Layer Protocol: Web Protocols (confidence low, mapping table only)

ACSC matrix version was not retrieved.
Local severity P1:
  The EDR reports a beacon named as malware (DemoLoader).
  3 observables match hostile records in the demo intel set.

Containment (proposals only, nothing is run):
  Proposal: isolate WS-DEMO-042 with the EDR. Risk: user downtime. Reversible: yes.
...
Source: cyber-au DEMO dataset (synthetic, not real intelligence), demo-2026.10, retrieved 2026-10-18
Source: DEMO sample alert edr-alert.json, none, retrieved 2026-10-18
Source: hermes-cyber-au incident-triage local severity, 0.1.0, retrieved 2026-10-18
Source: hermes-cyber-au incident-triage attack mapping, 0.1.0, retrieved 2026-10-18
...
END OF DEMO OUTPUT. Do not act on it, store it or share it as real intelligence.
```

More on demo mode, and how it is kept apart from real data, is in [Your first hour](first-hour.md#demo-mode).

## 6. A live, sourced answer: choose a model and chat

```bash
hermes -p cyber-au model
hermes -p cyber-au chat
```

`model` asks which provider and model to use. The profile leaves both unset on purpose. Then, in the chat, ask:

```text
Is CVE-2023-4966 in the CISA KEV catalogue, and what is its EPSS score?
```

That uses the keyless `kev` and `epss` connectors and should end with `Source:` lines. This step was not run for this page, because it needs a model provider. The connector call underneath it was run, with no key and no model:

```bash
~/.hermes/profiles/cyber-au/mcp/.venv/bin/python -c \
  'import json; from cyberau_cisa_kev.source import kev_lookup; print(json.dumps(kev_lookup(["CVE-2023-4966"]), indent=1))'
```

```text
 "source": "cisa-kev",
 "source_urls": ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"],
 "data_as_of": "2026.10.16",
 "cache": "miss",
 ...
   "cve_id": "CVE-2023-4966",
   "vendor": "<<untrusted source=cisa-kev>> Citrix <<end untrusted>>",
   "product": "<<untrusted source=cisa-kev>> NetScaler ADC and NetScaler Gateway <<end untrusted>>",
   "date_added": "2023-10-18",
   "ransomware": "Known",
```

Feed text arrives wrapped as untrusted data. The agent reports it and does not follow instructions inside it.

Start the chat from the root of your checkout and try the triage on the same sample alert: `Triage the alert in examples/edr-alert.json. It is demo data.` Nine more prompts are in [Your first hour](first-hour.md).

## 7. Optional: free keys

The profile works with no keys. Two free keys are worth adding first. Copy the template, then fill in only the lines you need:

```bash
cp ~/.hermes/profiles/cyber-au/.env.EXAMPLE ~/.hermes/profiles/cyber-au/.env
chmod 600 ~/.hermes/profiles/cyber-au/.env
```

| Variable | Where to get it | What changes |
|---|---|---|
| `ABUSECH_AUTH_KEY` | https://auth.abuse.ch/ | URLhaus, ThreatFox and MalwareBazaar. |
| `NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key | Turns on the NVD connector at 50 requests per 30 seconds. |

Then re-run bootstrap so the matching connectors turn on:

```bash
sh install/bootstrap.sh --profile cyber-au
```

Keep the filled `.env` in the profile directory only. Never commit it. The other optional names are in `.env.template`. This product uses data from the NVD API but is not endorsed or certified by the NVD.

## 8. Optional: the morning briefing

Scheduled jobs arrive paused, so you choose what runs. List them and resume the 07:30 Sydney briefing by its id:

```bash
hermes -p cyber-au cron list
hermes -p cyber-au cron resume cyberau-morning-brief
```

`cron list` on the test container showed twelve jobs, all `[paused]`, including `cyberau-morning-brief`. The resume was not run there because the briefing needs a model. `hermes resume` with no job id lifts the global stop for every job, which is different. More is in [Routines](../operations/routines.md).

## Docker instead

The image installs the same profile with bootstrap already run. From the checkout:

```bash
docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml run --rm agent -p cyber-au cyber-au demo triage
docker compose -f docker/compose.yaml run --rm agent
```

The last command opens a chat. Building the image took 516 seconds on the test host. Keys, if any, go in `docker/.env`, which is not part of the image. Details are in [docker/README.md](https://github.com/jusso-dev/hermes-cyber-au/blob/main/docker/README.md).
