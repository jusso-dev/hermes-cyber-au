# Guided setup

`hermes cyber-au setup` describes your organisation once, so skills give tailored answers from the first question. It writes `org.yaml`, picks connectors, seeds the watchlist, renders `config.yaml` and runs the doctor.

The command lives on the plugin CLI, next to `doctor` and `update`:

```bash
hermes -p cyber-au cyber-au setup
```

From a checkout, without Hermes, the same command is:

```bash
uv run --project mcp python plugins/cyber-au/cli.py setup --profile-home ~/.hermes/profiles/cyber-au
```

## What it asks

| Question | Values | Used for |
|---|---|---|
| Organisation name | free text, optional | Stays in `org.yaml` on this machine. |
| Sector | `general`, `health`, `education`, `local-government`, `state-government`, `federal-government`, `energy-water`, `financial-services`, `telecommunications`, `transport`, `retail`, `other` | Picks the sector pack. |
| Size | `small`, `medium`, `large` | Context for skills. |
| Annual turnover band | `under-3m`, `3m-or-more`, `unknown` | Ransomware payment reporting threshold and the Privacy Act small business question. |
| Regulators | `oaic`, `apra`, `soci`, `asic`, `aemo`, `ombudsman`, `none` | Which obligations a skill raises first (for example APRA CPS 234). |
| Environments | `it`, `ot`, `cloud` | Which ASD Essentials chapters to offer, OT triage questions. |
| SOCI responsible entity | yes or no | SOCI Part 2B and the risk management program rules. |
| Holds personal information | yes or no | The Notifiable Data Breaches scheme. |
| Domains and brands to watch | lists | Seeds `watchlists.yaml` when you have none. |
| Key names you have | variable names only, such as `NVD_API_KEY` | Which keyed connectors to switch on. |
| Sector packs | blank for the sector default, `none` to turn off, or pack names | See [sector packs](../reference/sector-packs.md). |

Setup never asks for a key value. It reads the profile `.env` only to see which variable names have a value, and it discards the values. `org.yaml` refuses anything that looks like a credential, so a pasted key stops setup before anything is written.

## What it writes

1. `plugin-data/cyber-au/org.yaml`, mode 600. An existing file is kept unless you pass `--force`.
2. A connector selection, recorded in `org.yaml` under `connectors`:
    - keyless connectors that ship on stay on;
    - a connector that needs a key is on only when every required variable name is present;
    - connectors that ship off for licence terms, paid feeds or local setup stay off. Switch one on yourself after reading its connector page.
3. `plugin-data/cyber-au/watchlists.yaml` with your domains and brands, only when no watchlist exists. An existing watchlist is never changed.
4. `config.yaml`, rendered by `install/render_config.py` (the same step bootstrap runs). A connector whose key is named in `org.yaml` but not set in `.env` stays disabled until you add the value to `.env`.
5. A `doctor --offline` run, which now also reports `org.profile` and `org.packs`.

## Non-interactive mode for fleet installs

Write the answers to a file and pass `--from-file`. The keys match the table above:

```yaml
# answers.yaml (synthetic example)
name: Example Water Pty Ltd
sector: energy-water
size: large
turnover: 3m-or-more
regulators: [soci, oaic]
environments: [it, ot]
critical_infrastructure: true
holds_personal_information: true
domains: [example.com.au]
brands: [Example Water]
keys_present: [NVD_API_KEY, OTX_API_KEY]
```

```bash
hermes -p cyber-au cyber-au setup --from-file answers.yaml
```

Options: `--force` replaces an existing `org.yaml`, `--no-render` skips `config.yaml`, `--no-doctor` skips the doctor. With no terminal and no `--from-file`, setup stops and asks for the file.

## How skills use it

`essentials-assessment`, `incident-triage`, `ndb-breach-notification` and `soci-reporting` start by running:

```bash
cyberau-mcp org context --skill soci-reporting
```

It prints the profile, the rules that apply to it for that skill (each with a source, version and review date), and notes from active sector packs. The profile is the organisation's own description: a skill still asks a coverage question the analyst has not answered, and nothing is submitted or sent. `cyberau-mcp org show` prints `org.yaml` as JSON and `cyberau-mcp org packs` lists installed packs.

The sector-neutral rules (Privacy Act, SOCI Part 2B, ransomware payment reporting, APRA CPS 234, ASD Essentials chapters) live in `plugins/cyber-au/store/org_rules.yaml`, in the same format as a sector pack.
