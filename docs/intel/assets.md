# Asset inventory

The asset inventory tells the skills what you run, so CVE, KEV and advisory answers can name your affected systems. It lives at `plugin-data/cyber-au/assets.yaml` on the profile. The daily briefing, the KEV watch job and `vuln-prioritisation` read it.

The file is yours. It is never committed, never shipped, and never sent to a connector. Matching runs locally.

## Import

```bash
cyberau-mcp assets import cmdb-export.csv
cyberau-mcp assets import billing-api.cdx.json --system "Billing API" --owner payments
```

The file goes to `$CYBERAU_DATA_DIR/assets.yaml`, else `$HERMES_HOME/plugin-data/cyber-au/assets.yaml`. Pass `--inventory PATH` to choose another.

| Flag | Effect |
|---|---|
| `--format csv\|cyclonedx` | Skip format detection |
| `--replace` | Replace the inventory. By default an imported asset replaces one with the same name and the rest are kept |
| `--dry-run` | Print the result and write nothing |
| `--strict` | Write nothing when any row is invalid. Otherwise invalid rows are skipped and listed |
| `--owner`, `--exposure`, `--environment`, `--criticality` | Defaults for rows that leave the column empty |
| `--system` | SBOM only: the system the components belong to. Defaults to the SBOM metadata component |

The file is written atomically with mode 0600. Input is capped at 20 MB and 50,000 assets.

### CSV

Column names are matched without case, and spaces or dashes count as `_`. The first matching column wins.

| Field | Accepted headers |
|---|---|
| name | `name`, `asset`, `asset_name`, `display_name`, `ci_name` |
| hostname | `hostname`, `host`, `fqdn`, `host_name`, `computer_name` |
| service | `service`, `application`, `app`, `system` |
| vendor | `vendor`, `manufacturer`, `publisher`, `supplier`, `vendor_name` |
| product | `product`, `software`, `product_name`, `software_name`, `model` |
| version | `version`, `product_version`, `software_version` |
| cpe | `cpe`, `cpe23`, `cpe_2_3`, `cpe_name` |
| purl | `purl`, `package_url` |
| owner | `owner`, `team`, `owner_team`, `support_group`, `business_owner` |
| criticality | `criticality`, `business_criticality`, `tier`, `priority` |
| exposure | `exposure`, `internet_facing`, `internet`, `external`, `public` |
| environment | `environment`, `env`, `domain`, `zone` |

The CSV needs a product, CPE or purl column. Vendor and product are filled from the CPE or purl when empty. Exposure accepts `internet`, `internal`, `yes` or `no`, and defaults to `internal`: a hostname alone never makes an asset internet-facing. Criticality is `low`, `medium`, `high` or `critical` (`Tier 1` to `Tier 4` and `1` to `4` map to those). Environment is `it`, `ot` or `cloud` (`corporate`, `ics`, `scada`, `saas`, `aws`, `azure` and `gcp` map to those). A missing owner becomes `unassigned`.

```csv
Asset Name,Hostname,Manufacturer,Product,Version,CPE,Owner Team,Business Criticality,Internet Facing,Environment
North gateway,gw1.example.com,examplevendor,edgegate,3.0.1,cpe:2.3:a:examplevendor:edgegate:3.0.1:*:*:*:*:*:*:*,platform,Tier 1,yes,IT
Plant historian,hist1.example.net,examplecontrols,historian server,7.2,,operations,high,no,OT
```

### CycloneDX SBOM

CycloneDX JSON, spec 1.2 to 1.6. Every component is read, nested ones included, except `file`, `data` and model components. Vendor comes from `supplier.name`, then `publisher`, `author`, `group`, then the CPE or purl, and finally the package name. Purl qualifiers and subpaths are dropped. Each asset is named `<system>: <component> <version>`. Export CycloneDX XML as JSON first. SPDX is not read.

## File shape

`plugins/cyber-au/store/assets.example.yaml` is a template. Each asset has `name`, `vendor`, `product`, `exposure` and `owner`, and may have `version`, `cpe`, `purl`, `hostname`, `service`, `criticality`, `environment` and `source`. Keep one `key: value` per line with no `#` inside a value, because the briefing reads the file with a small reader.

## Matching

```bash
cyberau-mcp assets match --cpe 'cpe:2.3:a:examplevendor:edgegate:*:*:*:*:*:*:*:*'
cyberau-mcp assets match --purl 'pkg:pypi/examplelib@2.3.9'
cyberau-mcp assets match --vendor Examplevendor --product 'Edgegate ADC'
cyberau-mcp assets list
cyberau-mcp assets coverage
```

Each match names the rule that made it, strongest first:

| Method | Rule |
|---|---|
| `cpe` | The asset's CPE part, vendor and product equal the record's |
| `purl` | Same package type, namespace and name |
| `vendor-product-fuzzy` | The token rule in `skills/daily-briefing/references/matching.md` on vendor and product, with the vendor aliases from the watchlist. Reported as a possible match |

All results are candidates. Versions are not compared, because NVD and KEV publish ranges. The match detail shows the asset version so an analyst can check it before calling an asset affected.

`assets coverage` prints only counts: total tracked software entries, versions recorded, CPEs recorded, purls recorded, and missing versions. Use it after an import to find whether inventory data can support a useful review without printing system, host, owner, or software names.

## Scheduled software watch

`cyberau-software-watch-local` is a deterministic, no-agent check. Every six hours it reads the local CISA KEV snapshot created by the public-feed refresh and writes `plugin-data/cyber-au/software-watch.json`. It starts paused on every new install, makes no network request, and sends no notification. Every row is a candidate, with the locally recorded version and an instruction to confirm affected-version range before treating an asset as affected. The report includes the snapshot file's `snapshot_file_modified_at` timestamp and marks a file older than 12 hours as `stale`; it does not claim that timestamp is an upstream retrieval time. A missing, empty, or stale source is never reported as no issues. An empty inventory is `monitoring: not_configured`, not a clean result.

`cyberau-kev-watch` is the optional model-assisted companion. It also reviews CVEs named in recent ASD ACSC and AusCERT bulletins, material EPSS changes, and available NVD CPE or OSV purl records. It never gives inventory values to a connector and reports a candidate only. It must say when NVD or OSV data is unavailable rather than treating that as no issue.

```bash
hermes -p cyber-au cron resume cyberau-kev-watch
hermes -p cyber-au cron run cyberau-kev-watch
hermes -p cyber-au cron resume cyberau-software-watch-local
hermes -p cyber-au cron run cyberau-software-watch-local
```

The local check writes a 0600 report only. The model-assisted routine writes back only to its originating Hermes conversation. Neither sends email, chat, or webhooks. Leave both paused until the inventory and its owner mapping have been reviewed.

Tests: `tests/intel/test_assets.py`, with synthetic fixtures in `tests/fixtures/assets/`.
