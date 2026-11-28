# Hunt queries from an advisory or CVE

[hunt_queries.py](../scripts/hunt_queries.py) turns an ASD advisory id or a CVE id, plus its IOCs and ATT&CK technique ids, into hunt query drafts. It is a pure function. It does not open a connection, call a connector, or run a query. Every query it returns is marked `untested draft`.

## Input

```yaml
source:
  id: CVE-2026-0001            # or an advisory id such as 2026-SYN-0042
  url: https://www.cyber.gov.au/...   # optional, https only, goes into the Sigma references
  retrieved: "2026-11-28"      # retrieved_at from the envelope, YYYY-MM-DD
iocs:                          # a list of {type, value}, or a map of type to values
  ip: ["203[.]0[.]113[.]10"]
  domain: ["updates[.]example[.]com"]
  url: ["hxxps://web[.]example[.]com/login"]
  sha256: ["..."]
  md5: ["..."]
  email: ["billing[@]example[.]com"]
techniques: [T1505.003, T1190]
lookback: 30d                  # 1h to 999h, or 1d to 365d
languages: [kql_defender, kql_sentinel, spl, sigma]   # optional
```

```bash
python skills/threat-hunting/scripts/hunt_queries.py request.yaml --format markdown
python skills/threat-hunting/scripts/hunt_queries.py request.yaml > pack.json
python skills/threat-hunting/scripts/check_hunt_pack.py pack.json
```

## Output

Each query has its language, the query text, `status: untested draft`, `data_sources` (the tables, data models or log sources it needs), `false_positives`, and `citations`. The first citation is always the advisory or CVE. A technique query also cites the ATT&CK technique. A KQL query cites the bundled schema file for each table it uses, and an SPL query cites the bundled Splunk CIM extract.

| Language | Target | Schema checked against |
|---|---|---|
| `kql_defender` | Microsoft Defender XDR advanced hunting | [schemas/](schemas/readme.md) |
| `kql_sentinel` | Microsoft Sentinel (Log Analytics) | [schemas/](schemas/readme.md) |
| `spl` | Splunk with accelerated CIM data models (`tstats`) | [splunk-cim.yaml](splunk-cim.yaml) |
| `sigma` | Sigma, the neutral format | pySigma parse plus Kusto and Splunk conversion |

The mapping from IOC types and technique ids to templates is in [hunt-templates.yaml](hunt-templates.yaml). Every IOC type has a template. A technique with no template is listed under `unmapped_techniques`. A parent technique id such as `T1003` selects the templates for its sub-techniques.

## How feed text is kept out of the query syntax

IOC values come from advisories and feeds, so they are untrusted.

1. Refang: `hxxp` and `hxxps`, `[.]`, `(.)`, `[dot]`, `[@]`, `[at]` and `[:]` become the plain characters, once.
2. Validate: each value must match a strict pattern for its type. An IP address must parse as IPv4 or IPv6 (no scope id or CIDR). A domain is lowercase labels of letters, digits and hyphens. A URL is http or https with a plain host and only URL-safe characters, with no quote, backtick, space, pipe, asterisk or credentials. A hash is hex of the right length. An email is a plain local part and a domain. Anything else is refused with a reason and shown defanged under `rejected`.
3. Escape: accepted values are escaped again for each language. KQL and SPL values go in double-quoted strings with `\` and `"` escaped. Sigma values have `*`, `?` and `\` escaped so they match literally. An SPL value with `*` is refused, because SPL cannot escape a wildcard.

The tests in `tests/skills/threat-hunting/test_hunt_queries.py` feed quotes, pipes, newlines, `evaluate http_request`, `outputlookup`, `sendemail`, management commands and Sigma condition text through every IOC type and check none of it reaches a query.

## Offline checks

[check_hunt_pack.py](../scripts/check_hunt_pack.py) checks every query in a pack:

- status is `untested draft`, data sources and false positives are present, citations are well formed, and one cites the advisory, CVE or technique
- Sigma: pySigma parses the rule and both the Kusto and Splunk backends convert it
- KQL: [check_kql.py](../scripts/check_kql.py) passes (known table, known columns, time bound, no management command, `externaldata` or outbound plugin), and quotes and brackets balance
- SPL: one `tstats` search over a data model and fields in the bundled CIM extract, an `earliest=` time bound, balanced quotes and brackets, and no command that writes, sends or calls out (`outputlookup`, `collect`, `sendemail`, `rest`, `script`, `map`, `delete` and similar)

Passing is a lint result. It does not mean the query was run or that the analyst's tenant has the table or field.

## Limits

- No live SIEM is queried, here or anywhere in this skill.
- Splunk queries assume CIM data models are populated and accelerated. Use `summariesonly=false` as written, or adjust after review.
- `EmailEvents` reaches Microsoft Sentinel through the Defender XDR connector, so there is no separate Sentinel email query. Sigma has no mail flow log source, so there is no Sigma email rule.
- Technique templates cover Windows. Linux and cloud hunts are drafted by hand.

Source: MITRE ATT&CK, v20.1, retrieved 2026-11-28.
Source: Splunk Common Information Model, 6.2, retrieved 2026-11-28.
