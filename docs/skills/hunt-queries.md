# Hunt queries from an advisory

The threat-hunting skill can turn an ASD advisory or a CVE, with its IOCs and ATT&CK technique ids, into hunt queries a team can paste into their SIEM or EDR. Every query is an untested draft. Nothing here runs a query against a live SIEM, creates an analytics rule, or contacts anyone.

## Languages

| Language | Target | Tables or data models |
|---|---|---|
| KQL | Microsoft Defender XDR advanced hunting | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `EmailEvents` |
| KQL | Microsoft Sentinel | `SecurityEvent`, `CommonSecurityLog` |
| SPL | Splunk with CIM data models | `Network_Traffic`, `Network_Resolution`, `Web`, `Endpoint`, `Email` (CIM 6.2) |
| Sigma | Any SIEM with a Sigma backend | `process_creation`, `network_connection`, `dns_query`, `proxy` log sources |

IOC types: IP address, domain, URL, SHA-256, MD5 and sender email address. Technique templates cover T1059.001, T1505.003, T1190, T1003.001, T1053.005 and T1105. Other techniques are listed so an analyst can draft them by hand.

## What each query carries

- `status: untested draft`
- the data sources it needs (the table, data model or log source)
- false positive notes
- citations: the advisory or CVE it came from, the ATT&CK technique for a technique query, and the bundled schema or CIM extract it was checked against

## Run it

```bash
uv run --project mcp python skills/threat-hunting/scripts/hunt_queries.py request.yaml --format markdown
uv run --project mcp python skills/threat-hunting/scripts/hunt_queries.py request.yaml > pack.json
uv run --project mcp python skills/threat-hunting/scripts/check_hunt_pack.py pack.json
```

The request format, and how untrusted feed text is kept out of the query syntax, are in the skill reference `skills/threat-hunting/references/advisory-hunts.md`.

## Checks

`check_hunt_pack.py` is an offline lint. Sigma rules are parsed by pySigma and converted with its Kusto and Splunk backends. KQL is checked against the bundled table schemas (table, columns, time bound, no management commands or outbound plugins) and for balanced quotes and brackets. SPL must be one `tstats` search over a known CIM data model and fields, with a time bound, balanced quotes and brackets, and no command that writes, sends or calls out. The offline evals in `tests/skills/threat-hunting/` run these checks on synthetic sample advisories and on feed text that tries to inject query syntax.

Passing the checks does not mean a query was tested. Review each query against your own tenant before you run it.
