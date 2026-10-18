---
name: google-ti-dtm
description: Read Google Threat Intelligence Digital Threat Monitoring alerts and monitors. Off by default. Bring your own licence.
version: 0.1.0
author: Justin Middler
license: Apache-2.0
metadata:
  hermes:
    tags: [Security, threat-intelligence, premium]
    related_skills: [ioc-enrichment]
    requires_tools: []
---

# Google Threat Intelligence DTM

## When to Use

Load this skill when the user holds a Google Threat Intelligence licence and wants to read Digital Threat Monitoring alerts or the monitors that raise them.

State these terms before the first gtidtm call in a session.

Commercial licence. Session cache. Store metadata only. No STIX export. Redistribution is forbidden. Do not reuse a VirusTotal Public API key. The server ships disabled until you set `enabled: true` for `gtidtm` in your profile config. Put the licence in `GTI_API_KEY`.

## Quick Reference

| Tool | What it returns |
|---|---|
| `gti_dtm_alerts` | DTM alerts, read only |
| `gti_dtm_monitors` | DTM monitors, read only |

## Procedure

1. State the terms above if this is the first gtidtm call in the session.
2. After the terms are clear, you may call `gti_dtm_alerts` or `gti_dtm_monitors`. Both are read only.
3. Report alert metadata only. Do not copy alert content into an export.

## Pitfalls

- Do not create monitors, update alerts, or download samples.
- A VirusTotal Public API key is not a GTI licence. Do not reuse it.
- Redistribution is forbidden, so keep results inside the session.

## Verification

- The terms were stated before the first call.
- Only `gti_dtm_alerts` and `gti_dtm_monitors` were called.
- Nothing beyond metadata was stored or exported.
