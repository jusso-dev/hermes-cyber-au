---
name: google-ti-dtm
description: Read Google Threat Intelligence Digital Threat Monitoring alerts and monitors. Off by default. Bring your own licence.
---

# Google Threat Intelligence DTM

State these terms before the first gtidtm call in a session.

Commercial licence. Session cache. Store metadata only. No STIX export. Redistribution is forbidden. Do not reuse a VirusTotal Public API key. The server ships disabled until you set `enabled: true` for `gtidtm` in your profile config. Put the licence in `GTI_API_KEY`.

After the terms are clear, you may call `gti_dtm_alerts` or `gti_dtm_monitors`. Both are read only. Do not create monitors, update alerts, or download samples.
