# Australian reporting obligations

Read-only deadlines and source quotes for the OAIC Notifiable Data Breaches scheme, SOCI Act cyber incident reporting, and ransomware payment reporting under the Cyber Security Act 2024.

| Tool | What it returns |
|---|---|
| `aureg_obligation` | The encoded rule, deadline and quoted source sentence for a regime and trigger |
| `aureg_deadline` | Those deadlines calculated in Australia/Sydney from an awareness time |

Regimes are `ndb`, `soci` and `ransomware_payment`. Triggers are `suspected_breach`, `eligible_breach`, `critical_incident`, `other_incident` and `payment`. Leave the trigger out of `aureg_obligation` to see every rule for that regime.

Quotes are short passages from Commonwealth legislation, with the URL, retrieval date and SHA-256 of the quoted sentence. The 30 day NDB assessment, the 12 hour and 72 hour SOCI reports, and the 72 hour ransomware payment report are fixed in the shipped snapshot. A written record after an oral SOCI report is timed from the oral report, not from awareness. Notice to the Commissioner and to individuals under the NDB scheme is as soon as practicable, so those clocks do not invent a fixed hour.

This is guidance, not legal advice. It is not endorsed by the OAIC, the Australian Signals Directorate, the Australian Cyber Security Centre or the Cyber and Infrastructure Security Centre.
