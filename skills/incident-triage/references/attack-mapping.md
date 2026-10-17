# Attack mapping

Use `mcp__attack__attack_technique` when it is available and cite that envelope, including the catalogue version it returns. The ids below are the only ones this skill may state when that tool is missing. Confidence is low in that case, because the catalogue version was not retrieved. Do not add an id that is not in this table and not in a tool result.

| Reported activity | Id | Name |
|---|---|---|
| A person clicked a phishing link | T1566.002 | Spearphishing Link |
| A later sign-in to a cloud account is confirmed | T1078.004 | Valid Accounts: Cloud Accounts |
| A beacon over HTTP or HTTPS | T1071.001 | Application Layer Protocol: Web Protocols |
| The alert names Cobalt Strike | S0154 | Cobalt Strike |
| A ransom note, or files confirmed encrypted | T1486 | Data Encrypted for Impact |
| An inbound network scan | T1595 | Active Scanning |

`T1078.004` requires a confirmed later sign-in. A password typed into a page is not enough. `T1486` stays low when only a note was found and encryption is not confirmed.

Source: hermes-cyber-au incident-triage attack mapping, 0.1.0, retrieved 2026-10-17.
