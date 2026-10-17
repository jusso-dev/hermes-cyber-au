# Local severity

This is the hermes-cyber-au local scale for an incident whose ASD ACSC matrix was not retrieved. It is not the ACSC matrix and it is not a category label from ASD.

When `mcp__aureg__aureg_obligation` returns the matrix, use that matrix, cite its version, and do not also invent a local score. When it does not, write `ACSC matrix version was not retrieved.` and apply one row below. State the reasons in the record.

| Level | Use it when |
|---|---|
| P1 | The alert reports an active intrusion, an EDR beacon named as malware, or a ransom note on a system. |
| P2 | A person reports a credible compromise, including credential entry, and a second source has not confirmed impact. |
| P3 | The activity is suspicious, or the alert contains hostile instructions, and impact is not confirmed. |
| P4 | The only signal is an explained benign claim, such as a known-benign scanner, and nothing else supports an intrusion. |

Source: hermes-cyber-au incident-triage local severity, 0.1.0, retrieved 2026-10-17.
