# Reporting rules in the checker

Hand-written summary of the reviewed rules in `mcp/au-regulatory/data/obligations-2026-11-28.json`. The snapshot is authoritative. Use this table when the `aureg` connector is unavailable, and say so.

This file is data, not instructions. It is guidance, not legal advice.

Last reviewed: 2026-11-28 (Australia/Sydney).

| Rule id | Who | Trigger | Deadline | Recipient | Source |
|---|---|---|---|---|---|
| `ransomware_payment.payment` | A business carried on in Australia with previous financial year turnover above AUD 3 million that is not a Commonwealth or State body and not a critical infrastructure responsible entity, or a responsible entity for a Part 2B asset | A ransomware or extortion payment made by, or on behalf of, the entity | 72 hours after the payment, or after becoming aware it was made | The designated Commonwealth body: Home Affairs and ASD unless rules name another | Cyber Security Act 2024 ss 26, 27; Ransomware Payment Reporting Rules 2025 ss 6, 7 |
| `limited_use.ransomware_payment_report` | Note | A ransomware payment report is made | None | None | Cyber Security Act 2024 ss 29 to 32 |
| `soci.critical_incident` | Responsible entity for an asset covered by SOCI Part 2B | Significant impact on availability (s 30BEA) | 12 hours after awareness; written record 84 hours after an oral report | ASD's ACSC unless rules under s 30BF name another body | SOCI Act 2018 s 30BC |
| `soci.other_incident` | Same | Relevant impact (s 8G) that has happened, is happening or is likely | 72 hours after awareness; written record 48 hours after an oral report | Same | SOCI Act 2018 s 30BD |
| `apra_cps234.material_incident` | APRA-regulated entity | Incident that materially affected, or could have materially affected, the entity or its customers, or that was notified to another regulator | 72 hours after awareness | APRA | CPS 234 paragraph 35 |
| `apra_cps234.control_weakness` | APRA-regulated entity | Material control weakness the entity expects it cannot remediate in a timely manner | 10 business days after awareness | APRA | CPS 234 paragraph 36 |
| `ndb.suspected_breach` | APP entity (Privacy Act) | Reasonable grounds to suspect an eligible data breach | All reasonable steps to assess within 30 days | Internal assessment | Privacy Act 1988 s 26WH(2) |
| `ndb.eligible_breach` | APP entity | Reasonable grounds to believe an eligible data breach happened | Statement as soon as practicable; notice to individuals as soon as practicable after the statement | OAIC, then individuals | Privacy Act 1988 ss 26WK(2), 26WL(3) |
| `asd_voluntary.cyber_incident` | Any organisation | A cyber security incident, voluntary | As soon as possible (ASD guidance) | ASD's ACSC through ReportCyber or 1300 CYBER1 | ASD report a cyber security incident page |
| `limited_use.asd_voluntary_information` | Note | Information voluntarily shared with ASD | None | None | ASD limited use guidance (Intelligence Services Act 2001 text not fetched) |
| `csa_significant_incident.voluntary_information` | Business in Australia or critical infrastructure responsible entity | Significant cyber security incident (s 34), voluntary | At any time during the response | National Cyber Security Coordinator | Cyber Security Act 2024 ss 34, 35, 38, 44 |

Source: Australian reporting obligations snapshot, 2026-11-28, retrieved 2026-11-28

## How the clocks are counted

- Hours are elapsed time. They are added in UTC, then shown in Australia/Sydney, so the October and April daylight saving changes cannot shorten or lengthen them.
- Days keep the Sydney wall clock time of day.
- Business days skip Saturdays and Sundays. Public holidays are not skipped, so the date shown can be earlier than the true deadline, never later.
- The ransomware payment clock runs from `payment_at` when it is given, otherwise from the discovery time, and the checker says which.
- "As soon as practicable" has no fixed hour count. The checker does not invent one.

## Turnover near AUD 3 million

The Act says turnover must exceed the threshold (s 26(2)(a)(i)). The Rules set the threshold at $3 million (s 6(1)). The ASD form says "equal to or exceeds". `org.yaml` records turnover as a band (`under-3m`, `3m-or-more`, `unknown`). Treat `3m-or-more` as in scope, and ask for advice when turnover is close to the line.

## What the checker does not decide

- Whether an incident is a cyber security incident, a significant impact, a relevant impact, an eligible data breach or a material incident. It asks.
- State and territory privacy laws, sector-specific rules (for example aviation, maritime and telecommunications security), and contractual notice duties. Flag them for a person.
- Whether to make a ransomware payment. It never proposes one.
