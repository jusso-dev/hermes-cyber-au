# au-regulatory

- Upstream: https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches and the OAIC NDB scheme guide, https://www.cyber.gov.au/report-a-cyber-security-incident, https://www.cisc.gov.au/resources-subsite/Documents/ncsi-guidance.pdf, and the Federal Register of Legislation for the Privacy Act 1988, the Security of Critical Infrastructure Act 2018, the Cyber Security Act 2024, the Cyber Security (Ransomware Payment Reporting) Rules 2025 and APRA Prudential Standard CPS 234.
- Auth: none
- Rate limit: one request every 5 seconds. Live health probes fetch a source page. Tool calls answer from the reviewed shipped snapshot and do not fetch.
- Live health uses the Register's published HTML for the Act as made, rather than its JavaScript viewer. It checks source availability and snapshot schema; it does not verify subsequent amendments.
- Terms: Commonwealth legislation and government guidance. Short quotes are stored with the source URL, the retrieval date and the SHA-256 of the quoted sentence. This is guidance, not legal advice. The connector is not endorsed by the OAIC, ASD, the ACSC or the Cyber and Infrastructure Security Centre.
- Verified: 2026-11-28
- Egress hosts: www.oaic.gov.au, www.cyber.gov.au, www.cisc.gov.au, www.legislation.gov.au

Section numbers checked against the register, not by submitting anything to a regulator:

- Privacy Act 1988 (Cth) s 26WH(2): all reasonable steps to finish the suspected-breach assessment within 30 days. Sections 26WK(2) and 26WL(3): statement to the Commissioner, and notice to individuals, as soon as practicable.
- Security of Critical Infrastructure Act 2018 (Cth) ss 30BC and 30BD, compilation dated 4 June 2026: critical incidents within 12 hours (written record within 84 hours after an oral report); other incidents within 72 hours (written record within 48 hours after an oral report). Significant impact is s 30BEA. Relevant impact is s 8G.
- Cyber Security Act 2024 (Cth) s 27(1), from the Act as made on 29 November 2024: a reporting business entity must give the designated Commonwealth body a ransomware payment report within 72 hours of making the payment or of becoming aware that it was made. Who must report is s 26. The turnover threshold is the amount prescribed by the rules, not a figure in the Act. The latest register contents still place this duty in Part 3.
- Cyber Security (Ransomware Payment Reporting) Rules 2025 (F2025L00278) s 6(1): the turnover threshold is $3 million, pro rata under s 6(2) for a business carried on for part of the year. Section 7 lists the report contents, which `aureg_check` uses as the draft field list. The Act says turnover must exceed the threshold. The ASD reporting form says "equal to or exceeds". The checker treats the org.yaml band `3m-or-more` as in scope and tells the user to get advice near the line.
- Cyber Security Act 2024 (Cth) ss 29 to 32 (limited use, privilege and admissibility for ransomware payment reports), s 34 (significant cyber security incident), s 35 (voluntary information to the National Cyber Security Coordinator), s 38 (the Coordinator's limited use) and s 44 (sharing under Part 4 does not affect any other requirement to report).
- Prudential Standard CPS 234 Information Security (F2018L01745) paragraphs 35 and 36: notify APRA no later than 72 hours after becoming aware of a material information security incident, or one notified to another regulator, and no later than 10 business days after becoming aware of a material control weakness the entity expects it cannot remediate in time.
- ASD guidance pages for the voluntary report (ReportCyber) and the ASD limited use obligation. The limited use rule is marked `partial`: the Intelligence Services Act 2001 Division 1A text was not fetched in this review, so only ASD's description is quoted.

The shipped snapshot is `data/obligations-2026-11-28.json`. Each answer is also appended to `$CYBERAU_DATA_DIR/aureg-obligations.jsonl` as a local source observation.

## Operator guide

Read-only deadlines and source quotes for the OAIC Notifiable Data Breaches scheme, SOCI Act cyber incident reporting, and ransomware payment reporting under the Cyber Security Act 2024.

| Tool | What it returns |
|---|---|
| `aureg_obligation` | The encoded rule, deadline and quoted source sentence for a regime and trigger |
| `aureg_deadline` | Those deadlines calculated in Australia/Sydney from an awareness time |
| `aureg_check` | Which reports may apply to an incident given `org.yaml`, with deadlines, recipients, sources, draft report fields and a countdown timeline |

Regimes are `ndb`, `soci`, `ransomware_payment`, `apra_cps234`, `asd_voluntary`, `csa_significant_incident` and `limited_use`. Each rule has an `id` of the form `<regime>.<trigger>`, a recipient, conditions keyed to `org.yaml` fields and incident facts (`applies_when`), the deadline clocks, the report fields to prefill, the source URL and a `last_reviewed` date. Leave the trigger out of `aureg_obligation` to see every rule for that regime.

`aureg_check` runs a pure function, `cyberau_au_regulatory.engine.check`. It sorts each rule into applies, may apply (with the questions to ask) or does not apply (with the reason). Hours are elapsed time, added in UTC and shown in Australia/Sydney. Days keep the Sydney wall clock time. Business days skip weekends but not public holidays, so the date shown is never later than the true deadline. A ransomware payment clock runs from `payment_at` when it is given. Prefilled draft values come only from the facts and `org.yaml`, and are wrapped as untrusted text. The result always says it is not legal advice and that nothing was submitted. Nothing in this connector submits, sends or lodges anything.

Quotes are short passages from Commonwealth legislation, with the URL, retrieval date and SHA-256 of the quoted sentence. The 30 day NDB assessment, the 12 hour and 72 hour SOCI reports, and the 72 hour ransomware payment report are fixed in the shipped snapshot. A written record after an oral SOCI report is timed from the oral report, not from awareness. Notice to the Commissioner and to individuals under the NDB scheme is as soon as practicable, so those clocks do not invent a fixed hour.

This is guidance, not legal advice. It is not endorsed by the OAIC, the Australian Signals Directorate, the Australian Cyber Security Centre or the Cyber and Infrastructure Security Centre.


## Snapshot maintenance

The obligations snapshot contains reviewed quotes, deadline rules and applicability conditions. It is not
automatically refreshed from web pages. The data workflow checks its file hashes
without changing retrieval dates. Review the cited legislation and guidance
before changing a quote, deadline or retrieval date. `regen aureg --fetch` is not
supported. ISM and Essential Eight use separate automatic fetch adapters.
