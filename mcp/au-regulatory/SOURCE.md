# au-regulatory

- Upstream: https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches and the OAIC NDB scheme guide, https://www.cyber.gov.au/report-a-cyber-security-incident, https://www.cisc.gov.au/resources-subsite/Documents/ncsi-guidance.pdf, and the Federal Register of Legislation for the Privacy Act 1988, the Security of Critical Infrastructure Act 2018 and the Cyber Security Act 2024.
- Auth: none
- Rate limit: one request every 5 seconds. Fetches run from the regeneration path, about once a week. Tool calls answer from the shipped snapshot and do not fetch.
- Terms: Commonwealth legislation and government guidance. Short quotes are stored with the source URL, the retrieval date and the SHA-256 of the quoted sentence. This is guidance, not legal advice. The connector is not endorsed by the OAIC, ASD, the ACSC or the Cyber and Infrastructure Security Centre.
- Verified: 2026-10-17
- Egress hosts: www.oaic.gov.au, www.cyber.gov.au, www.cisc.gov.au, www.legislation.gov.au

Section numbers checked against the register, not by submitting anything to a regulator:

- Privacy Act 1988 (Cth) s 26WH(2): all reasonable steps to finish the suspected-breach assessment within 30 days. Sections 26WK(2) and 26WL(3): statement to the Commissioner, and notice to individuals, as soon as practicable.
- Security of Critical Infrastructure Act 2018 (Cth) ss 30BC and 30BD, compilation dated 4 June 2026: critical incidents within 12 hours (written record within 84 hours after an oral report); other incidents within 72 hours (written record within 48 hours after an oral report). Significant impact is s 30BEA. Relevant impact is s 8G.
- Cyber Security Act 2024 (Cth) s 27(1), from the Act as made on 29 November 2024: a reporting business entity must give the designated Commonwealth body a ransomware payment report within 72 hours of making the payment or of becoming aware that it was made. Who must report is s 26. The turnover threshold is the amount prescribed by the rules, not a figure in the Act. The latest register contents still place this duty in Part 3.

The shipped snapshot is `data/obligations-2026-10-17.json`. Each answer is also appended to `$CYBERAU_DATA_DIR/aureg-obligations.jsonl` until the shared intel store exists.
