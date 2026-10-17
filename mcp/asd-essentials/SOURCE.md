# asd-essentials

- Upstream: https://www.cyber.gov.au/publication/what-is-the-essentials
- Auth: none. This connector has no API key.
- Rate limit: one request every 5 seconds, with a burst of two so a single retry is not held for a full window. Chapter pages and the Essential Eight catalogues are cached for a day. Tools answer from the shipped snapshot unless a live health check is asked for.
- Terms: Essential Eight and ASD Essentials material is published by the Australian Signals Directorate. Record the ISM release tag and the page SHA-256 with every answer. This connector is not endorsed by ASD.
- Verified: 2026-10-17
- Egress hosts: www.cyber.gov.au, www.asd.gov.au, raw.githubusercontent.com

Confirmed on 17 October 2026, before the parser was written:

- OT chapter: https://www.cyber.gov.au/publication/essentials-for-ot (the longer publication path redirects here)
- Transition guidance: https://www.cyber.gov.au/publication/transitioning-from-the-essential-eight
- Launch notice: https://www.asd.gov.au/news/2026-10-15-asd-essentials-evolving-our-approach-cyber-security-resilience

The launch notice names enterprise IT, operational technology and cloud chapters, and says both Essential Eight and Essentials stay in force during the transition. Priority phases sequence domains. They are not maturity levels.

Essential Eight control assignment uses the ISM section title in `ISM_E8_ML1/2/3-baseline-resolved-profile_catalog.json` for release `v2026.09.4`. Patching sections are split by the subject of the control statement. Office macro statements, including the trusted-publisher review, stay with Restrict Microsoft Office macros. Memory integrity stays with Restrict administrative privileges. Event logging and incident reporting controls that the ISM does not place under one mitigation strategy are kept in `unassigned_controls` and returned as `cross_cutting`, not copied onto every strategy.

The cloud chapter shows priority phases in a figure, not in text. The snapshot leaves that phase list empty rather than copying another chapter's order.
