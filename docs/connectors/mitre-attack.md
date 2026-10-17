# MITRE ATT&CK (STIX 2.1)

Read-only ATT&CK techniques, groups and software from the `mitre-attack/attack-stix-data` bundles.

| Tool | What it returns |
|---|---|
| `attack_technique` | One technique or sub-technique by id: tactics, platforms, data sources, detection notes, mitigations and sub-techniques |
| `attack_search` | Techniques, groups and software in one domain (`enterprise`, `mobile` or `ics`) matching a keyword, best matches first |
| `attack_group` | One group by id or name or alias, with aliases, the techniques it uses and its software |

Detection notes and data sources come from the technique's own detection text and from the detection strategies, analytics and log sources that detect it. Revoked and deprecated objects are skipped, along with relationships that point at them. Looking up a revoked technique returns no data and a warning that names its replacement. `attack_technique` and `attack_group` check the enterprise, mobile and ICS bundles in that order and return the first match.

The connector reads `index.json` and downloads a bundle only when the index reports a version it has not stored. Each version is kept under `$CYBERAU_DATA_DIR/attack/<version>/`, so earlier versions stay available. If GitHub cannot be reached, it serves the newest stored version, then the hand-written test excerpt shipped in the package, which always comes with a warning and is not current ATT&CK content. No key is needed. Names, descriptions and detection text are untrusted. `detection` is null when ATT&CK has no detection text for the technique. Identifiers, URLs, platforms and dates are checked against fixed patterns and anything that does not fit is wrapped as untrusted text or dropped.

MITRE ATT&CK is a registered trademark of The MITRE Corporation. ATT&CK content is used under the ATT&CK Terms of Use (https://attack.mitre.org/resources/terms-of-use/). This connector is not endorsed by MITRE.
