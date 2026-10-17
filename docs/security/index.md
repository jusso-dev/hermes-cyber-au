# Security

The distribution is read-only by default. A person approves anything that sends, blocks, posts or submits.

Content fetched from feeds is untrusted data. It stays inside the result envelope and is not treated as instructions.

Credentials are `${VAR}` placeholders resolved from the profile `.env`. Do not commit secrets, tokens, real customer data or internal hostnames.

[Hermes structure](../research/hermes-structure.md) lists security controls Hermes already ships. A threat model page and an egress page are not in this checkout.

---

Owner ticket: docs-site
Last verified: 17 October 2026
