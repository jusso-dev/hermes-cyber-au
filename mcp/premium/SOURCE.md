# premium

- Upstream: none. This package is the shared interface for paid feeds. It does not call a vendor.
- Auth: licence environment names only. Values come from the profile `.env`.
- Rate limit: quota ledger in `premium-ledger.sqlite`, Australia/Sydney. No upstream calls here.
- Terms: off by default. See `docs/premium/README.md`.
- Verified: 2026-10-17
