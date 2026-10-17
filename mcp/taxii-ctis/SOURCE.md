# taxii-ctis

- Upstream: a user-supplied TAXII 2.1 API root (`TAXII_API_ROOT`), then `{root}/collections/` and `{root}/collections/{id}/objects/`. A URL whose path is `/taxii2/` is treated as a discovery document and the client follows an API root on the same host that is also on the allowlist. The API root must be https with no userinfo, query or fragment.
- Auth: HTTP Basic from `TAXII_USERNAME` and `TAXII_PASSWORD`. The password is never logged, stored in the cache key, or returned in an envelope.
- Rate limit: at most one poll an hour, and at most 20 object pages in that poll. Collection and discovery reads spend the page budget only, and a fresh cached answer spends nothing. That stays under the Sentinel CTIS guide (poll hourly, indicators at most a month old). Collection lists are cached for 24 hours.
- Terms: CTIS content is covered by the ASD Network Partner deed. It must not be copied into a public repository, a shared log, or an export without a TLP check. The connector ships disabled.
- Verified: 2026-10-16 (cyber.gov.au partner pages were not fetched). Shapes checked against TAXII 2.1 and the public Sentinel CTIS guide on 2026-10-17.
- Egress hosts: none shipped. Add the API root host before the first live call. `doctor --add-host` is the intended confirmation step once doctor supports it.

Doctor text: off by default: licence terms. Docs: `docs/connectors/taxii-ctis.md`.

Objects are kept in `$CYBERAU_DATA_DIR/taxii_objects.sqlite` until the shared intel store exists. There is no submission, upload, or other write to the TAXII server.

The shipped sample under `data/` is synthetic. It is labelled in every answer and is never written to the object store.
