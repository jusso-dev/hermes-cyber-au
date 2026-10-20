# custom-feeds

- Upstream: any RSS 2.0 or Atom feed turned on in `watchlists.yaml`. The shipped `microsoft-security` pack reads the MSRC Security Update Guide (https://api.msrc.microsoft.com/update-guide/rss), the Microsoft Security blog, Azure updates, the Microsoft 365 roadmap and the Sentinel and Defender blogs on Microsoft Tech Community.
- Auth: none. Every feed is public.
- Rate limit: one request a second, each feed cached for an hour. The nightly ingest makes one request per feed.
- Terms: each feed's publisher terms. The `microsoft-security` pack is Microsoft content under the Microsoft Terms of Use. Cite the publisher named in each item's feed.
- Verified: 2026-10-20
- Egress hosts: api.msrc.microsoft.com, techcommunity.microsoft.com, www.microsoft.com

## Operator guide

Watches are daily rules over what the intel store collected, like a Sentinel analytics rule over a watchlist. This connector supplies the feeds they read. Nothing is fetched until you turn a pack or a feed on in `watchlists.yaml` (`plugin-data/cyber-au/watchlists.yaml` on the profile).

```yaml
packs:
  - microsoft-security        # shipped feeds plus the "Microsoft security changes" watch
feeds:
  - id: vendor-blog
    label: Vendor security blog
    url: https://vendor.example/feed.xml
    include: [security, vulnerability]   # optional: keep only items with one of these terms
watches:
  - name: vendor-changes
    title: Vendor security changes
    sources: [vendor-blog]
    any: [security, vulnerability]
```

| Tool | What it returns |
|---|---|
| `custom_feed_list` | The packs, feeds and watches turned on, and the packs available |
| `custom_feed_items` | Recent items from one configured feed, after its filters |

`cyberau-mcp refresh --sources custom --store` loads every configured feed into the intel store as advisories (source `feed-<id>`). The `cyberau-ingest-custom` job runs it every six hours. The nightly watchlist run then evaluates each watch, and its new matches appear under "Watchlist hits" in the daily briefing, grouped by watch.

A feed entry takes `id`, `url`, optional `label`, `categories` (keep only items in one of these feed categories), `include` (keep only items with one of these terms) and `max_age_days` (default 14). A watch takes `name`, `title`, `sources` (feed ids, or the store sources `asd-acsc` and `auscert`; empty means every source), `any`, `all`, `exclude` and `lookback_days` (default 3). Terms match whole words, ignoring case and punctuation.

### Egress

The allowlist covers the shipped packs. A feed you add brings its own host at run time. It must be https with a DNS host name, with no port, user info or IP literal, and every connection still goes through the private address floor in the egress policy.

### Safety

Feed text is untrusted. Titles, summaries and categories are stripped of markup and wrapped as untrusted. A feed that declares a DTD is refused. Links must be https.
