# Watchlists

A watchlist names what your organisation cares about: its domains, brands, address ranges, autonomous system numbers and the vendors it runs. An hourly run matches that list against the local intel store and keeps the current matches for the daily briefing. A daily run can also look for lookalike certificates on crt.sh and BGP hijack and route leak events on Cloudflare Radar, when those connectors are turned on.

## The file

The live file is `plugin-data/cyber-au/watchlists.yaml` on the profile: `$CYBERAU_DATA_DIR/watchlists.yaml` when that variable is set, otherwise `$HERMES_HOME/plugin-data/cyber-au/watchlists.yaml`. It is user-owned and is never committed or shipped. The repository ignores `plugin-data/` and `watchlists/`.

`cyberau-mcp store watchlist init` copies the template `plugins/cyber-au/store/watchlists.example.yaml` to that path. It never overwrites an existing file. The template uses documentation values only (`example.com`, `192.0.2.0/24`, `2001:db8::/32`, `AS64496`), so it matches nothing real until you edit it.

```yaml
domains:
  - example.com
brands:
  - Example Brand
ip_ranges:
  - 192.0.2.0/24
  - 2001:db8::/32
asns:
  - AS64496
vendors:
  - Fortinet
  - name: Example Vendor
    aliases:
      - ExampleOS
```

Every key is optional. Plain mappings and lists only.

| Key | Entries |
|---|---|
| `domains` | Host names. A scheme, a path, a leading `*.` and a trailing dot are removed. Unicode names are stored in IDNA form. |
| `brands` | Free-text names. |
| `ip_ranges` | IPv4 or IPv6 CIDR blocks. Host bits are ignored. |
| `asns` | `AS64496` or `64496`. |
| `vendors` | A name, or a mapping with `name` and a list of `aliases`. |

An entry that cannot be read is skipped and the run reports a warning with the list name and position, not the value. A file that is not valid YAML, or is not a mapping, fails the run.

The org exposure connector (`mcp/org-exposure`) also reads `domains` and `brands` from this file and adds them to its own watchlist. Keep those two keys as plain lists of strings.

## Matching rules

| List | Store rows | Kind | Rule |
|---|---|---|---|
| `ip_ranges` | `ipv4`, `ipv6` indicators, and URLs whose host is an IP address | `ip_range` | The address is inside the range. |
| `ip_ranges` | `cidr` indicators | `ip_range` | The stored block is inside the range, or covers it. |
| `asns` | `asn` indicators | `asn` | The numbers are equal. |
| `domains` | `domain`, `url` and `email` indicators | `domain` | The host equals the watched domain or is a subdomain of it. |
| `domains` | `domain`, `url` and `email` indicators | `lookalike` | The host is not under the watched domain and its registrable name looks like it (below). |
| `domains` | crt.sh certificate names (daily, opt-in) | `lookalike` | As above, for names on certificates crt.sh returns. |
| `asns` | Cloudflare Radar BGP hijack events (daily, opt-in) | `bgp_hijack` | The watched ASN is the hijacker or one of the victims. |
| `asns` | Cloudflare Radar route leak events (daily, opt-in) | `bgp_leak` | The watched ASN is the leaker or on the leak path. |
| `brands` | advisories | `brand` | The brand's tokens appear in the title, summary or indexed text. |
| `vendors` | advisories | `vendor` | The vendor name or one of its aliases appears in the title, summary or indexed text. |

### Lookalikes

The registrable name is the last two labels, or the last three under a known two-part suffix such as `com.au`. Both names are folded first: IDNA labels are decoded, a working set of confusable characters is mapped to Latin (Cyrillic and Greek look-alikes, `0` to `o`, `1` to `l`, `5` to `s`) and `rn` reads as `m`, `vv` as `w`. Then the first rule that applies wins:

1. `homoglyph`: the folded registrable names are equal, for example `examp1e.com` or `exarnple.com` for `example.com`.
2. `suffix-swap`: the folded first labels are equal under a different suffix, for example `example.net`.
3. `token`: the watched label (five letters or more) is a hyphen-separated part of the other label, for example `example-login.com`.
4. `edit-distance-N`: the folded first labels are one edit apart (five to seven letters) or up to two edits apart (eight letters or more). Labels under five letters only use rules 1 to 3.

The fold table and edit limits come from `skills/phishing-analysis`. It is a working subset, not the Unicode confusables catalogue.

### Brand and vendor tokens

Text and names use the token rule in `skills/daily-briefing/references/matching.md`: Unicode NFKC, casefold, `&` read as `and`, every run of other punctuation treated as a space, tokens under two characters and company suffixes (`pty`, `ltd` and the rest) dropped. A name matches when its tokens appear next to each other, in order, in the text. `Example Brand` matches `EXAMPLE-brand Pty Ltd`. It does not match `examplebrand` or `Example products and a brand refresh`.

Vendors are merged with a built-in alias table. A watched name that is a known vendor or one of its aliases brings in the whole entry.

| Vendor | Built-in aliases |
|---|---|
| Microsoft | MSFT |
| Fortinet | FortiGate, FortiOS |
| Palo Alto Networks | PAN-OS |
| Cisco | |
| Citrix | NetScaler |
| Ivanti | Pulse Secure |
| VMware | Broadcom VMware |
| Atlassian | Confluence, Jira |

Your own `aliases` are added to the built-in ones.

## Watches

A watch is a named daily rule over what the intel store collected: recent advisories and feed items whose text has the terms you care about. It works like a Sentinel analytics rule over a watchlist. Watches live in the same `watchlists.yaml`, under three optional keys.

```yaml
packs:
  - microsoft-security        # shipped feeds plus a ready-made watch
feeds:
  - id: vendor-blog
    label: Vendor security blog
    url: https://vendor.example/feed.xml
watches:
  - name: vendor-changes
    title: Vendor security changes
    sources: [vendor-blog]
    any: [security, vulnerability]
    exclude: [webinar]
    lookback_days: 3
```

| Key | Entries |
|---|---|
| `packs` | Names of shipped packs in `mcp/custom-feeds/packs/`. A pack brings its own feeds and watches. |
| `feeds` | RSS 2.0 or Atom feeds: `id`, `url` (https, a DNS host name, no port), optional `label`, `categories` (keep only items in one of these feed categories), `include` (keep only items with one of these terms) and `max_age_days` (default 14). |
| `watches` | `name`, `title`, `sources` (feed ids, or the store sources `asd-acsc` and `auscert`; empty means every source), `any`, `all`, `exclude` and `lookback_days` (default 3, at most 30). A watch needs `any` or `all`. |

Terms use the brand and vendor token rule above, so they match whole words in order, ignoring case and punctuation. An item matches when it has every `all` term, at least one `any` term and no `exclude` term, and it was published inside the lookback window.

### How a watch runs

1. `cyberau-ingest-custom` (every six hours) runs `cyberau-mcp refresh --sources custom --store`. Every configured feed is fetched through the `custom-feeds` connector and its items are stored as advisories with source `feed-<id>`. One failing feed is reported and skipped; the run fails only when every feed fails.
2. The hourly watchlist run evaluates every watch and keeps its matches under the list `watches`, with the watch title as the value.
3. The daily briefing lists new watch matches under "Watchlist hits", grouped by watch, with the item, its feed, its date and an https link. An external channel shows only a count per watch.

### The microsoft-security pack

Feeds: the MSRC Security Update Guide (cloud and security product entries only), the Microsoft Security blog, Azure updates (Security, Retirements and Compliance categories), the Microsoft 365 roadmap (security products only), and the Microsoft Sentinel, Defender XDR, Defender for Endpoint and Defender for Cloud blogs. Its watch, "Microsoft security changes", flags items about Sentinel, Defender, Entra, Azure, Intune, Purview, Conditional Access and Key Vault from the last two days.

To write your own pack, copy that file, change the feeds and watch, and save it under a new name in `mcp/custom-feeds/packs/`. A pack's hosts must be in the `custom-feeds` entry of the egress allowlist. A feed in your own `watchlists.yaml` brings its host at run time instead.

### Egress and safety

The `custom-feeds` connector allows the allowlisted hosts plus the host of each feed you configure. Every connection still goes through the private address floor in the egress policy. A feed that declares a DTD is refused. Titles, summaries and categories are stripped of markup and kept as untrusted text, and only https links are kept.

## Stored matches

Matches are kept in the `watchlist_matches` table of the intel store (migration `0003_watchlist_matches.sql`). Each row records the list, the match kind, the watchlist entry, what it points at (`indicator`, `advisory`, `crtsh` or `radar`), the store value that matched, a short detail, and when it was first and last matched.

Every run recomputes the whole set from what the store holds at that moment:

- A match found again keeps its first match time and gets a new last match time.
- A match not found again is deleted. That covers an indicator or advisory that was removed or expired, a feed row that no longer matches, and a watchlist entry you removed.
- Deleting an indicator or an advisory also deletes its matches straight away, through triggers, so a read between runs never returns a match for data that has gone.
- When the file is missing the run succeeds with `no watchlist configured` and deletes any earlier matches.

Each run writes the `routine_state` row `watchlist`: the watermark and `updated_at` are the run time.

## Commands

```sh
cyberau-mcp store watchlist init [--watchlist FILE]
cyberau-mcp store watchlist run [--crtsh] [--radar] [--profile-config FILE] [--path STORE] [--watchlist FILE]
cyberau-mcp store watchlist matches [--since ISO] [--list domains|brands|ip_ranges|asns|vendors] [--path STORE]
cyberau-mcp store watchlist hits --since ISO [--path STORE]
```

`--path` is the store file, as for every `store` command. `--watchlist` overrides the watchlist file. `--profile-config` names the profile `config.yaml`; with it, `--crtsh` runs only when `mcp_servers.crtsh.enabled` is `true` there and `--radar` only when `mcp_servers.cloudflare_radar.enabled` is `true`. A lookup that is off is reported as skipped, not as an error.

`run` prints one JSON summary: `status` (`ok` or `skipped`), `run_at`, the entry count per list, the number of current, new and removed matches, the count per kind, the crt.sh and Radar results and any warnings. The summary carries counts only, never watched values. It exits 0 on success, including a missing file, and 1 on an error such as a broken file.

`matches` prints the current matches as `{"matches": [...]}`, newest first. `--since` keeps matches first seen at or after that time. `--list` may be repeated.

`hits` prints matches first seen at or after `--since` in the shape the daily briefing reads for its intel store section: an envelope whose `data.hits` rows have `id`, `kind`, `value` (the store value that matched), `seen` (the first match time, ISO 8601 UTC) and `asset` (the watchlist entry). The briefing ties a hit to an inventoried asset only when `asset` equals an asset name in `assets.yaml`.

## Scheduled runs

Two no-agent jobs in `cron/jobs.json` run the watchlist. Both arrive paused, like every shipped job; resume them with `hermes cron resume <id>`.

| Job | When | Command | Network |
|---|---|---|---|
| `cyberau-watchlist` | every 60 minutes | `cyberau-mcp store watchlist run` | none |
| `cyberau-watchlist-lookups` | 05:15 every day | `cyberau-mcp store watchlist run --crtsh --radar --profile-config <profile>/config.yaml` | crt.sh and Cloudflare Radar, each only when enabled |

The hourly job checks every store row loaded since the last run (and every older one, since each run recomputes the whole set) and writes the `routine_state` row `watchlist`, which the daily briefing reads for its intel store section. It needs no agent, no key and no network. On a fresh install with no watchlist it succeeds and does nothing.

The daily lookups job does the same recompute and adds the two outbound lookups. crt.sh and Cloudflare Radar ship off for licence terms (`docs/connectors/crtsh.md`, `docs/connectors/cloudflare-radar.md`), so each lookup runs only after you set `enabled: true` for that server in the profile `config.yaml`. Radar also needs `CLOUDFLARE_RADAR_API_TOKEN` in the job's environment. Hermes runs no-agent scripts with a sanitised environment and the script does not read the profile `.env`, so on a default install the Radar part is skipped with the warning `CLOUDFLARE_RADAR_API_TOKEN is not set`. To run it, export the token in the environment Hermes cron runs in, or run the command by hand from a shell that has it. crt.sh needs no key.

## Privacy

Watched values stay on the machine. Matching reads the local store only.

There are two exceptions, both opt-in.

`run --crtsh` sends each entry under `domains`, and nothing else, to crt.sh through the crt.sh connector (keyless, one request every five seconds, results cached for 24 hours). Each query is written to the audit log as a `tool_call` for `crtsh_certs` with the domain in its arguments, before the result is used. If the audit log cannot be written, crt.sh is not queried. If the connector is not installed or a query fails, the run continues with a warning.

crt.sh is searched for certificates on the watched domain and its subdomains. A certificate name on those certificates that is a lookalike, and not the domain or one of its subdomains, is stored with the reference kind `crtsh`. Such a match is replaced on the next successful query for its domain. If queries keep failing, or later runs leave out `--crtsh`, it is deleted after seven days.

`run --radar` sends each entry under `asns`, and nothing else, to Cloudflare Radar through the cloudflare-radar connector: one `bgp/hijacks/events` and one `bgp/leaks/events` request per ASN, with `involvedAsn`, a seven day window and up to 50 events (Radar results are cached for 15 minutes, two requests a second at most). Each query is written to the audit log as a `tool_call` for `get_radar_bgp_hijacks_events` or `get_radar_bgp_leaks_events` with the ASN in its arguments. The token is never logged. If the audit log cannot be written, Radar is not queried. If the token is unset, the connector is not installed or a query fails, the run continues with a warning. An event becomes a match with the reference kind `radar` and the reference `hijack:<id>` or `leak:<id>`; the stored value names the hijacking or leaking ASN and up to three prefixes. Radar's event text is not stored. Matches follow the crt.sh rule: replaced on the next successful query for that ASN, and deleted after seven days if queries keep failing or later runs leave out `--radar`.

`tests/intel/test_watchlists.py::test_no_outbound_call_carries_watched_values_except_to_its_connector` runs both lookups with a full watchlist and checks every request and every audit record: domains reach only crt.sh, ASNs reach only Radar, and brands, ranges and vendors reach neither.

## Follow-up

- crt.sh only returns certificates that carry a watched name. Finding lookalike certificates that do not, for example by querying generated permutations, is not done.

---

Owner ticket: 062
Last verified: 28 November 2026
