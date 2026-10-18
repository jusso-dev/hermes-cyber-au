# Watchlists

A watchlist names what your organisation cares about: its domains, brands, address ranges, autonomous system numbers and the vendors it runs. A nightly run matches that list against the local intel store and keeps the current matches for the daily briefing.

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

## Stored matches

Matches are kept in the `watchlist_matches` table of the intel store (migration `0003_watchlist_matches.sql`). Each row records the list, the match kind, the watchlist entry, what it points at (`indicator`, `advisory` or `crtsh`), the store value that matched, a short detail, and when it was first and last matched.

Every run recomputes the whole set from what the store holds at that moment:

- A match found again keeps its first match time and gets a new last match time.
- A match not found again is deleted. That covers an indicator or advisory that was removed or expired, a feed row that no longer matches, and a watchlist entry you removed.
- Deleting an indicator or an advisory also deletes its matches straight away, through triggers, so a read between runs never returns a match for data that has gone.
- When the file is missing the run succeeds with `no watchlist configured` and deletes any earlier matches.

Each run writes the `routine_state` row `watchlist`: the watermark and `updated_at` are the run time.

## Commands

```sh
cyberau-mcp store watchlist init [--watchlist FILE]
cyberau-mcp store watchlist run [--crtsh] [--path STORE] [--watchlist FILE]
cyberau-mcp store watchlist matches [--since ISO] [--list domains|brands|ip_ranges|asns|vendors] [--path STORE]
cyberau-mcp store watchlist hits --since ISO [--path STORE]
```

`--path` is the store file, as for every `store` command. `--watchlist` overrides the watchlist file.

`run` prints one JSON summary: `status` (`ok` or `skipped`), `run_at`, the entry count per list, the number of current, new and removed matches, the count per kind, the crt.sh result and any warnings. The summary carries counts only, never watched values. It exits 0 on success, including a missing file, and 1 on an error such as a broken file.

`matches` prints the current matches as `{"matches": [...]}`, newest first. `--since` keeps matches first seen at or after that time. `--list` may be repeated.

`hits` prints matches first seen at or after `--since` in the shape the daily briefing reads for its intel store section: an envelope whose `data.hits` rows have `id`, `kind`, `value` (the store value that matched), `seen` (the first match time, ISO 8601 UTC) and `asset` (the watchlist entry). The briefing ties a hit to an inventoried asset only when `asset` equals an asset name in `assets.yaml`.

## Nightly run

The nightly job calls:

```sh
cyberau-mcp store watchlist run
```

Add `--crtsh` to look for lookalike certificates as well. The job needs no agent and no key. On a fresh install with no watchlist it succeeds and does nothing.

## Privacy

Watched values stay on the machine. Matching reads the local store only.

The one exception is `run --crtsh`. It sends each entry under `domains`, and nothing else, to crt.sh through the crt.sh connector (keyless, one request every five seconds, results cached for 24 hours). Each query is written to the audit log as a `tool_call` for `crtsh_certs` with the domain in its arguments, before the result is used. If the audit log cannot be written, crt.sh is not queried. If the connector is not installed or a query fails, the run continues with a warning.

crt.sh is searched for certificates on the watched domain and its subdomains. A certificate name on those certificates that is a lookalike, and not the domain or one of its subdomains, is stored with the reference kind `crtsh`. Such a match is replaced on the next successful query for its domain. If queries keep failing, or later runs leave out `--crtsh`, it is deleted after seven days.

## Follow-up

- Cloudflare Radar BGP hijack and route leak events for watched ASNs. Radar needs a key and there is no Python client in this checkout yet, so ASN alerts come only from `asn` indicators in the store.
- crt.sh only returns certificates that carry a watched name. Finding lookalike certificates that do not, for example by querying generated permutations, is not done.

---

Owner ticket: 062
Last verified: 18 October 2026
