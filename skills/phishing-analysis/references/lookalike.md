# Lookalike rules

The helper `scripts/analyse_email.py` applies these rules. It does not use the network.
`references/au-brands.json` holds the raw hostnames the helper compares. Prose in this
skill defangs those hosts. The list is a shipped aid, version 0.1.0, retrieved 2026-10-17.
It is not an official register of Australian brands. Pass the organisation's own domains
on the command line. If they are omitted, say so and compare only against the shipped list.

Source: hermes-cyber-au phishing brand list, 0.1.0, retrieved 2026-10-17.

## Registrable domain

This is an approximation, not the public suffix list. For `com[.]au`, `net[.]au`, `org[.]au`,
`gov[.]au`, `edu[.]au`, `asn[.]au`, `id[.]au`, `co[.]nz`, `net[.]nz`, `org[.]nz`, `govt[.]nz`,
`co[.]uk`, and `org[.]uk`, the registrable domain is the last three labels. Otherwise it is
the last two labels. A host is under a domain when it equals that domain or is a subdomain
of it. `login[.]ato[.]gov[.]au[.]evil[.]example` is not under `ato[.]gov[.]au`.

## Folding

Lowercase the host. Decode a punycode label (`xn--`) with IDNA, then map confusable
characters to Latin letters. The map is a working subset, not the whole Unicode
confusables catalogue. It includes common Cyrillic and Greek lookalikes. Digits `0`,
`1`, and `5` fold to `o`, `l`, and `s`.

## Decision order

1. Exact own domain, or a subdomain of one: owned. Not a lookalike.
2. Exact shipped brand domain, or a subdomain of one: official. Not a lookalike.
3. Otherwise apply the first matching rule below. A match is a lookalike.

| Rule | When it matches |
|---|---|
| homoglyph | The folded host is under a brand or own domain and the raw host is not. |
| token | A folded label, split on hyphens, equals a protected label. |
| digit-suffix | A raw token is a protected label plus one or more digits, such as `ing0`. |
| hyphen-join | The registrable label with hyphens removed equals a protected label. |
| prefix | A protected label of 5 or more characters is a prefix or suffix of a longer folded token. |
| edit-distance | The folded registrable label is close to a protected label. |

Protected labels shorter than 5 characters (`ato`, `anz`, `nab`, `ing`, `boq`) use
homoglyph, token, and digit-suffix only. They are not compared with edit distance, and
they do not use the prefix rule. `atom[.]example` does not match `ato`. `national[.]example`
does not match `nab`. `marketing[.]example[.]com` does not match `ing`.

Edit distance uses the length of the protected label. Length 5 to 7 allows distance 1.
Length 8 or more allows distance 2. The candidate length must be within that same limit.
Distance 0 is reported as token or hyphen-join, not as edit distance.

A protected label shorter than 3 characters is ignored. The label `my` is not used for
myGov. The protected label is `mygov`, and the official domain is `my[.]gov[.]au`.

## Readings

| Candidate | Reading |
|---|---|
| `ato-refund[.]example` | Token `ato`, Australian Taxation Office. |
| `www[.]ato[.]gov[.]au` | Official. |
| `updates[.]example[.]com` | No shipped brand match. |
| `combank[.]example` | Edit distance 1 from `commbank`. |

Own-domain lookalikes use the same rules. The brand name in the result is `own domain`
plus the raw own domain.
