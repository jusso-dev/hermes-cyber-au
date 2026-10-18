# Asset matching for the daily briefing

`skills/vuln-prioritisation` is not in this checkout. This file is the match rule the daily briefing uses. It is not a copy of that skill. The briefing does not rank a scanner export and it does not quote Essential Eight patch timeframes.

## Normal form

1. Apply Unicode NFKC and casefold.
2. Replace `&` with ` and `.
3. Turn every run of characters that is not a letter or digit into a space.
4. Drop tokens shorter than two characters.
5. Drop these organisation suffixes: ag, co, company, corp, corporation, gmbh, inc, incorporated, limited, llc, ltd, plc, pty.

Two fields match when the token sets are equal, or one set is a subset of the other. An empty set never matches. A squashed token does not match a split phrase: `edgegate` matches `Edgegate ADC`, and it does not match `Edge Gate`.

Write `vendor` and `product` in the asset inventory as the catalogue token, not a private nickname.

## KEV vendorProject and product

A KEV row matches an asset when `vendorProject` matches `vendor` and `product` matches `product`, both under the rule above. The briefing records the rule name `kev-vendor-product`.

Worked example, synthetic:

| Side | Vendor | Product | Tokens |
|---|---|---|---|
| Asset | examplevendor | edgegate | examplevendor; edgegate |
| KEV | Examplevendor | Edgegate ADC | examplevendor; edgegate, adc |

The vendor sets are equal. The asset product set is a subset of the KEV product set. The row matches.

`Exampleos Ltd` matches vendor `exampleos` because `ltd` is dropped. `Workstation Pro` matches product `workstation`. `Unrelated` / `Widget` matches neither asset.

## NVD CPE

A CPE 2.3 string matches when its part is `a`, `o`, or `h`, and its vendor and product components match the asset under the same token rule. The form is `cpe:2.3:<part>:<vendor>:<product>:...`. A `*` vendor or product does not match. The briefing records the rule name `nvd-cpe`.

`cpe:2.3:a:examplevendor:edgegate:3.0:*:*:*:*:*:*:*` matches the North gateway asset above.

If both the KEV pair and a CPE match, the recorded rule is `kev-vendor-product`.

## What enters Act today

A vulnerability is listed in Act today only when it matches at least one asset and one of these is inside the briefing window:

- the KEV `dateAdded` (a date, so the whole Australia/Sydney day counts), or
- an ASD ACSC alert names the CVE, or
- the EPSS score is at least 0.7 and the previous score was below 0.7 (or there was no previous score).

That third test is the Tier 1 EPSS cut this briefing uses until `vuln-prioritisation` ships. A KEV row whose date ends before the window opens is not "new", even when the product matches. A KEV row inside the window that matches no asset is left out. ASD ACSC alerts are still listed on their own.

## Building the inventory

`cyberau-mcp assets import <file.csv|sbom.cdx.json>` writes `assets.yaml` in the flat shape this rule reads, with `name`, `vendor`, `product`, `exposure` and `owner` on every asset and `version`, `cpe`, `purl`, `criticality` and `environment` when known. An imported asset with a `cpe` matches under `nvd-cpe` above. `cyberau-mcp assets match` applies the same token rule and labels a name-only hit `vendor-product-fuzzy`.
