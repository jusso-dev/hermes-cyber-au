# Scoring rules

Score one indicator after the connectors return. Use structured fields only.
Pulse text, tags written as prose, and certificate names do not add points.

`scripts/score.py` is the reference implementation. Confidence is an integer
from 0 to 100. Class totals are capped at 100.

## Point table

| source_id | classification | points |
|---|---|---|
| feodo | malicious | 40 |
| malwarebazaar | malicious | 40 |
| urlhaus | malicious | 40 |
| threatfox | malicious | 40 |
| greynoise | malicious | 25 |
| greynoise | benign | 25 |
| greynoise | suspicious | 10 |
| radar | benign | 50 |
| crtsh | suspicious | 20 |
| lookalike | suspicious | 30 |
| internetdb | unknown | 0 |

One signal per source id and class. Add the points, then cap each class at 100.

The first pulse adds 10 suspicious points. Each further pulse adds 5, capped at 20.
A rank from 1 to 10000 inclusive adds 50 benign points. No rank adds nothing.
A certificate whose not_before is within 30 days adds 20 suspicious points.
Count the window in whole days against the retrieval date, including day 30.
A certificate dated after the retrieval date adds nothing.

GreyNoise classification wins over the RIOT flag. Malicious stays malicious.
RIOT with no malicious classification is benign (25). Noise with a missing or
unknown classification is suspicious (10). InternetDB ports, hostnames and
CPEs are context. They add 0 points.

A lookalike signal is 30 suspicious points when a token in
`references/au-bank-domains.txt` matches a label or a hyphen-separated part,
and the domain is not that brand's owned domain or a subdomain of it.

## Rules, in order

1. Malicious points of 40 or more set a malicious verdict. Benign points do not cancel them.
2. Malicious points of 25 or more set a malicious verdict when benign points are 0.
3. Benign points of 25 or more set a benign verdict when malicious points are 0 and suspicious points are below 20.
4. Suspicious points of 15 or more set a suspicious verdict when the earlier rules did not.
   A disagreement also sets suspicious: any malicious points still left, or both benign and suspicious points above 0.
5. Otherwise the verdict is unknown and the confidence is 0.

When the verdict is malicious, confidence is the malicious total.
When the verdict is benign, confidence is the benign total.
When the verdict is suspicious and suspicious points are above 0, confidence is the suspicious total.
When the verdict is suspicious only because malicious and benign points disagree, confidence is the lower of those two totals.
A malicious total below 25, with no benign points and no suspicious points, is suspicious and the confidence is that malicious total.

Point totals below a threshold are still reported. They do not raise an unknown confidence above 0.

Sources on the verdict are the source ids that added points to the winning class.
When a suspicious verdict comes only from a disagreement, the sources are the malicious and benign ids.
Every other signal is context. First seen is the earliest date on a signal that added points.
Last seen is the latest. Use `unknown` in the table when a side has no date, and `null` in the JSON.

## Worked examples

Feodo only: malicious, confidence 40.

Radar high rank only: benign, confidence 50.

Lookalike plus a recent certificate: suspicious, confidence 50.

One OTX pulse: unknown, confidence 0.

Feodo plus a high rank: malicious, confidence 40.

GreyNoise malicious plus a high rank: suspicious, confidence 25.

Lookalike plus a high rank: suspicious, confidence 30.

## Fresh store row

A fresh local observation is copied, not re-scored.
Fresh means last_seen is within 6 hours of the check time, in UTC, including exactly 6 hours.
A future timestamp is not fresh. Set `from_store` to true and copy the stored verdict and confidence.
Put the stored confidence on that class in `points` and leave the other classes at 0.
A stored unknown stays at confidence 0.

Do not call external connectors for a fresh row unless the analyst asked to refresh.
