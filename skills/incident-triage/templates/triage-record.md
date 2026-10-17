# Triage record

Header: id, opened (`YYYY-MM-DD`, Australia/Sydney), analyst, status.

Status stays `open`. This skill does not set it to contained, notified, or submitted.

## Timeline

| Time (Australia/Sydney) | Event | Source |
|---|---|---|
| YYYY-MM-DD HH:MM | What was observed or reported | Alert, tool, or person |

## Observables

Defanged once. Do not put raw tool arguments in this table.

| Observable | Type | Where seen |
|---|---|---|
| defanged value | ip, domain, url, hash, email, or host | Alert or tool |

## ATT&CK

| Id | Name | Confidence | Reason |
|---|---|---|---|
| id from the tool or the attack mapping | name | high, medium, or low | Why that confidence |

## Severity

ACSC category and the matrix version, or `ACSC matrix version was not retrieved.` plus local P1 to P4, with the reasons.

## Containment proposals

Each option starts with `Proposal:` and states the risk and how it is reversed. None are executed.

## Reporting triggers

For NDB, SOCI, and ransomware payment: open or `not indicated`, the awareness time, the handoff skill, and a deadline only when a retrieved source states it.

## Open questions

Facts the record does not contain. Write `I don't know` rather than a guess.

## Sources

One citation per line.

```text
Source: <name>, <version>, retrieved YYYY-MM-DD
```

## Summary for the on-call lead

A short paragraph. Say what is proposed and that nothing was sent, blocked, isolated, or posted.
