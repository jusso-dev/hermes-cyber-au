# ADR 0001: Analyst observations are STIX sightings

## Status

Accepted.

## Context

The intel store keeps every observation on an indicator. STIX 2.1 can represent that either as a `sighting` relationship or as `x_cyberau_sources` on the indicator. A sighting must reference a STIX domain object. The export creates an `indicator` domain object only when the stored verdict is `malicious` or `suspicious`.

## Decision

Analyst observations (`source_id` `analyst`) are `sighting` objects when that indicator domain object exists. The sighting references the indicator, not the observable. Every observation, analyst or feed, is also listed in `x_cyberau_sources` on that indicator so a later import can replay the same votes.

When the verdict is not `malicious` or `suspicious`, there is no indicator domain object. Those observations, including an analyst note, stay in `x_cyberau_sources` on the observable. They are not sightings, because a sighting would have nothing valid to point at.

Import reads `x_cyberau_sources` and does not also replay sightings, so an analyst observation is not counted twice.

## Consequences

A shareable bundle shows analyst sightings for malicious and suspicious indicators. Benign and unknown indicators still round trip through the observable. Feed observations do not become sightings.
