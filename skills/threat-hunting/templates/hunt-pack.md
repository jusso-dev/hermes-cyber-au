# Hunt pack

Fill this in for a person to review. Delete a heading only when the procedure says the source is missing, and write that the source is missing.

## Hypothesis

One or two sentences.

## ATT&CK

Technique id, and the name and tactic only when `mcp__attack__attack_technique` returned them. Otherwise name the missing source.

## Existing Sigma rule

Author and id from the SigmaHQ record, or a statement that the sigma source is missing. A new draft is not a SigmaHQ rule.

## Sigma

Label the block as a proposal. Include `title`, `id`, and `author`.

## KQL

Label pySigma output as pySigma output. Label a hand draft as a hand draft. Include the schema-check result. If the check is not ready, show the errors and do not call the query ready.

## Test events

One true positive and one false positive. Use synthetic observables and defang them.

## Tuning

What a person might exclude after review. Do not change a tenant from here.

## Boundary

Proposal: review this draft. This skill does not create a Sentinel analytics rule and does not run a hunt.

## References

One `Source:` line for each fact, in the form `Source: <name>, <version>, retrieved <YYYY-MM-DD>`.
