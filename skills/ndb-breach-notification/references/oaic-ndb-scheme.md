# OAIC NDB scheme notes

Hand-written fallback for when `mcp__aureg__aureg_obligation` or `mcp__aureg__aureg_deadline` is unavailable. Prefer the tool envelope, and its `retrieved_at` value, when the tool runs.

These are short notes from OAIC pages retrieved on 2026-10-17. They are guidance, not legal advice. They are not a copy of those pages.

Pages:

- Part 4, Notifiable Data Breach (NDB) scheme: `https://www.oaic.gov.au/privacy/notifiable-data-breaches/preventing-preparing-for-and-responding-to-data-breaches/data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme`
- Quick reference guide for responding to data breaches: `https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches`
- Report a data breach: `https://www.oaic.gov.au/privacy/notifiable-data-breaches/report-a-data-breach`
- OAIC online form for an eligible data breach statement: `https://webform.oaic.gov.au/prod?entitytype=DBN&layoutcode=DataBreachWF`

## Three elements

The OAIC states that an eligible data breach arises when three criteria are satisfied:

1. there is unauthorised access to or unauthorised disclosure of personal information, or a loss of personal information, that an entity holds;
2. this is likely to result in serious harm to one or more individuals; and
3. the entity has not been able to prevent the likely risk of serious harm with remedial action.

Source: OAIC Notifiable Data Breaches scheme, none, retrieved 2026-10-17

For a loss, the OAIC states there is no eligible data breach if later unauthorised access or disclosure is unlikely (s 26WE(2)(b)(ii)). Its examples are information remotely deleted before anyone could access it, and information encrypted to a high standard. An OAIC example of a loss is personal information left on public transport, including unsecured computer equipment or a portable storage device.

Source: OAIC Notifiable Data Breaches scheme, none, retrieved 2026-10-17

## Serious harm

The OAIC states that "likely" means more probable than not, judged by a reasonable person in the entity's position. Serious harm is not defined. In this context it may include serious physical, psychological, emotional, financial, or reputational harm. Section 26WG lists relevant matters, which the Part 4 page says are non-exhaustive and which begin with the kind or kinds of information and the sensitivity of the information. This note does not reproduce the rest of that list.

Source: OAIC Notifiable Data Breaches scheme, none, retrieved 2026-10-17

## Assessment period

The OAIC states that an entity must take all reasonable steps to complete the assessment within 30 calendar days after the day the entity became aware of the grounds that caused it to suspect an eligible data breach (s 26WH(2)). The Commissioner expects entities to treat 30 days as a maximum and to finish sooner where they can.

Source: OAIC Notifiable Data Breaches scheme, none, retrieved 2026-10-17

Count the Sydney calendar day of awareness as the day in that sentence. The last day of the period is 30 calendar days after that day. `scripts/assessment_deadline.py` uses that count. Its warning flag, at 7 or fewer calendar days, is an operational marker for this skill. It is not an OAIC rule.

The quick reference uses the same 30 calendar day assessment period where the entity suspects it may have experienced an eligible data breach. It also says that if the information is held jointly, only one entity needs to assess the breach.

Source: OAIC Notifiable Data Breaches scheme, none, retrieved 2026-10-17

## Remedial action

The OAIC states that if remedial action means the breach would not be likely to result in serious harm, it is not an eligible data breach (s 26WF). For a loss, remedial action is adequate if it prevents unauthorised access to or disclosure of the information.

Source: OAIC Notifiable Data Breaches scheme, none, retrieved 2026-10-17

## Statement and individual notice

The OAIC states that the entity must prepare a statement and give a copy to the Commissioner as soon as practicable after becoming aware of the eligible data breach (s 26WK(2)). The statement must include:

- the identity and contact details of the entity (s 26WK(3)(a));
- a description of the eligible data breach (s 26WK(3)(b));
- the kind or kinds of information involved (s 26WK(3)(c));
- the steps the entity recommends that individuals take (s 26WK(3)(d)).

Source: OAIC Notifiable Data Breaches scheme, none, retrieved 2026-10-17

The OAIC states that the entity must notify affected individuals of the contents, or, if that is not practicable, publish a copy on its website and take reasonable steps to publicise the contents (s 26WL(2)). The Part 4 page points entities to the OAIC online form above. If the form cannot be used, the page says to contact the OAIC enquiries line. This note does not record that phone number.

Source: OAIC Notifiable Data Breaches scheme, none, retrieved 2026-10-17

## Not in this note

This note does not state a SOCI reporting period, a ransomware payment reporting period, a state or territory notification period, or whether a particular organisation is an APP entity. If the question needs one of those facts, write `I don't know` unless `aureg_obligation` returned it. Hand a SOCI question to `soci-reporting`.

The Commissioner provides general information about the scheme and will not provide detailed advice on a specific breach. Entities should seek their own legal and technical advice.

Source: OAIC Notifiable Data Breaches scheme, none, retrieved 2026-10-17
