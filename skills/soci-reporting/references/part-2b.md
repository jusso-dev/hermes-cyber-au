# SOCI Act Part 2B reference

Guidance for an analyst. Not legal advice, an audit, or a formal assessment.
Bundled from Compilation No. 9 of the Security of Critical Infrastructure Act 2018
(Cth), compilation date 4 June 2026, register id C2026C00213, retrieved 2026-10-17.
Quote the Act for the obligation. Do not treat this note as a substitute for it.

Source: Security of Critical Infrastructure Act 2018, Compilation No. 9, retrieved 2026-10-17

The approved form and the phone channel were not re-fetched on 2026-10-17.
The project research note records a review of the ACSC reporting page on
2026-10-16. Copy fields from the live form. Do not invent a field.

Source: ACSC report a cyber security incident page, none, retrieved 2026-10-16

## When Part 2B applies

s 30BB(1): this Part applies to a critical infrastructure asset if the asset is
specified in the rules, or the asset is the subject of a declaration under
s 51 and that declaration determines that this Part applies.

s 30BB(3): the rules may delay the start. Ask. Do not assume that every
critical infrastructure asset is covered.

## What counts as a cyber security incident

s 12M: one or more acts, events or circumstances involving unauthorised access
to computer data or a computer program, unauthorised modification of computer
data or a computer program, unauthorised impairment of electronic communication
to or from a computer, or unauthorised impairment of the availability,
reliability, security or operation of a computer, computer data or a computer
program. s 12N gives the meaning of unauthorised access, modification or
impairment. If the triage record does not support s 12M, say so and ask.

## Critical incident (s 30BC)

The entity is the responsible entity, and it becomes aware that a cyber
security incident has occurred or is occurring, and the incident has had or is
having a significant impact (direct or indirect) on the availability of the
asset. Imminent and "likely" are not in s 30BC(1).

The report goes to the relevant Commonwealth body (s 30BF). It is about the
incident and includes such information, if any, as the rules prescribe. Give it
as soon as practicable, and in any event within 12 hours after the entity
becomes aware.

The report may be oral or in writing. A written report must be in the approved
form (a form approved by the Secretary). If the report is oral, make a written
record in the approved form, give a copy to the relevant Commonwealth body, and
do so within 84 hours after the oral report is given. The 84 hours do not run
from awareness unless the oral report was given at that same instant. Under
s 30BC(5) the head of the relevant Commonwealth body may exempt an entity, by
written notice about a specified incident, from the written record. Ask whether
there is such a notice. Do not assume one.

s 30BEA: a significant impact on availability means the asset is used in
connection with the provision of essential goods or services and the incident
has materially disrupted the availability of those essential goods or services,
or a circumstance specified in the rules exists.

## Other incident (s 30BD)

The entity is the responsible entity, and it becomes aware that a cyber
security incident has occurred, is occurring or is imminent, and the incident
has had, is having, or is likely to have a relevant impact on the asset.

s 8G(2): a relevant impact of an incident on a critical infrastructure asset is
an impact (direct or indirect) on availability, integrity or reliability of the
asset, or on the confidentiality of information about the asset, information
stored in the asset, or computer data if the asset is computer data.

Give the report as soon as practicable, and in any event within 72 hours after
awareness. Oral or written, same approved-form rule. If oral, the written
record is due within 48 hours after the oral report is given. s 30BD(5) gives
the same written-record exemption.

s 30BD(1), as compiled here, does not say that an incident reported under
s 30BC is exempt from s 30BD. A significant availability impact is also a
relevant impact. Meet the 12 hour s 30BC deadline first. Do not claim that one
report satisfies both sections unless a source in front of you says so.

## Who receives the report

s 30BF: the relevant Commonwealth body is a Department specified in the rules,
or a body established by a Commonwealth law and specified in the rules. If no
rules are in force for those paragraphs, the body is ASD (the Australian
Signals Directorate). Ask whether such rules are in force. Do not assume ASD
when the rules name someone else. This bundle does not contain the current
rules text.

When the body is ASD, a person submits through the ACSC reporting page
(https://www.cyber.gov.au/report-a-cyber-security-incident) or by calling
1300 CYBER1. This skill never places that call and never lodges the form.

## Deadlines and daylight saving

Use `scripts/deadlines.py`. It adds the hour offset to the UTC instant, then
converts the result to Australia/Sydney. The October forward transition and
the April backward transition both change the Sydney offset by one hour. A
wall-clock addition of the same number of hours lands on the wrong Sydney time.

The report clock starts at awareness (s 30BC(1)(d), s 30BD(1)(d)). The written
record clock starts when the oral report is given (s 30BC(3)(b), s 30BD(3)(b)).
If the oral time is unknown, leave the written-record instant blank. An oral
time before awareness is an input error. An oral time after the report is due
means the report was late (`oral_after_report_due` in the script output).

## Related obligations to flag

Do not decide these in this skill:

- Notifiable Data Breaches scheme, Privacy Act 1988 (Cth) Part IIIC, when
  personal information is involved.
- Ransomware payment reporting under the Cyber Security Act 2024 (Cth). Confirm
  the current section on the register before quoting a number. This bundle does
  not state that section.
- The sector regulator named in the triage record or in a cited source. Do not
  invent a regulator.
