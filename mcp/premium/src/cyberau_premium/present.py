"""Shape a finding for a tool result. Feed text is redacted and wrapped as untrusted."""

from __future__ import annotations

from cyberau_common.envelope import untrusted_text

from cyberau_premium.base import ExposureFinding
from cyberau_premium.redact import redact_text


def finding_payload(finding: ExposureFinding) -> dict:
    """Return the finding as JSON data. Free text never reaches a result unwrapped.

    Enumerated fields are validated by the model. Names, references and data
    classes come from the vendor feed, so they are redacted and then wrapped.
    """
    payload = finding.model_dump(mode="json", exclude_none=True)
    source = finding.vendor

    def wrap(value: str) -> str:
        return untrusted_text(redact_text(value), source)

    payload["subject"]["value"] = wrap(finding.subject.value)
    if finding.subject.watchlist_entry is not None:
        payload["subject"]["watchlist_entry"] = wrap(finding.subject.watchlist_entry)
    if finding.source_ref is not None:
        payload["source_ref"] = wrap(finding.source_ref)
    if finding.data_classes is not None:
        payload["data_classes"] = [wrap(item) for item in finding.data_classes]
    return payload
