"""Score enrichment signals. Pure helper: no network.

The rules are published in references/scoring.md. Pulse text is not an input.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date

PRIMARY = {
    "feodo": 40,
    "malwarebazaar": 40,
    "urlhaus": 40,
    "threatfox": 40,
}
GREYNOISE_MALICIOUS = 25
GREYNOISE_BENIGN = 25
GREYNOISE_SUSPICIOUS = 10
RADAR_BENIGN_POINTS = 50
RADAR_RANK_MAX = 10_000
CRTSH_POINTS = 20
CRTSH_WINDOW_DAYS = 30
LOOKALIKE_POINTS = 30
OTX_FIRST = 10
OTX_EXTRA = 5
OTX_CAP = 20
MALICIOUS_PRIMARY = 40
MALICIOUS_SINGLE = 25
BENIGN_MIN = 25
BENIGN_BLOCK_SUSPICIOUS = 20
SUSPICIOUS_VERDICT_MIN = 15
CLASS_CAP = 100

_VERDICTS = {"malicious", "suspicious", "benign", "unknown"}
_CLASSES = _VERDICTS
_SOURCE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_WHEN_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?$")


@dataclass(frozen=True)
class Signal:
    source_id: str
    classification: str
    points: int
    first_seen: str | None = None
    last_seen: str | None = None

    def __post_init__(self) -> None:
        if not _SOURCE_RE.fullmatch(self.source_id):
            raise ValueError(f"bad source id: {self.source_id}")
        if self.classification not in _CLASSES:
            raise ValueError(f"bad classification: {self.classification}")
        if type(self.points) is not int or not 0 <= self.points <= CLASS_CAP:
            raise ValueError("points must be an integer from 0 to 100")
        for label, value in (
            ("first_seen", self.first_seen),
            ("last_seen", self.last_seen),
        ):
            if value is not None and not _WHEN_RE.fullmatch(value):
                raise ValueError(f"{label} must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ")


@dataclass(frozen=True)
class Verdict:
    verdict: str
    confidence: int
    sources: tuple[str, ...]
    context_sources: tuple[str, ...]
    first_seen: str | None
    last_seen: str | None
    malicious_points: int
    suspicious_points: int
    benign_points: int
    from_store: bool = False

    def __post_init__(self) -> None:
        if self.verdict not in _VERDICTS:
            raise ValueError(f"bad verdict: {self.verdict}")
        if type(self.confidence) is not int or not 0 <= self.confidence <= CLASS_CAP:
            raise ValueError("confidence must be an integer from 0 to 100")


def otx_points(pulse_count: int) -> int:
    """Suspicious points from a pulse count. The pulse text does not add points."""
    if type(pulse_count) is not int or pulse_count < 0:
        raise ValueError("pulse_count must be an integer >= 0")
    if pulse_count == 0:
        return 0
    return min(OTX_CAP, OTX_FIRST + OTX_EXTRA * (pulse_count - 1))


def certificate_points(not_before: str, as_of: str) -> int:
    """20 suspicious points when the certificate starts within the window, inclusive."""
    start = date.fromisoformat(not_before)
    day = date.fromisoformat(as_of)
    age = (day - start).days
    if 0 <= age <= CRTSH_WINDOW_DAYS:
        return CRTSH_POINTS
    return 0


def radar_points(rank: int | None) -> int:
    """50 benign points for a rank from 1 to 10000. No rank adds nothing."""
    if rank is None:
        return 0
    if type(rank) is not int or rank < 1:
        raise ValueError("rank must be an integer >= 1")
    if rank <= RADAR_RANK_MAX:
        return RADAR_BENIGN_POINTS
    return 0


def greynoise_signal(
    classification: str | None,
    *,
    riot: bool = False,
    noise: bool = False,
) -> Signal | None:
    """Classification wins. RIOT alone is benign. Unknown noise is suspicious."""
    label = (classification or "").strip().lower()
    if label == "malicious":
        return Signal("greynoise", "malicious", GREYNOISE_MALICIOUS)
    if label == "benign" or riot:
        return Signal("greynoise", "benign", GREYNOISE_BENIGN)
    if noise:
        return Signal("greynoise", "suspicious", GREYNOISE_SUSPICIOUS)
    return None


def score_signals(signals: Sequence[Signal]) -> Verdict:
    """Apply the published rules. One signal per source id and class."""
    seen: set[tuple[str, str]] = set()
    for signal in signals:
        key = (signal.source_id, signal.classification)
        if key in seen:
            raise ValueError(
                f"duplicate signal: {signal.source_id} {signal.classification}"
            )
        seen.add(key)
    malicious = _total(signals, "malicious")
    suspicious = _total(signals, "suspicious")
    benign = _total(signals, "benign")
    verdict, confidence = _decide(malicious, suspicious, benign)
    supporting = _supporting(signals, verdict, suspicious)
    return Verdict(
        verdict,
        confidence,
        supporting,
        _context(signals, supporting),
        *_bounds(signals),
        malicious,
        suspicious,
        benign,
        False,
    )


def from_store(
    verdict: str,
    confidence: int,
    first_seen: str | None,
    last_seen: str | None,
) -> Verdict:
    """Copy a fresh store row. Do not pass it through the point rules."""
    if verdict not in _VERDICTS:
        raise ValueError(f"bad verdict: {verdict}")
    if type(confidence) is not int or not 0 <= confidence <= CLASS_CAP:
        raise ValueError("confidence must be an integer from 0 to 100")
    if verdict == "unknown" and confidence != 0:
        raise ValueError("unknown confidence must be 0")
    for label, value in (("first_seen", first_seen), ("last_seen", last_seen)):
        if value is not None and not _WHEN_RE.fullmatch(value):
            raise ValueError(f"{label} must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ")
    points = {"malicious": 0, "suspicious": 0, "benign": 0}
    if verdict != "unknown":
        points[verdict] = confidence
    return Verdict(
        verdict,
        confidence,
        ("local",),
        (),
        first_seen,
        last_seen,
        points["malicious"],
        points["suspicious"],
        points["benign"],
        True,
    )


def proposal_source_ids(signals: Sequence[Signal]) -> tuple[str, ...]:
    """Sources that added points. Zero-point context is not a store proposal."""
    return _unique(signal.source_id for signal in signals if signal.points > 0)


def _decide(malicious: int, suspicious: int, benign: int) -> tuple[str, int]:
    if malicious >= MALICIOUS_PRIMARY:
        return "malicious", malicious
    if malicious >= MALICIOUS_SINGLE and benign == 0:
        return "malicious", malicious
    if benign >= BENIGN_MIN and malicious == 0 and suspicious < BENIGN_BLOCK_SUSPICIOUS:
        return "benign", benign
    if (
        suspicious >= SUSPICIOUS_VERDICT_MIN
        or malicious > 0
        or (benign > 0 and suspicious > 0)
    ):
        if suspicious > 0:
            confidence = suspicious
        elif malicious > 0 and benign > 0:
            confidence = min(malicious, benign)
        else:
            confidence = max(malicious, benign)
        return "suspicious", confidence
    return "unknown", 0


def _total(signals: Sequence[Signal], classification: str) -> int:
    raw = sum(
        signal.points for signal in signals if signal.classification == classification
    )
    return min(CLASS_CAP, raw)


def _supporting(
    signals: Sequence[Signal], verdict: str, suspicious: int
) -> tuple[str, ...]:
    if verdict == "unknown":
        return ()
    if verdict == "suspicious" and suspicious == 0:
        classes = {"malicious", "benign"}
    else:
        classes = {verdict}
    return _unique(
        signal.source_id
        for signal in signals
        if signal.classification in classes and signal.points > 0
    )


def _context(signals: Sequence[Signal], supporting: tuple[str, ...]) -> tuple[str, ...]:
    chosen = set(supporting)
    return _unique(
        signal.source_id for signal in signals if signal.source_id not in chosen
    )


def _bounds(signals: Sequence[Signal]) -> tuple[str | None, str | None]:
    dated = [signal for signal in signals if signal.points > 0]
    firsts = [signal.first_seen for signal in dated if signal.first_seen]
    lasts = [signal.last_seen for signal in dated if signal.last_seen]
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return tuple(seen)
