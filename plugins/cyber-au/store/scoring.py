"""Merge observations into one verdict and confidence.

The rules are specified in ``docs/intel/scoring.md``. This module is the
implementation of that document.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

VERDICTS = ("malicious", "suspicious", "benign", "unknown")
_TIE_BREAK = {name: index for index, name in enumerate(VERDICTS)}
MISSING_CONFIDENCE = 50


def score(observations: list[dict]) -> tuple[str, int]:
    """Return ``(verdict, confidence)`` for one indicator.

    Confidence is ``support^2 / (supporters * total)``, rounded half up.
    ``support`` is the confidence sum of the winning verdict, ``supporters``
    is how many observations cast it, and ``total`` is every observation's
    confidence. A missing confidence counts as 50. A missing verdict counts
    as ``unknown``. An empty set, or a total of 0, is ``unknown`` at 0.
    """
    buckets: dict[str, list[int]] = {name: [] for name in VERDICTS}
    for observation in observations:
        verdict = observation.get("verdict") or "unknown"
        if verdict not in buckets:
            raise ValueError("verdict must be malicious, suspicious, benign or unknown")
        confidence = observation.get("confidence")
        if confidence is None:
            confidence = MISSING_CONFIDENCE
        if isinstance(confidence, bool) or not isinstance(confidence, int):
            raise ValueError("confidence must be an integer from 0 to 100")
        if confidence < 0 or confidence > 100:
            raise ValueError("confidence must be an integer from 0 to 100")
        buckets[verdict].append(confidence)

    totals = {name: sum(values) for name, values in buckets.items()}
    total = sum(totals.values())
    if total == 0:
        return "unknown", 0

    winning = max(VERDICTS, key=lambda name: (totals[name], -_TIE_BREAK[name]))
    support = totals[winning]
    supporters = len(buckets[winning])
    if support == 0 or supporters == 0:
        return "unknown", 0
    confidence = _round_half_up(support * support, supporters * total)
    return winning, min(100, confidence)


def _round_half_up(numerator: int, denominator: int) -> int:
    value = Decimal(numerator) / Decimal(denominator)
    return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
