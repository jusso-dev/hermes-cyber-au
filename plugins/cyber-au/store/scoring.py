"""Merge observations into one verdict and confidence.

The rules are specified in ``docs/intel/scoring.md``. This module is the
implementation of that document.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

VERDICTS = ("malicious", "suspicious", "benign", "unknown")
_TIE_BREAK = {name: index for index, name in enumerate(VERDICTS)}
MISSING_CONFIDENCE = 50


def score(observations: list[dict], counters: list[dict] | None = None) -> tuple[str, int]:
    """Return ``(verdict, confidence)`` for one indicator.

    Confidence is ``support^2 / (supporters * total)``, rounded half up.
    ``support`` is the confidence sum of the winning verdict, ``supporters``
    is how many observations cast it, and ``total`` is every observation's
    confidence. A missing confidence counts as 50. A missing verdict counts
    as ``unknown``. An empty set, or a total of 0, is ``unknown`` at 0.

    ``counters`` are folded observations: each has ``verdict``, ``observations``
    (how many rows were folded) and ``confidence_sum`` (their confidence total,
    with a missing confidence already counted as 50).
    """
    support = dict.fromkeys(VERDICTS, 0)
    supporters = dict.fromkeys(VERDICTS, 0)
    for observation in observations:
        verdict = observation.get("verdict") or "unknown"
        if verdict not in support:
            raise ValueError("verdict must be malicious, suspicious, benign or unknown")
        confidence = observation.get("confidence")
        if confidence is None:
            confidence = MISSING_CONFIDENCE
        if isinstance(confidence, bool) or not isinstance(confidence, int):
            raise ValueError("confidence must be an integer from 0 to 100")
        if confidence < 0 or confidence > 100:
            raise ValueError("confidence must be an integer from 0 to 100")
        support[verdict] += confidence
        supporters[verdict] += 1

    for counter in counters or ():
        verdict = counter.get("verdict") or "unknown"
        if verdict not in support:
            raise ValueError("verdict must be malicious, suspicious, benign or unknown")
        count = counter.get("observations")
        confidence_sum = counter.get("confidence_sum")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError("counter observations must be a positive integer")
        if (
            isinstance(confidence_sum, bool)
            or not isinstance(confidence_sum, int)
            or confidence_sum < 0
        ):
            raise ValueError("counter confidence_sum must be a non-negative integer")
        support[verdict] += confidence_sum
        supporters[verdict] += count

    total = sum(support.values())
    if total == 0:
        return "unknown", 0

    winning = max(VERDICTS, key=lambda name: (support[name], -_TIE_BREAK[name]))
    winning_support = support[winning]
    winning_supporters = supporters[winning]
    if winning_support == 0 or winning_supporters == 0:
        return "unknown", 0
    confidence = _round_half_up(winning_support * winning_support, winning_supporters * total)
    return winning, min(100, confidence)


def _round_half_up(numerator: int, denominator: int) -> int:
    value = Decimal(numerator) / Decimal(denominator)
    return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
