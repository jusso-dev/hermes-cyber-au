"""Worked examples from docs/intel/scoring.md."""

from __future__ import annotations

import pytest
from store.scoring import score


@pytest.mark.parametrize(
    ("observations", "verdict", "confidence"),
    [
        ([{"verdict": "malicious", "confidence": 80}], "malicious", 80),
        (
            [
                {"verdict": "malicious", "confidence": 80},
                {"verdict": "benign", "confidence": 80},
            ],
            "malicious",
            40,
        ),
        (
            [
                {"verdict": "malicious", "confidence": 10},
                {"verdict": "benign", "confidence": 90},
            ],
            "benign",
            81,
        ),
        (
            [
                {"verdict": "malicious", "confidence": 1},
                {"verdict": "benign", "confidence": 1},
            ],
            "malicious",
            1,
        ),
        ([{"verdict": "suspicious", "confidence": None}], "suspicious", 50),
        (
            [
                {"verdict": "suspicious", "confidence": 10},
                {"verdict": "benign", "confidence": 10},
            ],
            "suspicious",
            5,
        ),
        ([], "unknown", 0),
        ([{"verdict": "malicious", "confidence": 0}], "unknown", 0),
        ([{"verdict": None, "confidence": 40}], "unknown", 40),
    ],
)
def test_score_examples(observations, verdict, confidence):
    assert score(observations) == (verdict, confidence)


def test_counters_score_like_the_observations_they_replace():
    observations = [
        {"verdict": "malicious", "confidence": 80},
        {"verdict": "benign", "confidence": 80},
    ]
    counters = [{"verdict": "benign", "observations": 1, "confidence_sum": 80}]
    assert score(observations[:1], counters) == score(observations)


def test_score_rejects_bad_verdict_and_confidence():
    with pytest.raises(ValueError):
        score([{"verdict": "evil", "confidence": 10}])
    with pytest.raises(ValueError):
        score([{"verdict": "malicious", "confidence": True}])
    with pytest.raises(ValueError):
        score([{"verdict": "malicious", "confidence": 101}])
