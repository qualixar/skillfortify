"""E5: trust monotonicity, weight sensitivity, and decay.

Checks three properties of the trust algebra: that a score never falls while
all incoming evidence is non-negative and stays within bounds, how far scores
move as the weight vector varies, and how an unmaintained skill's score decays
over a six-month horizon.

The decay rate is configurable, so the profile is reported for the shipped
default. The default is what a user gets and is therefore the figure to quote.
"""

from __future__ import annotations

import random
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any

from skillfortify.core.trust.engine import TrustEngine
from skillfortify.core.trust.models import TrustSignals, TrustWeights

SEED = 42
SCENARIOS = 10
TIME_STEPS = 20
WEIGHT_VECTORS = 100
DECAY_HORIZON_DAYS = 180

#: A slower alternative rate, reported alongside the default so the effect of
#: tuning this parameter is visible rather than implied.
ALTERNATE_DECAY_RATE = 0.005

_SIGNAL_NAMES = ("provenance", "behavioral", "community", "historical")


def _scenario_signals(rng: random.Random) -> TrustSignals:
    return TrustSignals(**{name: rng.uniform(0.1, 0.9) for name in _SIGNAL_NAMES})


def _monotonicity(engine: TrustEngine, rng: random.Random) -> dict[str, Any]:
    """Trust must never fall when every new piece of evidence is non-negative."""
    violations = []
    out_of_bounds = []
    checked = 0

    for scenario in range(SCENARIOS):
        signals = _scenario_signals(rng)
        score = engine.compute_intrinsic(signals)
        for step in range(TIME_STEPS):
            evidence = {name: rng.uniform(0.0, 0.05) for name in _SIGNAL_NAMES}
            signals = engine.update_with_evidence(signals, evidence)
            new_score = engine.compute_intrinsic(signals)
            checked += 1
            if new_score < score - 1e-9:
                violations.append(
                    {"scenario": scenario, "step": step, "from": score, "to": new_score}
                )
            if not 0.0 <= new_score <= 1.0:
                out_of_bounds.append({"scenario": scenario, "step": step, "score": new_score})
            score = new_score

    return {
        "data_points": checked,
        "violations": len(violations),
        "violation_details": violations[:10],
        "boundedness_violations": len(out_of_bounds),
        "holds": not violations and not out_of_bounds,
    }


def _weight_sensitivity(rng: random.Random) -> dict[str, Any]:
    """How much does a skill's score move as the weight vector varies?"""
    scenarios = [_scenario_signals(rng) for _ in range(SCENARIOS)]
    weight_vectors = []
    for _ in range(WEIGHT_VECTORS):
        draws = [rng.random() for _ in _SIGNAL_NAMES]
        total = sum(draws) or 1.0
        weight_vectors.append(
            TrustWeights(**dict(zip(_SIGNAL_NAMES, (d / total for d in draws))))
        )

    per_skill_cv = []
    for signals in scenarios:
        scores = [
            TrustEngine(weights=weights).compute_intrinsic(signals)
            for weights in weight_vectors
        ]
        mean = statistics.fmean(scores)
        cv = statistics.pstdev(scores) / mean if mean else 0.0
        per_skill_cv.append(cv)

    return {
        "weight_vectors": WEIGHT_VECTORS,
        "skills": len(scenarios),
        "mean_cv": round(statistics.fmean(per_skill_cv), 4),
        "min_cv": round(min(per_skill_cv), 4),
        "max_cv": round(max(per_skill_cv), 4),
    }


def _decay_profile(decay_rate: float) -> dict[str, Any]:
    """Trajectory of an abandoned skill's score over the horizon."""
    engine = TrustEngine(decay_rate=decay_rate)
    signals = TrustSignals(provenance=0.85, behavioral=0.85, community=0.85, historical=0.85)
    initial = engine.compute_intrinsic(signals)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    score = engine.compute_score("abandoned-skill", "1.0.0", signals)
    trajectory = {}
    for day in (0, 30, 90, DECAY_HORIZON_DAYS):
        decayed = engine.apply_decay(score, start, start + timedelta(days=day))
        trajectory[f"day_{day}"] = round(decayed.effective_score, 4)

    import math

    return {
        "decay_rate_per_day": decay_rate,
        "half_life_days": round(math.log(2) / decay_rate, 1),
        "initial_score": round(initial, 4),
        "trajectory": trajectory,
    }


def run() -> dict[str, Any]:
    """Measure all three trust properties."""
    rng = random.Random(SEED)
    engine = TrustEngine()

    return {
        "experiment": "E5",
        "description": "Trust algebra: monotonicity, weight sensitivity, and decay",
        "seed": SEED,
        "monotonicity": _monotonicity(engine, rng),
        "weight_sensitivity": _weight_sensitivity(rng),
        "decay_shipped_default": _decay_profile(engine.decay_rate),
        "decay_alternate_rate": _decay_profile(ALTERNATE_DECAY_RATE),
        "note": (
            "The decay rate is configurable. The shipped default is what a user "
            "gets unless they tune it; the alternate rate is shown for contrast."
        ),
    }
