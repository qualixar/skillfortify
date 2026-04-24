"""Wilson score confidence interval computation (LLD-07 S4.1).

Stdlib-only. No external dependencies.

Wilson (1927) CI for binomial proportions. Preferred over Wald because it
never degenerates to zero-width at k=0 or k=n.

Formula (from PHASE-08 Appendix A):
    centre = (k + z^2/2) / (n + z^2)
    margin = z * sqrt(k*(n-k)/n + z^2/4) / (n + z^2)
    lower  = max(0.0, centre - margin)
    upper  = min(1.0, centre + margin)
"""

from __future__ import annotations

import math

__all__ = ["wilson_ci", "wilson_ci_family"]

# Default z for 95% two-sided CI.
_Z_95: float = 1.96


def wilson_ci(
    successes: int,
    total: int,
    z: float = _Z_95,
) -> tuple[float, float]:
    """Compute Wilson score confidence interval.

    Parameters
    ----------
    successes:
        Number of successes (k).
    total:
        Number of trials (n).
    z:
        z-value for desired confidence level. Default 1.96 (95% two-sided).

    Returns
    -------
    (lower, upper) bounds. Returns (0.0, 0.0) when total == 0.
    """
    if total == 0:
        return (0.0, 0.0)

    p_hat = successes / total
    z_sq = z ** 2
    denom = 1 + z_sq / total
    centre = (p_hat + z_sq / (2 * total)) / denom
    margin = (z / denom) * math.sqrt(
        p_hat * (1 - p_hat) / total + z_sq / (4 * total ** 2)
    )
    lower = max(0.0, centre - margin)
    upper = min(1.0, centre + margin)
    return (lower, upper)


def wilson_ci_family(
    successes: int,
    total: int,
    family_confidence: float = 0.95,
    family_size: int = 17,
) -> tuple[float, float]:
    """Bonferroni-adjusted Wilson CI for simultaneous inference.

    For k=17 simultaneous CIs at family-wise 95%, per-CI alpha is
    0.05/17, giving z ~= 2.9690.

    Parameters
    ----------
    successes:
        Number of successes.
    total:
        Number of trials.
    family_confidence:
        Family-wise confidence level (default 0.95).
    family_size:
        Number of simultaneous CIs (default 17 per LLD-07 S4.6).

    Returns
    -------
    (lower, upper) Bonferroni-adjusted Wilson CI bounds.
    """
    alpha = 1 - family_confidence
    per_ci_alpha = alpha / family_size
    z_family = _inverse_normal_cdf(1 - per_ci_alpha / 2)
    return wilson_ci(successes, total, z=z_family)


# ---------------------------------------------------------------------------
# Inverse normal CDF (Peter Acklam's rational approximation)
# ---------------------------------------------------------------------------
# Max absolute error ~1.15e-9 over the entire range.
# Coefficients reproduced from Acklam's original publication.

_A = (
    -3.969683028665376e01,
    2.209460984245205e02,
    -2.759285104469687e02,
    1.383577518672690e02,
    -3.066479806614716e01,
    2.506628277459239e00,
)

_B = (
    -5.447609879822406e01,
    1.615858368580409e02,
    -1.556989798598866e02,
    6.680131188771972e01,
    -1.328068155288572e01,
)

_C = (
    -7.784894002430293e-03,
    -3.223964580411365e-01,
    -2.400758277161838e00,
    -2.549732539343734e00,
    4.374664141464968e00,
    2.938163982698783e00,
)

_D = (
    7.784695709041462e-03,
    3.224671290700398e-01,
    2.445134137142996e00,
    3.754408661907416e00,
)

_P_LOW = 0.02425
_P_HIGH = 1 - _P_LOW


def _inverse_normal_cdf(p: float) -> float:
    """Rational approximation of the inverse standard-normal CDF.

    Acklam's algorithm. Returns z such that Phi(z) = p.
    """
    if p <= 0.0:
        return float("-inf")
    if p >= 1.0:
        return float("inf")

    if p < _P_LOW:
        # Rational approximation for lower region.
        q = math.sqrt(-2 * math.log(p))
        return (
            ((((_C[0] * q + _C[1]) * q + _C[2]) * q + _C[3]) * q + _C[4]) * q
            + _C[5]
        ) / ((((_D[0] * q + _D[1]) * q + _D[2]) * q + _D[3]) * q + 1)

    if p <= _P_HIGH:
        # Rational approximation for central region.
        q = p - 0.5
        r = q * q
        return (
            ((((_A[0] * r + _A[1]) * r + _A[2]) * r + _A[3]) * r + _A[4]) * r
            + _A[5]
        ) * q / (
            ((((_B[0] * r + _B[1]) * r + _B[2]) * r + _B[3]) * r + _B[4]) * r
            + 1
        )

    # Rational approximation for upper region.
    q = math.sqrt(-2 * math.log(1 - p))
    return -(
        ((((_C[0] * q + _C[1]) * q + _C[2]) * q + _C[3]) * q + _C[4]) * q
        + _C[5]
    ) / ((((_D[0] * q + _D[1]) * q + _D[2]) * q + _D[3]) * q + 1)
