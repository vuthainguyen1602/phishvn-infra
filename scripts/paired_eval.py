#!/usr/bin/env python3
"""paired_eval.py — Corrected resampled t-test (Nadeau & Bengio 2003).

Shared by experiments comparing configurations across repeated random train/test splits.
Corrects standard error under repeated train/test splits where test folds overlap:
    se_corrected = sqrt((1/K + n2/n1) * Var(d))
"""
from __future__ import annotations

import math

import numpy as np

# The split ratio every content experiment uses (train_content_fusion.evaluate: test_size=0.30).
DEFAULT_TEST_FRAC = 0.30


def corrected_paired_t(d, test_frac: float = DEFAULT_TEST_FRAC) -> dict:
    """Corrected resampled t-test on per-split differences `d` (config A minus config B).

    Returns mean, corrected p-value, se, naive p-value, inflation factor, and win count.
    """
    d = np.asarray(d, dtype=float)
    k = len(d)
    mean = float(np.mean(d))
    var = float(np.var(d, ddof=1)) if k > 1 else 0.0
    out = {"k": k, "mean": mean, "wins": int(np.sum(d > 0)),
           "p": 1.0, "p_naive": 1.0, "se": 0.0, "inflation": float("nan")}
    if k < 2 or var <= 0:
        return out
    try:
        from scipy import stats
    except ImportError:  # keep the pipeline runnable without scipy; verdicts fall back to "no evidence"
        return out
    factor = 1.0 / k + test_frac / (1.0 - test_frac)
    se = math.sqrt(factor * var)
    se_naive = math.sqrt(var / k)
    t = mean / se
    out.update(p=float(2 * stats.t.sf(abs(t), k - 1)),
               p_naive=float(2 * stats.t.sf(abs(mean / se_naive), k - 1)),
               se=se, t=float(t), inflation=se / se_naive)
    return out


class QValue(float):
    """Multiplicity-adjusted p-value type (enforces 'q' label in fmt_p to prevent misattribution)."""

    __slots__ = ()


def bh_adjust(pvals, alpha: float = 0.05):
    """Benjamini-Hochberg FDR step-up: returns (adjusted_p, reject) for a family of tests."""
    idx = sorted(range(len(pvals)), key=lambda i: pvals[i])
    m = len(pvals)
    adj = [1.0] * m
    running = 1.0
    for rank in range(m, 0, -1):          # walk up from largest p-value
        i = idx[rank - 1]
        running = min(running, pvals[i] * m / rank)
        adj[i] = QValue(min(1.0, running))
    return adj, [a <= alpha for a in adj]


def wilson(k: float, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for binomial proportions (exact boundaries for extreme rates/small n)."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def fmt_p(p: float, symbol: str = "p") -> str:
    """Format p-value for LaTeX output, enforcing 'q' label for adjusted QValue instances."""
    if isinstance(p, QValue) and symbol != "q":
        raise ValueError(
            f"refusing to print a Benjamini--Hochberg adjusted value ({float(p):.4g}) under "
            f"the label '{symbol}'. Pass symbol='q'. See QValue for why this is a crash and "
            f"not a convention.")
    if p != p:
        return f"{symbol}=\\text{{n/a}}"
    if p < 0.001:
        return f"{symbol}<0.001"
    return f"{symbol}={p:.3f}" if p < 0.1 else f"{symbol}={p:.2f}"
