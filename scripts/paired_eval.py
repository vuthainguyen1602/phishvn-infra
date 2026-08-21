#!/usr/bin/env python3
"""
paired_eval.py — the corrected resampled t-test (Nadeau & Bengio 2003), shared by every
experiment in this repo that compares configurations across repeated random train/test splits.

WHY THIS EXISTS. Our content experiments score each configuration on K stratified 70/30 splits of
the SAME small page set and compare the per-split differences. Pairing is correct — it cancels
split difficulty — but the K differences are NOT independent: the test folds overlap heavily
(any two 30% test sets drawn from 716 rows share ~30% of their rows in expectation), so the
ordinary paired t-test underestimates Var(mean difference) and inflates t. Dietterich (1998)
identified the failure; Nadeau & Bengio (2003) give the fix used here.

THE CORRECTION. For K splits with a train/test ratio n1/n2, the naive estimator uses Var/K; the
corrected one replaces the 1/K factor:

    se_naive     = sqrt( (1/K)              * Var(d) )
    se_corrected = sqrt( (1/K + n2/n1)      * Var(d) )

At our K=20 and a 70/30 split that is sqrt((0.05 + 0.4286)/0.05) ~ 3.1x wider — i.e. every t we
previously reported was ~3.1x too large. Differences that sat at p ~ 0.001-0.01 under the naive
test are NOT significant under the corrected one; only genuinely large, consistent effects
survive. This is exactly the practice Arp et al.'s "Dos and Don'ts" warns about, and which this
project cites — so the naive form was an internal contradiction, not merely a conservative choice.

WHEN *NOT* TO USE THIS. The correction is for repeated random subsampling. It does not apply to
a bootstrap over a single fixed test set (make_p1_assets.paired_boot_f1), where the resampling
is of predictions on one held-out set rather than of the split itself.
"""
from __future__ import annotations

import math

import numpy as np

# The split ratio every content experiment uses (train_content_fusion.evaluate: test_size=0.30).
DEFAULT_TEST_FRAC = 0.30


def corrected_paired_t(d, test_frac: float = DEFAULT_TEST_FRAC) -> dict:
    """Corrected resampled t-test on per-split differences `d` (config A minus config B).

    Returns mean, the corrected p-value and standard error, the naive p-value (for disclosure of
    how much the correction moved the verdict), the inflation factor, and the win count.
    A zero-variance difference is treated as no evidence (p=1) rather than infinite confidence.
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
    """A multiplicity-adjusted p-value, carrying that fact through the code that prints it.

    WHY A TYPE AND NOT A CONVENTION. Benjamini--Hochberg was applied to a multi-channel encoder sweep on
    2026-08-08. The table became q-values; every cell still printed the literal "p=", and the
    results paragraph beside it went on quoting the pre-correction run for weeks. One of those
    stale figures (XLM-R PR-AUC: raw p=0.031 against q=0.052) was the difference between an
    effect the paper claimed and one that misses its own bar. Every number involved was true of
    SOME run, so no value check could see it, and nobody rereading the paragraph noticed that a
    "p" beside a corrected table was the wrong letter.

    A convention that lives in the author's head fails silently. A type does not: fmt_p refuses
    to render one of these under a "p" label, so the mislabelling becomes a crash at asset-
    generation time, in whichever paper introduces it, before anything reaches a manuscript.
    Being a float subclass, it is otherwise inert — arithmetic, comparison, CSV writing and
    f-string formatting all behave exactly as before.
    """

    __slots__ = ()


def bh_adjust(pvals, alpha: float = 0.05):
    """Benjamini-Hochberg step-up: returns (adjusted_p, reject) for a family of tests.

    WHY A FAMILY CORRECTION IS OWED HERE. The encoder sweep runs the same comparison across five
    content encoders and reports how many of them separate. Asking "does any encoder show a gain?"
    over five tests and then naming the winners is the textbook multiplicity setting: at alpha=0.05
    the chance of at least one false positive across five independent nulls is already 23%. Arp
    et al.'s "Dos and Don'ts", which this project cites, lists exactly this.

    BH rather than Bonferroni because the question is "which of these effects are real", not "is
    there any effect at all" — controlling the false-discovery rate keeps power that
    family-wise-error control spends, and the tests here are positively dependent (same subset,
    same splits), where BH is valid.

    Adjusted p-values are enforced monotone non-decreasing in rank, so a reader can compare them
    directly against alpha without re-deriving the step-up.
    """
    idx = sorted(range(len(pvals)), key=lambda i: pvals[i])
    m = len(pvals)
    adj = [1.0] * m
    running = 1.0
    for rank in range(m, 0, -1):          # walk up from the largest p-value
        i = idx[rank - 1]
        running = min(running, pvals[i] * m / rank)
        adj[i] = QValue(min(1.0, running))
    return adj, [a <= alpha for a in adj]


def wilson(k: float, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Lives here rather than in each caller because three separate analyses now quote one: the .vn
    false-negative rate, the per-tier label-noise rates and the drift-detector rates. Wilson rather than
    normal-approximation because every one of those has a small n and rates near 0 or 1, where
    the normal interval leaves the [0,1] range and understates uncertainty.
    """
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def fmt_p(p: float, symbol: str = "p") -> str:
    """A p-value as the paper should print it — below 3-decimal resolution, say so.

    `symbol` exists because a table whose caption says "these are Benjamini--Hochberg q-values"
    while every cell reads "p=" is an invitation to quote the cell as a raw p somewhere else,
    and that invitation was accepted: the results paragraph beside one carried pre-correction p-values for
    weeks after the correction landed, including one that turned a missed bar into a claimed
    effect. Corrected values must be labelled q at the point they are printed."""
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
