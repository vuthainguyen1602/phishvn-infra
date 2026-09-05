#!/usr/bin/env python3
"""
make_capture_lag.py — how long after a domain was first detected did we look at it?

WHY THIS EXISTS. Every infrastructure feature in this corpus is a measurement taken at
`captured_at`, and a reader is entitled to ask what that measurement is evidence OF. DNS, TLS and
WHOIS are perishable: a phishing domain observed four days after a feed listed it may already have
rotated its A record, renewed its certificate or been sinkholed, and the row then describes the
takedown rather than the attack. The corpus claims its features are contemporaneous with detection.
This file is where that claim is measured instead of asserted.

TWO UNITS, AND THEY ANSWER DIFFERENT QUESTIONS. Per capture is the operational one: the collector
re-visits domains on purpose (attempt 2 and 3 are the perishability arm), so that distribution
mixes the first look with deliberate later ones and its median is not a latency. Per domain, first
capture, is the one the claim is about, and it is the headline here.

TWO STRATA, AND POOLING THEM IS THE TRAP. The collector went live on 2026-07-30 and its first pass
swept a backlog of names whose `first_detected` predates it by weeks; their lag measures how old
the seed lists were, not how fast the collector is. `make_infra_assets.build_population` already
restricts the phishing arm to the live stratum for exactly this reason (§5, live-stratum-only), and
this file reports the two strata apart. Pooled, the phishing median is 13.6 h and reads as a
weakness; split, the live stratum is 1.2 h and the backlog is a seeding artefact that no longer
accrues.

WHAT THE NUMBERS TURNED OUT TO MEAN. Two things, and the second is the one a reader needs.
First, the live-stratum median is half the collection cycle: the watcher runs about every two
hours and the phishing median is 1.2 h with an interquartile range of 1.23--1.28 h, which is what
uniformly-arriving detections against a 2-hourly poll look like. The tightness is the cadence, not
a suspiciously good result. Second, the arms differ by a factor of sixty and it is NOT a latency
difference: every source the collector timestamps itself lands inside one cycle, including the
benign one (tinnhiem_benign, 1.5 h), while the CT-sourced benign sits at 73 h because for those
rows `first_detected` is the certificate's log timestamp rather than the moment we learned of the
name. The two arms are therefore not comparable on this axis by construction, and the per-source
table exists so that a reader can see which quantity each row is measuring.

TIMEZONES. Not re-derived here: `make_infra_assets.localise_timestamps` is imported, because CT rows
stamp `first_detected` in naive UTC while the collector stamps naive local, and subtracting them
raw adds a spurious seven hours to every CT row -- the same error that once inflated certificate
age (see its LOCAL_TZ note).

    python scripts/make_capture_lag.py           # csv + tables + figure
    python scripts/make_capture_lag.py --no-fig  # skip the figure
"""
from __future__ import annotations

import argparse
import io
import os
import sys

import numpy as np
import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)
from genfile import write_generated
from make_infra_assets import INFRA, WATCHER_START, localise_timestamps

OUT_CSV = os.path.join(ROOT, "data", "processed", "infra", "capture_lag.csv")
# One destination only. The Scientific Data port \input's these from here rather than holding a
# copy: check_paper_claims fails a port that duplicates a generated asset, so that the two
# manuscripts cannot drift into printing different numbers from the same name.
SEC_DIB = os.path.join(ROOT, "papers", "P4b_infra_data", "sections")
FIG_DIRS = [os.path.join(ROOT, "papers", p, "figures")
            for p in ("P4b_infra_data", "P4b_infra_data_scientific")]

# Thresholds a reader can act on, rather than only distribution shape: within an hour is
# "the same visit", within a day is "before the feed's own refresh".
BUCKETS = [("<= 1 h", 1.0), ("<= 6 h", 6.0), ("<= 24 h", 24.0), ("<= 72 h", 72.0)]


def load() -> tuple[pd.DataFrame, int]:
    """Raw captures with timestamps in one zone. Returns the frame and the number of rows whose
    timestamps would not parse -- reported rather than silently dropped."""
    df = pd.read_csv(INFRA, low_memory=False)
    before = len(df)
    df = localise_timestamps(df)
    df = df[df["captured_at"].notna() & df["first_detected"].notna()].copy()
    df["lag_h"] = (df["captured_at"] - df["first_detected"]).dt.total_seconds() / 3600.0
    return df, before - len(df)


def strata(df: pd.DataFrame) -> pd.DataFrame:
    """Label each row live/backlog by whether the feed saw it after the collector started."""
    df = df.copy()
    df["stratum"] = np.where(df["first_detected"] >= WATCHER_START, "live", "backlog")
    return df


def first_capture(df: pd.DataFrame) -> pd.DataFrame:
    """One row per registrable domain: its earliest capture. `registered_domain` is blank for a
    handful of rows, so fall back to the hostname rather than dropping them into one empty key."""
    key = df["registered_domain"].fillna("").str.strip()
    df = df.assign(_key=np.where(key != "", key, df["domain"].astype(str)))
    return df.sort_values("captured_at").drop_duplicates("_key", keep="first")


def describe(v: pd.Series) -> dict:
    v = v.dropna()
    if v.empty:
        return {}
    row = {"n": int(v.size), "median_h": v.median(), "q1_h": v.quantile(.25),
           "q3_h": v.quantile(.75), "p90_h": v.quantile(.90), "p95_h": v.quantile(.95),
           "max_h": v.max(), "negative": int((v < 0).sum())}
    for name, hours in BUCKETS:
        row[f"pct_{name.replace(' ', '').replace('<=', 'le')}"] = 100.0 * (v <= hours).mean()
    return row


def by_source(df: pd.DataFrame) -> pd.DataFrame:
    """Per-source lag on the live stratum. This is the table that separates a slow collector from
    a `first_detected` that means something different -- see the module docstring."""
    rows = []
    live = df[df["stratum"] == "live"]
    for (arm, src), sub in live.groupby(["label", "source"]):
        d = describe(sub["lag_h"])
        if d:
            rows.append({"unit": "first", "arm": arm, "stratum": "live", "source": src, **d})
    return pd.DataFrame(rows)


def table(df: pd.DataFrame, unit: str) -> pd.DataFrame:
    rows = []
    for arm in ("phish", "benign"):
        for stratum in ("live", "backlog"):
            sub = df[(df["label"] == arm) & (df["stratum"] == stratum)]
            d = describe(sub["lag_h"])
            if d:
                rows.append({"unit": unit, "arm": arm, "stratum": stratum, **d})
        d = describe(df[df["label"] == arm]["lag_h"])
        if d:
            rows.append({"unit": unit, "arm": arm, "stratum": "pooled", **d})
    return pd.DataFrame(rows)


def _fmt(x: float) -> str:
    """Hours below a day, days above it. A median of 0.03 h says nothing a reader can hold."""
    if x < 1:
        return f"{x * 60:.0f} min"
    return f"{x:.1f} h" if x < 48 else f"{x / 24:.1f} d"


def write_table(tab: pd.DataFrame, dropped: int) -> None:
    live = tab[(tab["unit"] == "first") & (tab["arm"] == "phish")
               & (tab["stratum"] == "live")].iloc[0]
    out = io.StringIO()
    out.write("\\begin{table}[h]\\centering\\footnotesize\n"
              "\\caption{Capture lag, \\texttt{captured\\_at} minus \\texttt{first\\_detected}, "
              "for the first capture of each registrable domain. The live stratum is the one the "
              "corpus conditions on; the backlog is the seed sweep of the collector's first pass, "
              "whose lag measures the age of the seed lists and not the collector.}\n"
              "\\label{tab:capturelag}\n"
              "\\begin{tabular}{llrrrrrr}\\toprule\n"
              "Arm & Stratum & $n$ & Median & IQR & P90 & P95 & $\\le$24 h \\\\ \\midrule\n")
    for _, r in tab[tab["unit"] == "first"].iterrows():
        if r["stratum"] == "pooled":
            continue
        out.write(f"{r['arm']} & {r['stratum']} & {int(r['n']):,} & {_fmt(r['median_h'])} & "
                  f"{_fmt(r['q1_h'])}--{_fmt(r['q3_h'])} & {_fmt(r['p90_h'])} & "
                  f"{_fmt(r['p95_h'])} & {r['pct_le24h']:.0f}\\% \\\\\n")
    out.write("\\bottomrule\\end{tabular}\\end{table}\n")
    write_generated(os.path.join(SEC_DIB, "tab_capture_lag.tex"), out.getvalue())

    body = (f"\\newcommand{{\\LagLiveN}}{{{int(live['n']):,}}}\n"
            f"\\newcommand{{\\LagLiveMedian}}{{{_fmt(live['median_h'])}}}\n"
            f"\\newcommand{{\\LagLivePninety}}{{{_fmt(live['p90_h'])}}}\n"
            f"\\newcommand{{\\LagLiveDay}}{{{live['pct_le24h']:.0f}\\%}}\n"
            f"\\newcommand{{\\LagUnparsed}}{{{dropped}}}\n")
    write_generated(os.path.join(SEC_DIB, "gen_capture_lag.tex"), body)


def write_figure(dom: pd.DataFrame) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from figstyle import apply, BLUE, ORANGE, GRAY
    apply()
    fig, ax = plt.subplots(figsize=(5.4, 3.2))
    series = [("phishing, live", "phish", "live", BLUE),
              ("benign, live", "benign", "live", ORANGE),
              ("phishing, backlog", "phish", "backlog", GRAY)]
    for lab, arm, stratum, colour in series:
        v = dom[(dom["label"] == arm) & (dom["stratum"] == stratum)]["lag_h"].dropna()
        v = v[v >= 0].sort_values()
        if v.empty:
            continue
        y = np.arange(1, len(v) + 1) / len(v)
        ax.step(np.maximum(v.to_numpy(), 1 / 60), y, where="post", color=colour,
                label=f"{lab} (n={len(v):,})")
    ax.set_xscale("log")
    ax.set_xlabel("capture lag (hours, log scale)")
    ax.set_ylabel("cumulative share of domains")
    ax.axvline(24, color=GRAY, ls=":", lw=.8)
    ax.text(24, .03, " 24 h", fontsize=7, color=GRAY)
    ax.set_ylim(0, 1)
    # Outside the axes on purpose: a CDF with a log x-axis leaves no empty corner here, and the
    # axis guard counts how many marks any in-axes placement would hide.
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.28), ncol=3, frameon=False,
              fontsize=7, handlelength=1.6, columnspacing=1.2)
    fig.tight_layout()
    for d in FIG_DIRS:
        if os.path.isdir(os.path.dirname(d)):
            os.makedirs(d, exist_ok=True)
            fig.savefig(os.path.join(d, "capture_lag_cdf.pdf"))
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-fig", action="store_true")
    args = ap.parse_args()

    df, dropped = load()
    df = strata(df)
    dom = first_capture(df)
    tab = pd.concat([table(dom, "first"), table(df, "capture"), by_source(dom)],
                    ignore_index=True)
    write_generated(OUT_CSV, tab.to_csv(index=False))
    write_table(tab, dropped)
    if not args.no_fig:
        write_figure(dom)

    live = tab[(tab["unit"] == "first") & (tab["arm"] == "phish")
               & (tab["stratum"] == "live")].iloc[0]
    print(f"[+] {OUT_CSV}")
    print(f"    unparsed timestamp rows: {dropped}")
    print(f"    phishing, live stratum, first capture: n={int(live['n']):,} "
          f"median={_fmt(live['median_h'])} P90={_fmt(live['p90_h'])} "
          f"within 24 h={live['pct_le24h']:.0f}%")


if __name__ == "__main__":
    main()
