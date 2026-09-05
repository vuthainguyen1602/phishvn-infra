#!/usr/bin/env python3
"""
make_capture_funnel.py — the population funnel and the accrual toward the trigger, drawn.

WHY THESE TWO TOGETHER. Both answer the question a time-stamped pre-specified design invites and a table
answers badly: is this study going to have a population, and where did the candidates go?
`tab_audit` prints the counts but cannot show that the cuts are wildly unequal, and that the
biggest by far is not a design choice but the registry-wildcard artefact of
Section~\\ref{ssec:wildcard} — names nobody ever registered, answered for by the registry.

The accrual panel is the honest version of the progress sentence: `gen_progress` states the count
and the fraction of the trigger, and a reader's next question is when the trigger fires — an
answer with a registered deadline attached (the 2027-01-31 calendar bound), so projection and
bound belong on the same axis.

pre-specification SAFETY. Both panels are single-arm marginals of the phishing candidate pool at
capture time: no outcome read, no model fitted, no arm compared, and the projection extrapolates
admission counts — how fast the population grows — not anything it will later measure. Same class
of object as the funnel table and progress sentence the protocol already ships.

THE PROJECTION IS DELIBERATELY DUMB: a constant-rate line, not a fit with a trend. The feed's rate
is visibly not constant, and a cleverer extrapolation would invite belief in a date the data
cannot support. Two rates are drawn — whole-window average and trailing fortnight — and where they
disagree is the honest uncertainty.

    python scripts/make_capture_funnel.py

Writes data/processed/infra/funnel.csv, data/processed/infra/accrual.csv,
papers/P4_infra/figures/funnel_accrual.pdf and papers/P4_infra/sections/gen_funnel.tex.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)

from genfile import write_generated
# The funnel, the trigger and the population rule are imported rather than restated: this figure
# must be the same object the table is, or it becomes a second source of truth for a number the
# pre-specification turns on.
from make_infra_assets import TRIGGER, build_population

SEC = os.path.join(ROOT, "papers", "P4_infra", "sections")
FIG = os.path.join(ROOT, "papers", "P4_infra", "figures")
PROC = os.path.join(ROOT, "data", "processed")

# §5.7, amendment 2026-08-07: if the trigger has not fired by this date the analysis proceeds at
# the achieved n, under-powered. A projection drawn without it would imply an open-ended wait.
CALENDAR_BOUND = dt.date(2027, 1, 31)
TRAIL_DAYS = 14


def funnel_rows(funnel: dict) -> list[dict]:
    """The phishing arm's cuts, in the order the protocol applies them, as survivor counts."""
    live = funnel["phish_live"]
    after_hosted = live - funnel["phish_hosted"]
    after_wild = after_hosted - funnel["phish_wildcard"]
    stages = [
        ("live-stratum candidates", live, ""),
        ("less hosted subdomains", after_hosted, "no registration of their own"),
        ("less registry wildcards", after_wild, "names nobody registered"),
        ("label gate", funnel["phish_gate"], "positive evidence required"),
        ("resolving, serving TLS", funnel["phish_conditioned"], "the study population"),
    ]
    out, prev = [], None
    for name, n, why in stages:
        out.append({"stage": name, "surviving": n,
                    "removed": "" if prev is None else prev - n,
                    "note": why})
        prev = n
    return out


def accrual_rows(pop) -> list[dict]:
    """Cumulative admissions by detection date -- the quantity the trigger counts."""
    ph = pop[pop["arm"] == "phish"].copy()
    days = sorted(d.date() for d in ph["first_detected"])
    out, running = [], 0
    for day in sorted(set(days)):
        running += sum(1 for d in days if d == day)
        out.append({"date": day.isoformat(), "cumulative": running})
    return out


def project(acc: list[dict], days: int | None) -> tuple[float, dt.date | None]:
    """Constant-rate extrapolation to the trigger. `days` limits the window to the trailing
    fortnight; None uses the whole record. Returns (per-day rate, projected date)."""
    if len(acc) < 2:
        return (0.0, None)
    last = dt.date.fromisoformat(acc[-1]["date"])
    first = dt.date.fromisoformat(acc[0]["date"])
    start = max(first, last - dt.timedelta(days=days)) if days else first
    base = next((r for r in acc if dt.date.fromisoformat(r["date"]) >= start), acc[0])
    span = (last - dt.date.fromisoformat(base["date"])).days
    gained = acc[-1]["cumulative"] - base["cumulative"]
    if span <= 0 or gained <= 0:
        return (0.0, None)
    rate = gained / span
    need = TRIGGER - acc[-1]["cumulative"]
    return (rate, last + dt.timedelta(days=need / rate) if need > 0 else last)


def write_csv(path: str, rows: list[dict]) -> None:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
    write_generated(path, buf.getvalue())


def make_figure(fun: list[dict], acc: list[dict], proj: dict) -> str:
    from figstyle import apply, BLUE, ORANGE, GRAY, INK
    plt = apply()

    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(7.5, 3.2),
                                  gridspec_kw={"width_ratios": [1.15, 1]})

    # --- LEFT: the funnel. The wildcard cut is coloured apart because it is the only stage that
    # removes an artefact rather than applying a design decision, and it is the largest.
    ypos = list(range(len(fun)))[::-1]
    for y, r in zip(ypos, fun):
        artefact = r["stage"].startswith("less registry")
        ax.barh(y, r["surviving"], height=0.55, zorder=3,
                color=ORANGE if artefact else BLUE, alpha=0.95 if artefact else 0.55)
        ax.annotate(f"{r['surviving']:,}", (r["surviving"], y), textcoords="offset points",
                    xytext=(5, -3), fontsize=8, color=INK)
        if r["removed"] != "":
            ax.annotate(f"$-${r['removed']:,}", (r["surviving"], y), textcoords="offset points",
                        xytext=(5, 6), fontsize=7, color=ORANGE if artefact else INK)
    ax.set_yticks(ypos, [r["stage"] for r in fun], fontsize=8)
    ax.set_xlim(0, max(r["surviving"] for r in fun) * 1.3)
    ax.set_xlabel("registrable domains surviving the cut")
    ax.set_title("what the phishing arm loses, and to what", fontsize=8.5)
    ax.grid(axis="x", alpha=0.6)

    # --- RIGHT: accrual against the trigger and the registered calendar bound.
    xs = [dt.date.fromisoformat(r["date"]) for r in acc]
    ys = [r["cumulative"] for r in acc]
    ax2.plot(xs, ys, "-", color=BLUE, lw=1.6, zorder=3)
    ax2.axhline(TRIGGER, color=INK, lw=0.9, ls=(0, (4, 3)), zorder=2)
    # Anchored at the LEFT edge, not against the calendar bound: the whole-window projection's
    # label ends its second line at the same height, and the two ran together as "15 Oct trigger
    # n >= 500" (2026-09-02). Above the dashed line on the left the curve is still near zero, so
    # the space is free whatever the projections do.
    ax2.annotate(f"trigger $n \\geq {TRIGGER}$", (xs[0], TRIGGER),
                 textcoords="offset points", xytext=(2, 5), fontsize=7.5, color=INK,
                 ha="left")
    ax2.axvline(CALENDAR_BOUND, color=GRAY, lw=0.9, ls=(0, (2, 3)), zorder=2)
    ax2.annotate("calendar bound\n(analyse anyway)", (CALENDAR_BOUND, TRIGGER * 0.42),
                 textcoords="offset points", xytext=(-4, 0), fontsize=7, color=INK, ha="right")

    for key, colour, dash in (("all", BLUE, (0, (5, 2))), ("trailing", ORANGE, (0, (1, 2)))):
        p = proj[key]
        if not p["date"]:
            continue
        ax2.plot([xs[-1], p["date"]], [ys[-1], TRIGGER], ls=dash, color=colour, lw=1.1,
                 alpha=0.9, zorder=2)
        ax2.scatter([p["date"]], [TRIGGER], s=18, color=colour, zorder=4)
        label = "whole window" if key == "all" else f"trailing {TRAIL_DAYS} d"
        ax2.annotate(f"{label}: {p['rate']:.1f}/day\n{p['date'].strftime('%d %b')}",
                     (p["date"], TRIGGER), textcoords="offset points",
                     xytext=(4, 10 if key == "all" else -20), fontsize=7, color=colour,
                     ha="left")
    ax2.set_ylim(0, TRIGGER * 1.28)
    ax2.set_xlabel("detection date")
    ax2.set_ylabel("conditioned phishing domains")
    ax2.set_title("accrual toward the trigger", fontsize=8.5)
    ax2.grid(axis="y", alpha=0.6)
    for lab in ax2.get_xticklabels():
        lab.set_rotation(30)
        lab.set_ha("right")

    for a in (ax, ax2):
        a.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    os.makedirs(FIG, exist_ok=True)
    out = os.path.join(FIG, "funnel_accrual.pdf")
    fig.savefig(out)
    plt.close(fig)
    return out


def tex_int(n: int) -> str:
    """Digit grouping that survives math mode, where a bare comma sets as punctuation."""
    return f"{n:,}".replace(",", "{,}")


def make_tex(fun: list[dict], acc: list[dict], proj: dict) -> None:
    live = fun[0]["surviving"]
    wild = next(r for r in fun if r["stage"].startswith("less registry"))
    final = fun[-1]["surviving"]
    kept = final / live
    p_all, p_tr = proj["all"], proj["trailing"]
    dates = sorted({r["date"] for r in acc})
    cal_days = (dt.date.fromisoformat(dates[-1]) - dt.date.fromisoformat(dates[0])).days + 1

    body = (
        f"Figure~\\ref{{fig:funnel}} puts the cuts of Table~\\ref{{tab:audit}} on one axis, and "
        "the shape is not the one a reader would guess from a list of design decisions: of the "
        f"${tex_int(live)}$ live-stratum candidates only ${final}$ survive "
        f"(${100 * kept:.1f}\\%$), and the single largest loss is not a decision at all. The "
        f"registry-wildcard screen removes ${tex_int(wild['removed'])}$ names --- more than the label "
        "gate and the conditioning together --- because a registry that answers for every name "
        "under its TLD manufactures candidates that were never registered "
        "(Section~\\ref{ssec:wildcard}). A study that had not screened them would have had a "
        "population several times larger and mostly fictitious, which is the strongest argument "
        "this design can make for auditing a feed before modelling it. Accrual is the other "
        f"half of the same question. At the whole-window rate of ${p_all['rate']:.1f}$ admitted "
        f"domains a day the trigger is reached around "
        f"{p_all['date'].strftime('%d %B %Y') if p_all['date'] else 'no projected date'}, at the "
        f"trailing {TRAIL_DAYS}-day rate of ${p_tr['rate']:.1f}$ a day around "
        f"{p_tr['date'].strftime('%d %B %Y') if p_tr['date'] else 'no projected date'} (both "
        "rates are gains over elapsed days from the first detection day, so the whole-window "
        f"rate excludes that day's ${acc[0]['cumulative']}$ first-day admissions; counting them, "
        f"${final}$ over the {cal_days} calendar days would read ${final / cal_days:.1f}$/day); the gap "
        "between those two dates is the honest width of the estimate, and both sit inside the "
        f"registered calendar bound of {CALENDAR_BOUND.strftime('%Y-%m-%d')}, past which the "
        f"analysis proceeds at the achieved $n$ regardless. The record spans {len(dates)} "
        "detection days"
    )
    write_generated(os.path.join(SEC, "gen_funnel.tex"), body.rstrip() + "%")

    # The prose quotes the accrual rate and the admitted count in five places outside the dated
    # deviation entries. They were typed by hand and went stale the moment the capture moved
    # (7.2 -> 7.1, 181 -> 186 on 2026-08-22), so they read from here now. The dated entries keep
    # their literals: what they record is what was true on their date.
    _vn_ph = _vn_phish_count()
    macros = "\n".join([
        f"\\newcommand{{\\AccrualRate}}{{{p_all['rate']:.1f}}}",
        f"\\newcommand{{\\AccrualTrailing}}{{{p_tr['rate']:.1f}}}",
        f"\\newcommand{{\\AdmittedN}}{{{final}}}",
        f"\\newcommand{{\\BenignVnN}}{{{_benign_vn_count()}}}",
        # The `.vn` phishing count went stale exactly the way the accrual rate had: 33 was typed
        # into the perishability paragraph, the capture moved to 35, and nothing complained
        # because a bare literal is bound to nothing. Its share and its per-day rate are derived
        # here too, so the prose never has to round "one in six" by hand again.
        f"\\newcommand{{\\VnPhishN}}{{{_vn_ph}}}",
        f"\\newcommand{{\\VnPhishShare}}{{{round(100 * _vn_ph / final) if final else 0}}}",
        f"\\newcommand{{\\VnPhishRate}}{{{_vn_ph / cal_days:.1f}}}",
        # Wildcard share of the screened population (candidates less hosted subdomains), the
        # figure the abstract quotes and dates to the snapshot.
        f"\\newcommand{{\\WildcardShare}}{{{round(100 * fun[2]['removed'] / fun[1]['surviving']) if fun[1]['surviving'] else 0}}}",
    ])
    write_generated(os.path.join(SEC, "gen_funnel_macros.tex"), macros)


def _vn_phish_count() -> int:
    """`.vn` names in the admitted phishing arm. Hand-typed as 33 until 2026-08-24, when the
    sync moved it to 35 and the sentence quoting it stayed put."""
    import pandas as _pd
    path = os.path.join(PROC, "infra", "infra_dataset.csv")
    if not os.path.exists(path):
        return 0
    d = _pd.read_csv(path, low_memory=False)
    ph = d[d["arm"] == "phish"]
    return int(ph["registered_domain"].astype(str).str.endswith(".vn").sum())


def _benign_vn_count() -> int:
    """`.vn` names in the matched benign arm. It was zero for three weeks, until the 2026-08-21
    supplement landed, so the discussion paragraph about empty `.vn` cells reads it from here
    rather than asserting a number that has since stopped being true."""
    import pandas as _pd
    path = os.path.join(PROC, "infra", "infra_dataset.csv")
    if not os.path.exists(path):
        return 0
    d = _pd.read_csv(path, low_memory=False)
    be = d[d["arm"] == "benign"]
    return int(be["registered_domain"].astype(str).str.endswith(".vn").sum())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    pop, funnel = build_population()
    fun = funnel_rows(funnel)
    acc = accrual_rows(pop)
    r_all, d_all = project(acc, None)
    r_tr, d_tr = project(acc, TRAIL_DAYS)
    proj = {"all": {"rate": r_all, "date": d_all}, "trailing": {"rate": r_tr, "date": d_tr}}

    os.makedirs(PROC, exist_ok=True)
    write_csv(os.path.join(PROC, "infra", "funnel.csv"), fun)
    write_csv(os.path.join(PROC, "infra", "accrual.csv"), acc)
    make_figure(fun, acc, proj)
    make_tex(fun, acc, proj)
    print(f"[i] funnel {fun[0]['surviving']:,} -> {fun[-1]['surviving']}; "
          f"accrual {r_all:.1f}/day (all), {r_tr:.1f}/day (trailing {TRAIL_DAYS}d); "
          f"projected {d_all} / {d_tr}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
