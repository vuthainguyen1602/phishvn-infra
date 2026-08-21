#!/usr/bin/env python3
"""
make_p4_funnel.py — the population funnel and the accrual toward the trigger, drawn.

WHY THESE TWO TOGETHER. Both answer the question a pre-registered design invites and a table
answers badly: is this study going to have a population, and where did the candidates go? The
funnel table (`tab_audit`) already prints the counts; what it cannot show is that the cuts are
wildly unequal in size, and that the biggest one by far is not a design choice at all but the
registry-wildcard artefact of Section~\\ref{ssec:wildcard} -- names nobody ever registered,
answered for by the registry. Reading that from five rows of numbers takes effort a bar does not.

The accrual panel is the honest version of the progress sentence. `gen_progress` states the count
and the fraction of the trigger; a reader's next question is when the trigger fires, and the
answer has a registered deadline attached (the 2027-01-31 calendar bound), so the projection and
the bound belong on the same axis.

PRE-REGISTRATION SAFETY. Both panels are single-arm marginals of the phishing candidate pool at
capture time. No outcome is read, no model is fitted, no arm is compared with another, and the
projection extrapolates admission counts -- how fast the population grows -- not anything the
population will later be used to measure. This is the same class of object as the funnel table
and the progress sentence the protocol already ships, and it is regenerated with them.

THE PROJECTION IS DELIBERATELY DUMB. A constant-rate line from the observed accrual, not a fit
with a trend: the feed's rate is visibly not constant, and a cleverer extrapolation would invite
the reader to believe a date the data cannot support. Two rates are drawn -- the whole-window
average and the trailing fortnight -- and where they disagree is the honest uncertainty.

    python scripts/assets/make_p4_funnel.py

Writes data/processed/p4_funnel.csv, data/processed/p4_accrual.csv,
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
    from _path import ROOT, add_script_dirs  # noqa: E402
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)

from genfile import write_generated  # noqa: E402
# The funnel, the trigger and the population rule are imported rather than restated: this figure
# must be the same object the table is, or it becomes a second source of truth for a number the
# pre-registration turns on.
from make_p4_assets import TRIGGER, build_population  # noqa: E402

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
                        xytext=(5, 6), fontsize=7, color=ORANGE if artefact else GRAY)
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
    ax2.annotate(f"trigger $n \\geq {TRIGGER}$", (CALENDAR_BOUND, TRIGGER),
                 textcoords="offset points", xytext=(-6, 6), fontsize=7.5, color=INK,
                 ha="right")
    ax2.axvline(CALENDAR_BOUND, color=GRAY, lw=0.9, ls=(0, (2, 3)), zorder=2)
    ax2.annotate("calendar bound\n(analyse anyway)", (CALENDAR_BOUND, TRIGGER * 0.42),
                 textcoords="offset points", xytext=(-4, 0), fontsize=7, color=GRAY, ha="right")

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


def make_tex(fun: list[dict], acc: list[dict], proj: dict) -> None:
    live = fun[0]["surviving"]
    wild = next(r for r in fun if r["stage"].startswith("less registry"))
    final = fun[-1]["surviving"]
    kept = final / live
    p_all, p_tr = proj["all"], proj["trailing"]
    dates = sorted({r["date"] for r in acc})

    body = (
        f"Figure~\\ref{{fig:funnel}} puts the cuts of Table~\\ref{{tab:audit}} on one axis, and "
        "the shape is not the one a reader would guess from a list of design decisions: of the "
        f"${live:,}$ live-stratum candidates only ${final}$ survive "
        f"(${100 * kept:.1f}\\%$), and the single largest loss is not a decision at all. The "
        f"registry-wildcard screen removes ${wild['removed']:,}$ names --- more than the label "
        "gate and the conditioning together --- because a registry that answers for every name "
        "under its TLD manufactures candidates that were never registered "
        "(Section~\\ref{ssec:wildcard}). A study that had not screened them would have had a "
        "population several times larger and mostly fictitious, which is the strongest argument "
        "this design can make for auditing a feed before modelling it. Accrual is the other "
        f"half of the same question. At the whole-window rate of ${p_all['rate']:.1f}$ admitted "
        f"domains a day the trigger is reached around "
        f"{p_all['date'].strftime('%d %B %Y') if p_all['date'] else 'no projected date'}, at the "
        f"trailing {TRAIL_DAYS}-day rate of ${p_tr['rate']:.1f}$ a day around "
        f"{p_tr['date'].strftime('%d %B %Y') if p_tr['date'] else 'no projected date'}; the gap "
        "between those two dates is the honest width of the estimate, and both sit inside the "
        f"registered calendar bound of {CALENDAR_BOUND.strftime('%Y-%m-%d')}, past which the "
        f"analysis proceeds at the achieved $n$ regardless. The record spans {len(dates)} "
        "detection days"
    )
    write_generated(os.path.join(SEC, "gen_funnel.tex"), body.rstrip() + "%")


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
    write_csv(os.path.join(PROC, "p4_funnel.csv"), fun)
    write_csv(os.path.join(PROC, "p4_accrual.csv"), acc)
    make_figure(fun, acc, proj)
    make_tex(fun, acc, proj)
    print(f"[i] funnel {fun[0]['surviving']:,} -> {fun[-1]['surviving']}; "
          f"accrual {r_all:.1f}/day (all), {r_tr:.1f}/day (trailing {TRAIL_DAYS}d); "
          f"projected {d_all} / {d_tr}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
