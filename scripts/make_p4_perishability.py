#!/usr/bin/env python3
"""
make_p4_perishability.py — the capture audit of §3, drawn rather than recited.

DESCRIPTIVE ONLY, NOT THE CASCADE'S PERISHABILITY FACTOR. pi(tau) is the time-stamped pre-specified estimand
of §5.5 — Kaplan-Meier on the live stratum, computed at analysis time and not before. What is
plotted here is observed resolvability at observed capture lag, one arm's marginal, revealing no
outcome. Nothing is fitted; no arm is compared with another.

THE PHISHING ARM ONLY. §3's numbers (median 1.2 h, 94.8% resolving on the live stratum) were
measured when the capture held phishing alone. `ct_benign` started the same day as the watcher,
so it lands almost entirely in the live stratum and the pooled figures have since drifted
(32.7 h, 87.6%) by ARM MIX, not by anything about phishing infrastructure.

WHAT THE SHAPE IS NOT. Resolvability holds near unity then collapses an order of magnitude one
bin later (0.97 at 16-32 h vs 0.09 at 32-64 h). Both bins sit inside the backlog, so the stratum
boundary is not doing that work — but a backlog worked in date order ties capture lag to
detection date, so it is not a clean hazard either. The plot establishes only that a smooth
hazard is not the sole candidate shape; the registered KM estimate settles it.

THE RISING TAIL past 256 h is not infrastructure surviving: those answers concentrate on parking
and aftermarket address space and sinkholes, so `has an A record` counts recycled and nulled
names as alive. Drawn rather than screened away, because it bounds how far this indicator reads
as survival at all — a caveat pi(tau) inherits.

THE RETRY, RE-MEASURED. §3 reports 0 revivals of 2,190 re-attempted domains. On the accumulated
capture the pooled count is no longer zero, and the right panel says so; split by arm it is still
~zero where the claim matters (revivals are benign-arm parking/aftermarket plus transient
resolver failures on .gov.vn — the artefact class of §4, not evidence returning).

REGISTRY WILDCARDS ARE LEFT OUT (2026-08-22), by the same predicate and probe file as P4b and
audit_p4_labels.py (verdict `registry_wildcard`): a wildcard name resolves whether or not anyone
registered it (98.6% of 2,147 live hosts before the screen, 95.4% of 668 after).

    python scripts/make_p4_perishability.py

Writes data/processed/p4/p4_perishability.csv, data/processed/p4/p4_retry.csv,
papers/P4_infra/figures/perishability.pdf, papers/P4_infra/sections/gen_perishability.tex and
papers/P4_infra/sections/gen_perishability_macros.tex (the retry/strata counts as macros).
"""
from __future__ import annotations

import argparse
import collections
import csv
import io
import ipaddress
import math
import os
import statistics
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)

from genfile import write_generated
# The stratification rule, the timestamp parser and the per-domain reduction all come from the
# audit script the paper cites, so this figure cannot drift from §3's numbers by having quietly
# redefined "live" or "best record".
from audit_infra_capture import (
    INFRA, WATCHER_START, best_per_domain, ts,
)
# Same registry-wildcard predicate and persisted probe file as the label audit and P4b: a name
# that resolves only to the registry's parking answer is not a registration.
from audit_p4_labels import is_registry_wildcard, registrable, write_wildcard_probe

SEC = os.path.join(ROOT, "papers", "P4_infra", "sections")
FIG = os.path.join(ROOT, "papers", "P4_infra", "figures")
PROC = os.path.join(ROOT, "data", "processed")

# Lag bins in hours. Log-spaced by construction: capture lag spans four orders of magnitude
# (minutes for the live stratum, weeks for the backlog), so equal-width bins would collapse the
# whole live stratum into one column. The last edge is a floor, not a cap.
BIN_EDGES = [0.0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512]
MIN_BIN = 25          # bins thinner than this are written to the CSV but not drawn
TAIL_H = 256.0        # where the backfill tail turns, and the window the caption quantifies


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval. Thin bins are the point of the plot, so a normal approximation
    would draw intervals leaving [0, 1] exactly where the counts are weakest."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    # Clamped: at k=0 the lower bound lands a few 1e-17 below zero, which is harmless as a
    # number and not harmless as an error bar drawn below an axis that starts at zero.
    return (max(0.0, (c - r) / d), min(1.0, (c + r) / d))


def a_records(r: dict) -> list[str]:
    return [x.strip() for x in (r.get("a_records") or "").split(";") if x.strip()]


def resolves(r: dict) -> bool:
    return bool(a_records(r))


def routable(r: dict) -> bool:
    """At least one answer that is a real destination. A name answering 127.0.0.1 has been
    nulled, not kept alive, and the raw indicator cannot tell the difference."""
    for x in a_records(r):
        try:
            a = ipaddress.ip_address(x)
        except ValueError:
            continue
        if not (a.is_loopback or a.is_private or a.is_reserved or a.is_unspecified):
            return True
    return False


def is_wildcard(r: dict) -> bool:
    """Registry-wildcard host, judged on the record's own capture-time addresses (never a live
    lookup: a record with no address cannot be a wildcard answer, and must not trigger one)."""
    ips = frozenset(a_records(r))
    return bool(ips) and is_registry_wildcard(registrable(r.get("domain") or ""), ips)


def load(path: str, arm: str = "phish"):
    """One record per domain in one arm, stratified as §3 stratifies, with lag in hours, and
    registry-wildcard hosts left out (counted, so the prose can say how many). Returns the raw
    rows, the screened records and the wildcard count."""
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    recs = []
    n_wild = 0
    for r in best_per_domain(rows):
        if arm and (r.get("label") or "") != arm:
            continue
        t0, t1 = ts(r.get("first_detected")), ts(r.get("captured_at"))
        if not (t0 and t1):
            continue
        if is_wildcard(r):
            n_wild += 1
            continue
        r = dict(r)
        r["_lag_h"] = max((t1 - t0).total_seconds() / 3600.0, 0.0)
        r["_stratum"] = "live" if t0.date() >= WATCHER_START else "backfill"
        r["_resolves"] = resolves(r)
        r["_routable"] = routable(r)
        recs.append(r)
    return rows, recs, n_wild


def bin_index(lag: float) -> int:
    idx = 0
    for i, e in enumerate(BIN_EDGES):
        if lag >= e:
            idx = i
    return idx


def bin_table(recs) -> list[dict]:
    """Resolvability by (stratum, lag bin), with the counts each interval is computed from."""
    buckets: dict[tuple[str, int], list[dict]] = collections.defaultdict(list)
    for r in recs:
        buckets[(r["_stratum"], bin_index(r["_lag_h"]))].append(r)
    out = []
    for (stratum, idx), g in sorted(buckets.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        lo = BIN_EDGES[idx]
        hi = BIN_EDGES[idx + 1] if idx + 1 < len(BIN_EDGES) else float("inf")
        k = sum(1 for r in g if r["_resolves"])
        kr = sum(1 for r in g if r["_routable"])
        cl, cu = wilson(k, len(g))
        out.append({"stratum": stratum, "lag_lo_h": lo, "lag_hi_h": hi, "n": len(g),
                    "resolves": k, "rate": k / len(g), "ci_lo": cl, "ci_hi": cu,
                    "routable": kr, "rate_routable": kr / len(g)})
    return out


def tail_concentration(recs) -> dict:
    """What the backfill's rising tail actually answers with. Generated, not asserted: the
    caption's claim that the tail is recycled address space has to come from the data."""
    g = [r for r in recs
         if r["_stratum"] == "backfill" and r["_resolves"] and r["_lag_h"] >= TAIL_H]
    ips = collections.Counter(x for r in g for x in a_records(r))
    top = ips.most_common(3)
    nulled = sum(1 for r in g if not r["_routable"])
    return {"n": len(g), "top_ips": top,
            "top_share": sum(c for _, c in top) / max(len(g), 1),
            "nulled": nulled}


def retry_table(rows) -> list[dict]:
    """Did a second look ever rescue a domain? Per arm, because the pooled number is carried by
    the benign side while the claim §3 makes is about the phishing side."""
    multi: dict[str, list[dict]] = collections.defaultdict(list)
    for r in rows:
        multi[r["domain"]].append(r)
    retried = {d: v for d, v in multi.items() if len(v) > 1}

    def revived(v) -> bool:
        return (not resolves(v[0])) and any(resolves(x) for x in v[1:])

    out = []
    for arm in ("phish", "benign"):
        sub = {d: v for d, v in retried.items() if (v[0].get("label") or "") == arm}
        rev = sorted(d for d, v in sub.items() if revived(v))
        out.append({"arm": arm, "reattempted": len(sub), "revived": len(rev),
                    "examples": ";".join(rev[:4])})
    allrev = [d for d, v in retried.items() if revived(v)]
    out.append({"arm": "pooled", "reattempted": len(retried), "revived": len(allrev),
                "examples": ""})
    return out


def write_csv(path: str, rows: list[dict]) -> None:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
    write_generated(path, buf.getvalue())


def _centre(b: dict) -> float:
    """Geometric centre of a bin, for a log axis. Two bins have no geometric centre and both
    would vanish silently if that were not handled: the first opens at 0 h, and the last is
    open-ended, whose centre is infinite -- matplotlib drops such a point without complaint, so
    the widest-lag bin (the tail this figure is partly about) would simply not be drawn."""
    lo, hi = b["lag_lo_h"], b["lag_hi_h"]
    if lo <= 0:
        return hi / 2
    if not math.isfinite(hi):
        return lo * 1.5      # the bins double, so this places it where the next centre would be
    return math.sqrt(lo * hi)


def make_figure(recs, bins: list[dict], retry: list[dict], tail: dict) -> str:
    from figstyle import apply, BLUE, ORANGE, GRAY, INK
    plt = apply()

    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(7.4, 3.1),
                                  gridspec_kw={"width_ratios": [1.8, 1]})

    # --- LEFT: resolvability against lag, one series per stratum, never joined across them.
    for stratum, colour in (("live", ORANGE), ("backfill", BLUE)):
        pts = [b for b in bins if b["stratum"] == stratum and b["n"] >= MIN_BIN]
        if not pts:
            continue
        x = [_centre(b) for b in pts]
        y = [b["rate"] for b in pts]
        err = [[b["rate"] - b["ci_lo"] for b in pts], [b["ci_hi"] - b["rate"] for b in pts]]
        ax.errorbar(x, y, yerr=err, fmt="none", elinewidth=1.0, ecolor=colour, alpha=0.9,
                    zorder=2)
        # Area with n, so a bin carrying 3,449 domains cannot be read against one carrying 41.
        ax.scatter(x, y, s=[12 + 26 * math.log10(b["n"]) for b in pts], color=colour,
                   zorder=3, edgecolor="white", linewidth=0.6)
        if len(pts) > 1:
            ax.plot(x, y, "-", color=colour, lw=1.0, alpha=0.45, zorder=1)

    # The hinge. It is a WITHIN-backfill comparison on purpose: contrasting live against
    # backfill would confound elapsed time with which population a domain came from, whereas
    # these two bins are the same population one bin apart, so only the clock differs.
    hinge = {b["lag_lo_h"]: b for b in bins
             if b["stratum"] == "backfill" and b["lag_lo_h"] in (16, 32) and b["n"] >= MIN_BIN}
    if len(hinge) == 2:
        xa, xb = _centre(hinge[16]), _centre(hinge[32])
        ax.annotate("", xy=(xb, hinge[32]["rate"]), xytext=(xa, hinge[16]["rate"]),
                    arrowprops={"arrowstyle": "->", "color": INK, "lw": 1.0,
                                "shrinkA": 5, "shrinkB": 5,
                                "connectionstyle": "arc3,rad=-0.25"})
        ax.annotate(f"{hinge[16]['rate']:.2f} $\\to$ {hinge[32]['rate']:.2f}\nin one bin",
                    (xb * 1.55, 0.62), fontsize=7.5, color=INK, ha="left", va="center")

    live_pts = [b for b in bins if b["stratum"] == "live" and b["n"] >= MIN_BIN]
    if live_pts:
        ax.annotate("live stratum", (_centre(live_pts[0]), live_pts[0]["rate"]), color=ORANGE,
                    fontsize=8, ha="center", textcoords="offset points", xytext=(0, -16))
    back = [b for b in bins if b["stratum"] == "backfill" and b["n"] >= MIN_BIN]
    if back:
        ax.annotate("backlog", (_centre(back[0]), back[0]["rate"]), color=BLUE, fontsize=8,
                    textcoords="offset points", xytext=(6, 4))
        ax.annotate("tail: recycled\naddress space", (_centre(back[-1]), back[-1]["rate"]),
                    color=INK, fontsize=7, ha="center", va="bottom",
                    textcoords="offset points", xytext=(0, 10))
    ax.set_xscale("log")
    ax.set_xlim(0.35, BIN_EDGES[-1] * 4)
    ax.set_ylim(0, 1.06)
    ax.set_xlabel("capture lag: enrichment $-$ detection (hours, log)")
    ax.set_ylabel("fraction with an A record")
    ax.set_title("phishing arm: resolvability holds for a day, then cliffs", fontsize=8.5)
    ax.grid(axis="y", alpha=0.6)

    # --- RIGHT: the retry. A bar that stays empty IS the finding, so the zero is labelled.
    arms = [r for r in retry if r["arm"] in ("phish", "benign")]
    ypos = list(range(len(arms)))[::-1]
    for y, r in zip(ypos, arms):
        colour = ORANGE if r["arm"] == "phish" else BLUE
        ax2.barh(y, r["reattempted"], height=0.46, color=colour, alpha=0.20, zorder=2)
        ax2.barh(y, r["revived"], height=0.46, color=colour, zorder=3)
        ax2.annotate(f"{r['revived']} revived of {r['reattempted']:,}", (r["reattempted"], y),
                     textcoords="offset points", xytext=(7, -3), fontsize=8, color=INK)
    ax2.set_yticks(ypos, ["phishing" if r["arm"] == "phish" else "benign" for r in arms])
    ax2.set_xlim(0, max(r["reattempted"] for r in arms) * 1.62)
    ax2.set_xlabel("re-attempted domains")
    ax2.set_title("a second look rescues nothing", fontsize=8.5)
    ax2.grid(axis="x", alpha=0.6)

    for a in (ax, ax2):
        a.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    os.makedirs(FIG, exist_ok=True)
    out = os.path.join(FIG, "perishability.pdf")
    fig.savefig(out)
    plt.close(fig)
    return out


def tex_int(n: int) -> str:
    """Digit grouping that survives math mode, where a bare comma sets as punctuation."""
    return f"{n:,}".replace(",", "{,}")


def make_tex(recs, bins: list[dict], retry: list[dict], tail: dict, n_wild: int = 0) -> None:
    """The numbers the prose may quote, generated so `make claims` can hold them to the CSV.
    Also writes gen_perishability_macros.tex (read from the preamble) so that prose elsewhere
    in the manuscript -- the retry anchor in S3 and the deviation record in S5 -- quotes the
    retry count through a macro rather than a literal that drifts with the capture."""
    st = {}
    for s in ("live", "backfill"):
        g = [r for r in recs if r["_stratum"] == s]
        st[s] = {"n": len(g), "median": statistics.median(r["_lag_h"] for r in g),
                 "rate": sum(1 for r in g if r["_resolves"]) / len(g)}
    hinge = {b["lag_lo_h"]: b for b in bins
             if b["stratum"] == "backfill" and b["lag_lo_h"] in (16, 32)}
    ph = next(r for r in retry if r["arm"] == "phish")
    be = next(r for r in retry if r["arm"] == "benign")
    po = next(r for r in retry if r["arm"] == "pooled")

    macros = {
        "PerishLiveN": tex_int(st["live"]["n"]),
        "PerishLiveRate": f"{100 * st['live']['rate']:.1f}",
        "PerishBackfillN": tex_int(st["backfill"]["n"]),
        "PerishBackfillRate": f"{100 * st['backfill']['rate']:.1f}",
        "PerishWildcardN": tex_int(n_wild),
        "PerishHingeBefore": f"{hinge[16]['rate']:.2f}",
        "PerishHingeAfter": f"{hinge[32]['rate']:.2f}",
        "RetryPhishRevived": str(ph["revived"]),
        "RetryPhishN": tex_int(ph["reattempted"]),
        "RetryBenignRevived": str(be["revived"]),
        "RetryBenignN": tex_int(be["reattempted"]),
        "RetryPooledRevived": str(po["revived"]),
        "RetryPooledN": tex_int(po["reattempted"]),
    }
    write_generated(os.path.join(SEC, "gen_perishability_macros.tex"),
                    "% generated by scripts/make_p4_perishability.py; do not edit\n"
                    + "".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in macros.items()))

    body = (
        "Redrawn on the accumulated phishing arm rather than the watcher's first five days "
        f"(Figure~\\ref{{fig:perish}}), counting each hostname once and leaving out the "
        f"{tex_int(n_wild)} registry-wildcard hosts of Section~\\ref{{ssec:wildcard}} (a name "
        "the registry answers for whether or not anyone registered it is not infrastructure "
        "surviving), the separation the design rests on is sharper than the "
        f"medians suggest. The live stratum ($n={tex_int(st['live']['n'])}$) is enriched a "
        f"median ${st['live']['median']:.1f}$\\,h after detection with "
        f"${100 * st['live']['rate']:.1f}\\%$ still resolving, the backlog "
        f"($n={tex_int(st['backfill']['n'])}$) a median "
        f"${st['backfill']['median']:.0f}$\\,h with ${100 * st['backfill']['rate']:.1f}\\%$; "
        "but the shape between those medians is the part a median cannot show, and it is a "
        "cliff rather than a decay. Resolvability holds near unity while the lag is short --- "
        f"${100 * st['live']['rate']:.1f}\\%$ under $16$\\,h, and still "
        f"${hinge[16]['rate']:.2f}$ at $16$--$32$\\,h "
        f"($n={tex_int(hinge[16]['n'])}$, a bin thin enough to read as a hinge and not a "
        "measurement) --- and then collapses to "
        f"${hinge[32]['rate']:.2f}$ in the very next bin ($32$--$64$\\,h, "
        f"$n={tex_int(hinge[32]['n'])}$), where it stays. Both of those bins sit inside the "
        "backlog, one bin apart, so the stratum boundary is not what does the work. Nor can "
        "this be read as a clean hazard: a backlog worked in date order ties capture lag to "
        "detection date, so the two bins differ by a day in both at once, and only the live "
        "stratum --- where enrichment follows detection within hours by construction --- "
        "separates them. What the shape does establish is that the smoothly decreasing hazard "
        "the cascade's design analysis assumed (Section~\\ref{ssec:cascade}) is not the only "
        "candidate: a step near one to two days would be friendlier economics, since evidence "
        "is then either almost certainly present or almost certainly gone, and the registered "
        "Kaplan--Meier estimate at analysis time will decide between them. The backlog's "
        "resolvability "
        f"then \\emph{{rises}} beyond ${tex_int(int(TAIL_H))}$\\,h, and that tail is an "
        f"artefact of the indicator rather than survival --- of its {tex_int(tail['n'])} "
        f"resolving domains, ${100 * tail['top_share']:.0f}\\%$ answer on just three "
        f"addresses and ${tex_int(tail['nulled'])}$ answer only on non-routable space. A domain "
        "recycled into parking or nulled still has an A record, so resolvability bounds "
        "survival from above wherever names have had time to be re-registered. The retry, "
        f"finally, re-measures as inert where the claim matters: ${ph['revived']}$ of "
        f"${tex_int(ph['reattempted'])}$ re-attempted phishing-arm domains ever gained an A "
        f"record, against ${be['revived']}$ of ${tex_int(be['reattempted'])}$ on the benign arm, "
        "whose revivals are parking and aftermarket infrastructure and transient resolver "
        f"failures on \\texttt{{.gov.vn}} --- the artefact class of Section~\\ref{{ssec:wildcard}}"
    )
    write_generated(os.path.join(SEC, "gen_perishability.tex"), body.rstrip() + "%")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--infra", default=INFRA)
    ap.add_argument("--arm", default="phish", help="capture arm to draw (default: the phishing "
                                                   "arm, which is what §3 quotes)")
    args = ap.parse_args()
    if not os.path.exists(args.infra):
        print(f"[i] {args.infra} absent — run watch_host_infra.py (or sync from the collector).")
        return 0

    rows, recs, n_wild = load(args.infra, args.arm)
    # Persist the backlog's suffix answers so every build reads the same probe file.
    write_wildcard_probe()
    bins = bin_table(recs)
    retry = retry_table(rows)
    tail = tail_concentration(recs)

    os.makedirs(PROC, exist_ok=True)
    write_csv(os.path.join(PROC, "p4", "p4_perishability.csv"), bins)
    write_csv(os.path.join(PROC, "p4", "p4_retry.csv"), retry)
    make_figure(recs, bins, retry, tail)
    make_tex(recs, bins, retry, tail, n_wild)

    live = sum(1 for r in recs if r["_stratum"] == "live")
    print(f"[i] {args.arm} arm: {len(recs):,} domains with both timestamps, "
          f"{n_wild:,} registry-wildcard hosts left out "
          f"(live {live:,}, backfill {len(recs) - live:,}); "
          f"tail>{TAIL_H:.0f}h {tail['n']:,} resolving, "
          f"top-3 IPs {100 * tail['top_share']:.0f}%, "
          f"non-routable {tail['nulled']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
