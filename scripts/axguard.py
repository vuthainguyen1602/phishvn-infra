#!/usr/bin/env python3
"""
axguard.py — refuse to write a figure that cuts off its own data.

WHY. A sweep of every generated figure in this repository found five that plotted data outside
their own axis limits, and not one was visible to a careful reader. Three shapes recurred:

  * a floor pinned at a round number just above a series' true minimum, so the deepest part of a
    decline left the plot and came back, reading as a gap rather than as a collapse;
  * an error bar whose lower cap fell under the axis, understating exactly the uncertainty the
    figure was drawn to show;
  * a curve cut at its terminal point -- the extreme operating point a reader reasons about
    first -- so several series ran off the bottom edge together.

A clipped series does not look wrong. It looks like a line that ends, and the reader has no way
to tell a real endpoint from a frame that stops early. That is why this is a build-time gate and
not a review checklist: figstyle.apply() installs it, and every generator in this repository goes
through figstyle.

WHAT IT DOES. Before a figure is written, every artist drawn in data coordinates is compared
against the view limits. Data outside them raises; a legend sitting on top of data prints a
warning (the data is still in frame, so it is a legibility problem, not a truth problem).

DELIBERATE ZOOMS. A figure may legitimately frame a sub-range -- but it should then not draw what
it excludes. Where that is impractical, say so at the call site and give the reason:

    from axguard import allow_clipping
    allow_clipping(ax, "boosting iterations 0-1 dwarf the converged region under study")

TWO TRAPS, both of which produced false alarms before this was trusted:
  * axhline/axvline/axhspan use a BLENDED transform -- one axis carries axes-fraction coords, so
    their (0, 1) endpoints look like data far outside any view;
  * a LineCollection (what errorbar draws its bars with) keeps its geometry in segments, and
    get_offsets() returns an unset [[0, 0]] placeholder that reads as a point at the origin.
Both are why artists are filtered on transform, and why collections are read via get_segments().
"""
from __future__ import annotations

import numpy as np

_ALLOW = "_axguard_allow_clip"
_INSTALLED = False


def allow_clipping(ax, reason: str):
    """Exempt one axes from the clipping gate. A reason is required, not decorative: it is the
    difference between a considered zoom and a floor nobody revisited."""
    if not reason or not reason.strip():
        raise ValueError("allow_clipping needs a reason")
    setattr(ax, _ALLOW, reason)
    return ax


def _in_data(ax, artist) -> bool:
    try:
        return artist.get_transform() == ax.transData
    except Exception:
        return False


def _data_points(ax) -> list:
    out = []
    for ln in ax.lines:
        if not _in_data(ax, ln):
            continue
        d = ln.get_xydata()
        if len(d):
            out.append(np.asarray(d, dtype=float))
    for c in ax.collections:
        if not _in_data(ax, c):
            continue
        try:
            segs = getattr(c, "get_segments", None)
            if segs is not None and segs():
                out.append(np.concatenate([np.asarray(s, float) for s in segs() if len(s)]))
                continue
            o = np.asarray(c.get_offsets(), dtype=float)
            if len(o) and not (len(o) == 1 and not o.any()):
                out.append(o)
        except Exception:
            pass
    for p in ax.patches:
        if not _in_data(ax, p):
            continue
        try:
            b = p.get_window_extent().transformed(ax.transData.inverted())
            out.append(np.array([[b.x0, b.y0], [b.x1, b.y1]], dtype=float))
        except Exception:
            pass
    return [d[np.isfinite(d).all(axis=1)] for d in out if len(d)]


def check_figure(fig) -> tuple[list, list]:
    """Return (clipped, legend_hits) as human-readable strings."""
    clipped, legend_hits = [], []
    for i, ax in enumerate(fig.axes):
        pts = _data_points(ax)
        if not pts:
            continue
        (x0, x1), (y0, y1) = sorted(ax.get_xlim()), sorted(ax.get_ylim())
        ex, ey = 1e-9 + 0.002 * (x1 - x0), 1e-9 + 0.002 * (y1 - y0)
        if not getattr(ax, _ALLOW, None):
            for d in pts:
                bad = d[(d[:, 0] < x0 - ex) | (d[:, 0] > x1 + ex)
                        | (d[:, 1] < y0 - ey) | (d[:, 1] > y1 + ey)]
                if len(bad):
                    # "furthest" means furthest OUTSIDE the frame, not largest in magnitude: on a
                    # floor violation the biggest |y| is the point nearest the edge, which names
                    # the least interesting offender in the message the author has to act on.
                    over = np.maximum.reduce([x0 - bad[:, 0], bad[:, 0] - x1,
                                              y0 - bad[:, 1], bad[:, 1] - y1])
                    worst = bad[np.argmax(over)]
                    clipped.append(
                        f"axes {i}: {len(bad)} point(s) outside x[{x0:.4g}, {x1:.4g}] "
                        f"y[{y0:.4g}, {y1:.4g}]; furthest {worst[0]:.4g}, {worst[1]:.4g}")
                    break
        lg = ax.get_legend()
        if lg is not None:
            try:
                fig.canvas.draw()
                b = lg.get_window_extent().transformed(ax.transData.inverted())
                bx0, bx1 = sorted((b.x0, b.x1))
                by0, by1 = sorted((b.y0, b.y1))
                n = sum(int(((d[:, 0] >= bx0) & (d[:, 0] <= bx1)
                             & (d[:, 1] >= by0) & (d[:, 1] <= by1)).sum()) for d in pts)
                if n:
                    legend_hits.append(f"axes {i}: the legend box covers {n} data point(s)")
            except Exception:
                pass
    return clipped, legend_hits


def install():
    """Patch Figure.savefig once, so every figure this repository writes is gated."""
    global _INSTALLED
    if _INSTALLED:
        return
    from matplotlib.figure import Figure

    original = Figure.savefig

    def savefig(self, fname, *args, **kwargs):
        clipped, legend_hits = check_figure(self)
        name = str(fname).split("/")[-1]
        for msg in legend_hits:
            print(f"[!] {name}: {msg} — move the legend or the reader loses those marks")
        if clipped:
            raise ValueError(
                f"{name} would cut off its own data:\n  " + "\n  ".join(clipped)
                + "\n  Derive the limit from the data, or call axguard.allow_clipping(ax, reason)"
                  " if the zoom is deliberate — and then do not draw what it excludes.")
        return original(self, fname, *args, **kwargs)

    Figure.savefig = savefig
    _INSTALLED = True
