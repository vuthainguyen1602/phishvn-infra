#!/usr/bin/env python3
"""
figstyle.py — one house style for every generated paper figure, so the figure set reads as a
system rather than a pile of individually-styled plots.

The palette is the two hues the earliest figures already use — orange for the
phishing/booster/attention role, blue for the benign/linear/reference role — plus a recessive
gray for "everything whose individual identity is not the point". The categorical pair was
checked with the dataviz validator (CVD ΔE 24.7 protan, well above the 8 target), so it is
colourblind-safe; do not swap in a third saturated hue without re-validating.

Numbers in a figure come from the SAME CSVs the tables read, never hand-typed, for the reason
spelled out in figures/decomposition.tex: make claims verifies .tex, not compiled PDFs, so a
literal in a figure is the one place a stale number could survive a data change unseen.
"""
from __future__ import annotations
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)

# Role-based palette. Assign by the job the mark does, never cycle hues.
ORANGE = "#eb6834"   # phishing / booster / the highlighted extreme / the blind spot
BLUE = "#2a78d6"     # benign / linear baseline / the reference
TEAL = "#1b9e8a"     # categorical slot 3 (multi-series line panels)
PURPLE = "#7c4dbe"   # categorical slot 4 — validated CVD-safe with BLUE/TEAL, direct-label required
GRAY = "#9aa0a6"     # families/marks whose individual identity is not the story
INK = "#2b2b2b"      # all text: labels, values, annotations — never the series colour
GRID = "#e6e6e6"     # recessive gridlines
FILL_O = "#f6c9b4"   # pale orange fill (bar bodies where a lighter tint reads better)
FILL_B = "#bcd6f4"   # pale blue fill


def apply():
    """Set the shared rcParams. Call once at the top of a figure-generating main().

    Also installs the axis guard: every generator here goes through this function, which makes it
    the one place a figure that clips its own data can be stopped before it is written."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from axguard import install as _install_axguard
    _install_axguard()
    plt.rcParams.update({
        "font.size": 9,
        "axes.edgecolor": "#8a8a8a",
        "axes.linewidth": 0.7,
        "axes.labelcolor": INK,
        "axes.titlecolor": INK,
        "text.color": INK,
        "xtick.color": INK,
        "ytick.color": INK,
        "xtick.labelsize": 8.5,
        "ytick.labelsize": 8.5,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "grid.color": GRID,
        "grid.linewidth": 0.7,
        "figure.dpi": 150,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
        "pdf.fonttype": 42,   # embed TrueType so text stays selectable/searchable in the PDF
    })
    return plt
