#!/usr/bin/env python3
"""
make_infra_assets.py — the results machinery, built before the data matured.

The study is a time-stamped pre-specified design: population, features, models and the
success criterion are frozen in §5. This script IS that protocol, executable. It always regenerates
the pre-outcome monitoring assets and refuses to fit until BOTH the candidate trigger and the
trusted-positive outcome gate are satisfied. Candidate-screen verdicts never become model labels.

    python scripts/make_infra_assets.py            # regenerate monitoring assets; fit iff triggered
    python scripts/make_infra_assets.py --smoke    # the fitting path on LABEL-PERMUTED data;
                                                # writes only to data/interim/p4_smoke/

POPULATION RULE CHANGE (2026-08-03): the original both-arms .vn cut selected exactly the slice with
no phishing — of 32 conditioned .vn "phishing" domains, zero blocklist-corroborated, ten (31%)
verifiably legitimate (bidv.vn, viettelpost.vn, sepay.vn...). Mechanism
(watch_urlscan_brands.py:23): urlscan's free tier cannot filter maliciousness, so label=phish means
only "hostname contains a Vietnamese brand token" — worst on .vn, since VN phishing is ~2.7% .vn
while VN companies are there. Repair: drop the TLD cut, let audit_capture_labels.audit() decide.

Population (§5, revised): phishing = live stratum only (first_detected >= 2026-07-30), admitted on
a corroborated / credential_form / content_confirmed / vn_lexical verdict; uncorroborated and
no_capture are honest unknowns, excluded_legitimate the error that forced the rewrite. Benign arm =
ct_benign (TLD- and age-matched from raw CT logs); tinnhiem_benign is 100% .vn so it is never
pooled, only kept as an age-mismatched comparator. Free-hosting-suffix names are their own stratum
in both arms (registration-level features belong to the provider) — counted, never modelled.
Registry-wildcard names (artefact #5, 2026-08-16) resolve, serve 443 and capture HTTP-200 without
ever being REGISTERED — 708 of 1,036 conditioned "phishing" domains were this — and are screened
from EVERY arm by capture-time a_records vs a live probe (audit_capture_labels.is_registry_wildcard),
counted in the funnel and modelled nowhere. Survivors are deduplicated to the most complete record
per registrable domain, conditioned on resolving AND serving TLS.

Features (DNS/TLS shape only): cert age at capture, validity length, issuer group, SAN count,
A-record TTL, NS count + provider group, MX presence, CNAME presence. Excluded by construction:
whois_* and its missingness, tls_present/resolution status, the TLD, anything lexical.
"""
from __future__ import annotations

import argparse
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
from paired_eval import corrected_paired_t, wilson
from genfile import write_generated
from compphish_features import extract as lex_extract
from audit_capture_labels import (audit, is_hosted_subdomain,
                             is_registry_wildcard, load_content_map, registrable)
from outcome_gate import OUTCOME_LABELS, trusted_positive_population

INFRA = "data/raw/host_infra/host_infra.csv"
DATASET = "data/processed/infra/infra_dataset.csv"
LABEL_AUDIT = "data/processed/infra/label_audit.csv"
SECTIONS = "papers/P4_infra/sections"
SMOKE_DIR = "data/interim/p4_smoke"
CONTENT_MAP = "data/interim/content_map.csv"
WATCHER_START = pd.Timestamp("2026-07-30")
# The collector's clock. Every duration is taken in ONE zone (2026-08-21 fix): `captured_at` and
# collector-stamped `first_detected` are naive local, CT rows' `first_detected` is naive UTC,
# `tls_not_before/after` carry an offset. Parsing all four utc=True inflated cert age by 7 h.
LOCAL_TZ = "Asia/Ho_Chi_Minh"
CT_SOURCES = ("ct_benign", "ct_benign_vn")
TRIGGER, CONFIRM = 500, 1000

# Positive-evidence verdicts, strongest first: blocklist-named, rendered credential form (added
# 2026-08-16 -- only 18% of Vietnamese-rendering pages ask for a password, so language and
# harvesting are distinct), rendered Vietnamese, or a name that spells a Vietnamese word.
# Everything else is unknown or exoneration: an arm of unknowns measures token co-occurrence.
PHISH_VERDICTS = ("corroborated", "credential_form", "content_confirmed", "vn_lexical")
BENIGN_SOURCE = "ct_benign"
# The .vn supplement of the matched arm (PREREG amendment 2026-08-21): its own source, admitted to
# the SAME arm under the same conditioning, but it may fill .vn cells only, and is never pooled.
SUPPLEMENT_SOURCE = "ct_benign_vn"
BENIGN_SOURCES = (BENIGN_SOURCE, SUPPLEMENT_SOURCE)
COMPARATOR_SOURCE = "tinnhiem_benign"
COMPARATOR_ARM = "benign_tinnhiem"
MODEL_ARMS = ("phish", "benign")

ISSUER_GROUPS = ("Let's Encrypt", "ZeroSSL", "Google Trust", "Sectigo", "DigiCert",
                 "GlobalSign", "cPanel", "GoDaddy", "Amazon", "Cloudflare")


def issuer_group(s) -> str:
    s = "" if pd.isna(s) else str(s)
    for g in ISSUER_GROUPS:
        if g.lower() in s.lower():
            return g
    return "other" if s.strip() else ""


def ns_provider(s) -> str:
    """Provider group of the NS set: the dominant registrable suffix among the NS hosts."""
    s = "" if pd.isna(s) else str(s)
    hosts = [h for h in s.split(";") if h.strip()]
    if not hosts:
        return ""
    provs = [".".join(h.strip(".").split(".")[-2:]) for h in hosts]
    return max(set(provs), key=provs.count)


def most_complete(g: pd.DataFrame) -> pd.Series:
    score = (g["a_records"].fillna("").astype(str).str.strip().astype(bool).astype(int)
             + g["tls_not_before"].fillna("").astype(str).str.strip().astype(bool).astype(int)
             + g["ns_hosts"].fillna("").astype(str).str.strip().astype(bool).astype(int))
    return g.loc[score.idxmax()]


def _to_local_naive(col: pd.Series, naive_zone: str) -> pd.Series:
    """Parse a timestamp column into naive LOCAL_TZ wall time. Values without an offset are
    taken to be in `naive_zone`; values with one keep it. Every column goes through here, so
    every subtraction in the file happens in one zone."""
    parsed = pd.to_datetime(col, errors="coerce", utc=False)
    if getattr(parsed.dt, "tz", None) is None:        # all naive: one zone, no offsets
        aware = parsed.dt.tz_localize(naive_zone, ambiguous="NaT", nonexistent="NaT")
    else:                                              # all offset-bearing, already aware
        aware = parsed
    return aware.dt.tz_convert(LOCAL_TZ).dt.tz_localize(None)


def localise_timestamps(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["captured_at"] = _to_local_naive(df["captured_at"], LOCAL_TZ)
    for c in ("tls_not_before", "tls_not_after"):
        df[c] = _to_local_naive(df[c], "UTC")
    is_ct = df["source"].isin(CT_SOURCES)
    fd = pd.Series(pd.NaT, index=df.index, dtype="datetime64[ns]")
    fd[is_ct] = _to_local_naive(df.loc[is_ct, "first_detected"], "UTC")
    fd[~is_ct] = _to_local_naive(df.loc[~is_ct, "first_detected"], LOCAL_TZ)
    df["first_detected"] = fd
    return df


def build_population() -> tuple[pd.DataFrame, dict]:
    df = pd.read_csv(INFRA, low_memory=False)
    df = localise_timestamps(df)
    # Recompute registered_domain with the audit's extractor: pre-2026-08-03 collector rows lack the
    # PSL private section, collapsing free-hosting names onto their host (mbbank.pages.dev ->
    # pages.dev), so this keeps study unit, label gate and stratum naming the same objects.
    df["registered_domain"] = df["domain"].map(registrable)
    df = df[df["registered_domain"].astype(bool)]
    funnel: dict[str, int] = {}

    content = load_content_map(CONTENT_MAP) if os.path.exists(CONTENT_MAP) else None
    if content is None:
        print(f"[!] {CONTENT_MAP} absent — the 'content_confirmed' class is UNAVAILABLE and the "
              "phishing arm is undercounted by every domain whose only evidence is that it renders "
              "Vietnamese. The captures live on the collector; export the map there with "
              f"`python scripts/audit_capture_labels.py --export-content {CONTENT_MAP}` and sync it.",
              file=sys.stderr)

    # Capture-time addresses per registrable domain, unioned across attempts: a domain that ever
    # resolved beyond the wildcard is never mistaken for it, and builds avoid live re-resolution.
    ipmap: dict[str, frozenset] = {}
    for reg, ips in zip(df["registered_domain"],
                        df["a_records"].fillna("").astype(str).str.split(";")):
        got = frozenset(x.strip() for x in ips if x.strip())
        if got:
            ipmap[reg] = ipmap.get(reg, frozenset()) | got

    ph_live = df[(df["label"] == "phish") & (df["first_detected"] >= WATCHER_START)]
    audit_tab = audit(sorted(set(ph_live["registered_domain"])), content_map=content,
                      ipmap=ipmap)
    verdict = dict(audit_tab[["registered_domain", "verdict"]].itertuples(index=False, name=None))
    stage_removed: dict[str, str] = {}     # phishing candidates only: where each one left
    # Time-matching means "collected by the same watcher over the same period", not strict containment:
    # the benign queue runs on its own cadence and can lag or lead the last phishing tick by hours.
    be = df[(df["label"] == "benign") & (df["captured_at"] >= WATCHER_START)]

    arms = []
    for name, arm in (("phish", ph_live),
                      ("benign", be[be["source"].isin(BENIGN_SOURCES)]),
                      (COMPARATOR_ARM, be[be["source"] == COMPARATOR_SOURCE])):
        funnel[f"{name}_live"] = arm["registered_domain"].nunique()
        # astype(bool) is load-bearing on an arm the collector has not filled yet: an empty
        # object-dtype mask is read by pandas as a list of column labels, not as a row filter.
        hosted = arm["registered_domain"].map(is_hosted_subdomain).astype(bool)
        funnel[f"{name}_hosted"] = arm.loc[hosted, "registered_domain"].nunique()
        if name == "phish":
            stage_removed.update((d, "hosted_subdomain") for d in arm.loc[hosted, "registered_domain"])
        arm = arm[~hosted]
        # Wildcard screen applies to every arm -- a wildcard name has no registration to study whichever
        # arm claims it. Only the phishing feed is contaminated in practice (the benign arms sample
        # certificates, which require registration), and recording ~0 for them is what shows that.
        wild = arm["registered_domain"].map(
            lambda d: is_registry_wildcard(d, ipmap.get(d))).astype(bool)
        funnel[f"{name}_wildcard"] = arm.loc[wild, "registered_domain"].nunique()
        if name == "phish":
            stage_removed.update((d, "registry_wildcard") for d in arm.loc[wild, "registered_domain"])
        arm = arm[~wild]
        if name == "phish":
            gated = arm["registered_domain"].map(lambda d: verdict.get(d) in PHISH_VERDICTS).astype(bool)
            stage_removed.update((d, "label_gate") for d in arm.loc[~gated, "registered_domain"])
            arm = arm[gated]
        funnel[f"{name}_gate"] = arm["registered_domain"].nunique()
        if len(arm):
            arm = arm.groupby("registered_domain",
                              group_keys=False)[arm.columns].apply(most_complete)
            cond = (arm["a_records"].fillna("").astype(str).str.strip().astype(bool)
                    & (pd.to_numeric(arm["tls_present"], errors="coerce") == 1))
            if name == "phish":
                stage_removed.update((d, "conditioning") for d in arm.loc[~cond, "registered_domain"])
                stage_removed.update((d, "admitted") for d in arm.loc[cond, "registered_domain"])
            arm = arm[cond]
        funnel[f"{name}_conditioned"] = len(arm)
        arms.append(arm.assign(arm=name))
    pop = pd.concat(arms, ignore_index=True)
    write_label_audit(ph_live, audit_tab, stage_removed, funnel)
    pop["verdict"] = pop["registered_domain"].where(pop["arm"] == "phish").map(verdict).fillna("")
    funnel["content_map"] = int(content is not None)
    funnel["phish_vn"] = int((pop.loc[pop["arm"] == "phish", "registered_domain"]
                              .str.endswith(".vn")).sum())

    # Both operands are naive LOCAL_TZ wall time (localise_timestamps), so the difference is a
    # true elapsed interval: no constant offset enters any duration here.
    pop["cert_age_days"] = (pop["captured_at"] - pop["tls_not_before"]).dt.total_seconds() / 86400
    pop["cert_validity_days"] = (pop["tls_not_after"]
                                 - pop["tls_not_before"]).dt.total_seconds() / 86400
    pop["issuer_grp"] = pop["tls_issuer"].map(issuer_group)
    pop["san_count"] = pd.to_numeric(pop["tls_san_count"], errors="coerce")
    pop["ttl"] = pd.to_numeric(pop["a_ttl"], errors="coerce")
    pop["ns_count"] = pd.to_numeric(pop["ns_count"], errors="coerce")
    pop["ns_provider_grp"] = pop["ns_hosts"].map(ns_provider)
    pop["mx_present"] = (pd.to_numeric(pop["mx_count"], errors="coerce") > 0).astype(int)
    pop["cname_present"] = pop["cname"].fillna("").astype(str).str.strip().astype(bool).astype(int)

    keep = ["registered_domain", "arm", "source", "verdict", "first_detected", "captured_at",
            "cert_age_days", "cert_validity_days", "issuer_grp", "san_count", "ttl",
            "ns_count", "ns_provider_grp", "mx_present", "cname_present"]
    # Atomic replace: make_infra_data_assets imports build_population and can run concurrently; a
    # plain to_csv leaves a torn file to whichever reader arrives mid-write.
    write_generated(DATASET, pop[keep].to_csv(index=False))
    return pop, funnel


def write_label_audit(ph_live: pd.DataFrame, audit_tab: pd.DataFrame,
                      stage_removed: dict[str, str], funnel: dict) -> None:
    """The per-candidate verdict table the funnel is counted from, one row per live-stratum
    phishing registrable domain, with the stage at which the protocol removed it (or
    `admitted`). Output only: every value is computed by build_population already; writing it
    makes the funnel auditable row by row. The row count and the stage counts are asserted
    against the funnel so the file can never disagree with tab_audit / funnel.csv."""
    first = (ph_live.sort_values("first_detected")
             .groupby("registered_domain")
             .agg(source=("source", "first"), first_detected=("first_detected", "first")))
    tab = audit_tab.set_index("registered_domain").join(first, how="left")
    tab["stage_removed"] = tab.index.map(stage_removed)
    tab = tab.reset_index()
    cols = ["registered_domain", "source", "first_detected", "verdict", "stage_removed",
            "in_tranco", "in_allowlist", "blocklists", "renders_vietnamese", "credential_form",
            "vn_lexical"]
    tab = tab[cols].sort_values(["stage_removed", "verdict", "registered_domain"])
    counts = tab["stage_removed"].value_counts().to_dict()
    live = funnel["phish_live"]
    expect = {"hosted_subdomain": funnel["phish_hosted"],
              "registry_wildcard": funnel["phish_wildcard"],
              "label_gate": live - funnel["phish_hosted"] - funnel["phish_wildcard"]
                            - funnel["phish_gate"],
              "conditioning": funnel["phish_gate"] - funnel["phish_conditioned"],
              "admitted": funnel["phish_conditioned"]}
    got = {k: counts.get(k, 0) for k in expect}
    if len(tab) != live or tab["stage_removed"].isna().any() or got != expect:
        raise RuntimeError(f"label audit table disagrees with the funnel: rows {len(tab)} vs "
                           f"live {live}; stages {got} vs {expect}")
    write_generated(LABEL_AUDIT, tab.to_csv(index=False))


FEATURES_NUM = ["cert_age_days", "cert_validity_days", "san_count", "ttl", "ns_count",
                "mx_present", "cname_present"]
FEATURES_CAT = ["issuer_grp", "ns_provider_grp"]


ARM_COLUMNS = (("phish", "Phishing"),
               ("benign", "Benign (\\texttt{ct\\_benign})"),
               (COMPARATOR_ARM, "Comparator (\\texttt{tinnhiem\\_benign})"))


def write_monitoring(pop: pd.DataFrame, funnel: dict) -> None:
    import io
    asof = pop["captured_at"].max().date()
    n_ph, n_be = funnel["phish_conditioned"], funnel["benign_conditioned"]
    n_cmp, n_vn = funnel[f"{COMPARATOR_ARM}_conditioned"], funnel["phish_vn"]
    # The benign arm's own .vn count. Calling ct_benign "TLD-matched" while never reporting it let a
    # degenerate case pass unstated: the arm holds zero .vn, so on the .vn slice -- where the
    # artefact this design neutralises actually lives -- there is nothing to match against.
    be_vn = int(pop[(pop["arm"] == "benign")]["registered_domain"]
                .astype(str).str.endswith(".vn").sum())
    _, outcome_gate = trusted_positive_population(pop, TRIGGER)
    gate_reason_tex = outcome_gate.reason.replace("_", r"\_")
    with io.StringIO() as f:
        f.write(f"As of {asof}: ${n_ph}$ conditioned phishing registrable domains admitted by the "
                f"label gate of \\S\\ref{{sec:protocol}} (${100 * n_ph // TRIGGER}\\%$ of the "
                f"$n \\geq {TRIGGER}$ analysis trigger), of which ${n_vn}$ are \\texttt{{.vn}}, "
                f"and ${format(n_be, ',').replace(',', '{,}')}$ conditioned benign registrable domains from \\texttt{{ct\\_benign}} "
                f"--- the age-matched arm, and the only benign arm the comparison uses. "
                + (f"TLD matching is achieved off \\texttt{{.vn}} but not on it: the benign arm "
                   f"holds ${be_vn}$ \\texttt{{.vn}} domains against the phishing arm's ${n_vn}$, "
                   f"so for that ${round(100 * n_vn / max(n_ph, 1))}\\%$ of the phishing arm the "
                   f"artefact is not matched away but simply unmatched, and any \\texttt{{.vn}} "
                   f"contrast is out of reach until the benign feed supplies them. "
                   if be_vn < n_vn else
                   f"The benign arm holds ${be_vn}$ \\texttt{{.vn}} domains against the phishing "
                   f"arm's ${n_vn}$, so the TLD match is achieved on both sides. ")
                + f"The \\texttt{{tinnhiem\\_benign}} comparator (${n_cmp}$ conditioned) is reported "
                "beside it and never pooled with it: it is entirely \\texttt{.vn}, so pooling "
                "would reinstate as a benign marker the very restriction this design dropped. "
                + ("" if funnel["content_map"] else
                   "The content-evidence map was absent for this snapshot, so the "
                   "\\emph{content-confirmed} class could not contribute and the phishing arm is "
                   "undercounted. ")
                + (f"The candidate trigger has fired, but the outcome remains locked: "
                   f"{gate_reason_tex}."
                   if n_ph >= TRIGGER and not outcome_gate.unlocked else
                   "Both the candidate trigger and trusted-positive gate have fired; the "
                   "confirmatory outcome path is unlocked."
                   if outcome_gate.unlocked else
                   f"The candidate trigger has not fired, and the outcome-label gate is also "
                   f"locked ({gate_reason_tex}); no outcome model has been fitted.") + "\n")
        write_generated(f"{SECTIONS}/gen_progress.tex", f.getvalue())
    with io.StringIO() as f:
        # The per-arm hosted-subdomain and wildcard removals are the differences between consecutive rows
        # below, and why both classes are counted-but-not-modelled is in the body, so the caption no
        # longer repeats it. The comparator's never-pooled rule is stated in gen_progress.
        f.write("\\begin{table}[t]\\centering\n"
                "\\caption{Population funnel at the current snapshot: unique registrable domains "
                "surviving each cut of \\S\\ref{sec:protocol}, per arm; the label gate applies "
                "to the phishing arm only.}\n"
                "\\label{tab:audit}\n"
                "\\begin{tabular}{lccc}\\toprule\n"
                "Cut & Phishing & Benign & Comparator \\\\ \\midrule\n")
        for label, cell in (
                ("Live stratum / capture window",
                 lambda a: funnel[f"{a}_live"]),
                ("Less hosted-subdomain stratum",
                 lambda a: funnel[f"{a}_live"] - funnel[f"{a}_hosted"]),
                ("Less registry-wildcard names",
                 lambda a: funnel[f"{a}_live"] - funnel[f"{a}_hosted"] - funnel[f"{a}_wildcard"]),
                ("Label gate (blocklist / credential / content / lexical)",
                 lambda a: funnel[f"{a}_gate"]),
                ("Resolving and serving TLS",
                 lambda a: funnel[f"{a}_conditioned"])):
            # Digit-grouped like every other count in the manuscript ("1{,}953", not "1953").
            f.write(f"{label} & " + " & ".join(f"{cell(a):,}".replace(",", "{,}")
                                              for a, _ in ARM_COLUMNS) + " \\\\\n")
        f.write("\\bottomrule\\end{tabular}\\end{table}\n")
        write_generated(f"{SECTIONS}/tab_audit.tex", f.getvalue())
    with io.StringIO() as f:
        f.write("\\begin{table}[t]\\centering\n"
                "\\caption{Feature availability by arm after conditioning, the standing check "
                "that no \\S\\ref{sec:design}-class artefact has re-entered; every gap is "
                "reported, none is used as a feature.}\n\\label{tab:availability}\n"
                "\\begin{tabular}{lccc}\\toprule\n"
                "Feature & " + " & ".join(h for _, h in ARM_COLUMNS) + " \\\\ \\midrule\n")
        for feat in FEATURES_NUM + FEATURES_CAT:
            row = []
            for arm, _ in ARM_COLUMNS:
                sub = pop[pop["arm"] == arm][feat]
                ok = sub.notna() & (sub.astype(str).str.strip() != "")
                row.append(f"{100 * ok.mean():.0f}\\%" if len(sub) else "--")
            feat_tex = feat.replace("_", "\\_")  # Jetson is Python 3.10: no backslash in f-string exprs
            f.write(f"\\texttt{{{feat_tex}}} & " + " & ".join(row) + " \\\\\n")
        f.write("\\bottomrule\\end{tabular}\\end{table}\n")
        write_generated(f"{SECTIONS}/tab_availability.tex", f.getvalue())

    # Single-arm marginal of the benign pool's cert age, split at the 2026-08-16 age-rotation fix. One
    # arm's marginal reveals nothing about separation, so it is safe pre-trigger -- and it is the one
    # place the pre-fix age glut can surface BEFORE it becomes an artefact in a fitted model.
    be_age = pop[(pop["arm"] == "benign")][["captured_at", "cert_age_days"]].dropna()
    fix = pd.Timestamp("2026-08-16")
    rows = []
    for label, sub in (("collected before 2026-08-16 (rotation pinned at 1\\,d)",
                        be_age[be_age["captured_at"] < fix]),
                       ("collected 2026-08-16 or later (rotation active)",
                        be_age[be_age["captured_at"] >= fix])):
        if len(sub):
            q = sub["cert_age_days"].quantile([0.25, 0.5, 0.75])
            rows.append(f"{label} & {len(sub)} & {q[0.25]:.1f} & {q[0.5]:.1f} & {q[0.75]:.1f} \\\\")
        else:
            rows.append(f"{label} & 0 & -- & -- & -- \\\\")
    write_generated(
        f"{SECTIONS}/tab_benign_age.tex",
        "\\begin{table}[t]\\centering\n"
        "\\caption{Certificate age in the \\texttt{ct\\_benign} pool (rows with a certificate) "
        "before and after the collector's age-rotation fix, quartiles in days; a single-arm "
        "marginal, so it reveals no outcome.}\n"
        "\\label{tab:benignage}\n"
        "\\begin{tabular}{lcccc}\\toprule\n"
        "Collection window & $n$ & Q1 & median & Q3 \\\\ \\midrule\n"
        + "\n".join(rows) + "\n\\bottomrule\\end{tabular}\\end{table}\n")


# ----------------------------------------------------------------- analysis-time procedures
# Frozen 2026-08-17 (deviation record §5.7; the pre-specification pins the commit). Everything
# below runs only at trigger, or under --smoke on randomised labels.

SEEDS = 20                 # raised from 5 on 2026-08-17, before any trigger (amendment)
MATCH_RATIO = 3            # benign : phishing ceiling per matching cell
FPR_BUDGET = 0.30          # the registered corpus budget (§5.4)
ROLL_CUTS = (0.60, 0.65, 0.70)   # descriptive rolling origins; 0.70 is the registered split


def public_suffix(reg_dom: str) -> str:
    """The matching TLD of a registrable domain = everything after its first label."""
    parts = str(reg_dom).split(".", 1)
    return parts[1] if len(parts) == 2 else parts[0]


def lexical_frame(domains: pd.Series) -> pd.DataFrame:
    """The lexical channel: CompPhish features of the HOSTNAME string, identical extractor for
    both arms (the benign arm has no URL — CT logs carry names — so the hostname is the only
    string both arms possess, and using anything richer on one arm would measure the channel
    difference, not the infrastructure)."""
    feats = pd.DataFrame([lex_extract(d) for d in domains.astype(str)], index=domains.index)
    return feats.apply(pd.to_numeric, errors="coerce")


def match_benign(d: pd.DataFrame, seed: int) -> tuple[pd.DataFrame, float]:
    """TLD- and age-matched benign subsample (deviation record 2026-08-03 promised it; this is
    the procedure, frozen 2026-08-17): cells = public suffix x quartile bin of the PHISHING
    arm's cert age; per cell draw at most MATCH_RATIO x (phishing count) benign without
    replacement, RNG(seed). Returns the matched frame and the coverage ratio (matched / desired)
    — under-supplied cells are reported, never silently topped up from other cells."""
    ph = d[d["arm"] == "phish"]
    be = d[d["arm"] == "benign"]
    edges = ph["cert_age_days"].quantile([0.25, 0.5, 0.75]).tolist()

    def age_bin(v):
        if pd.isna(v):
            return -1
        return int(np.searchsorted(edges, v))

    rng = np.random.default_rng(seed)
    got, want = [], 0
    ph_cells = ph.assign(_sfx=ph["registered_domain"].map(public_suffix),
                         _bin=ph["cert_age_days"].map(age_bin))
    be_cells = be.assign(_sfx=be["registered_domain"].map(public_suffix),
                         _bin=be["cert_age_days"].map(age_bin))
    for (sfx, b), cell in ph_cells.groupby(["_sfx", "_bin"]):
        wish = MATCH_RATIO * len(cell)
        want += wish
        pool = be_cells[(be_cells["_sfx"] == sfx) & (be_cells["_bin"] == b)]
        # Amendment 2026-08-21: the .vn supplement fills .vn cells ONLY. Its rows are all .vn by
        # construction, so this guards a future change of the sampler, not today's data.
        if not str(sfx).endswith("vn"):
            pool = pool[pool["source"] != SUPPLEMENT_SOURCE]
        take = min(wish, len(pool))
        if take:
            got.append(pool.sample(n=take, random_state=rng.integers(0, 2**31)))
    matched = (pd.concat(got).drop(columns=["_sfx", "_bin"]) if got
               else be.iloc[0:0])
    return matched, (len(matched) / want if want else 0.0)


def qmap_scores(scores: np.ndarray, is_vn: np.ndarray, cal_be_scores: np.ndarray,
                cal_be_vn: np.ndarray) -> np.ndarray:
    """The companion XAI study's benign quantile mapping (§5.4): each registry group's scores
    pass through that group's TRAIN-benign quantile function, so one global threshold spends
    the same benign quantile in every group. Groups: .vn vs other. A group with no calibration
    benign falls back to the pooled reference (reported by the caller)."""
    out = np.empty_like(scores, dtype=float)
    for vn in (True, False):
        m = is_vn == vn
        if not m.any():
            continue
        cal = cal_be_scores[cal_be_vn == vn]
        if len(cal) < 10:                      # degenerate group: pooled fallback
            cal = cal_be_scores
        out[m] = np.searchsorted(np.sort(cal), scores[m], side="right") / len(cal)
    return out


def fit_main(pop: pd.DataFrame, out_dir: str, smoke: bool) -> None:
    """The time-stamped pre-specified main comparison (§5.3-5.4, frozen 2026-08-17): lexical baseline vs
    URL+infrastructure fusion, on the gated phishing arm against the TLD/age-MATCHED ct_benign
    subsample. Temporal split at the registered 0.70 origin, SEEDS seeds, scores
    benign-quantile-mapped per registry group. The confirmatory quantity is the .vn miss rate at
    the corpus FPR <= 0.30 budget, fusion minus lexical, corrected paired t, BH over m=2."""
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import cross_val_predict
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler
    from catboost import CatBoostClassifier

    if not smoke:
        pop, outcome_gate = trusted_positive_population(pop, TRIGGER)
        if not outcome_gate.unlocked:
            raise RuntimeError("outcome is locked: " + outcome_gate.reason)
    d = pop[pop["arm"].isin(MODEL_ARMS)].copy()
    if smoke:
        rng = np.random.default_rng(0)
        # Random arm labels: destroys the outcome while proving the full path (matching,
        # mapping, both channels, the paired test) end to end.
        d["arm"] = np.where(rng.integers(0, 2, len(d)) == 1, "phish", "benign")
    lex = lexical_frame(d["domain"] if "domain" in d else d["registered_domain"])
    LEX_COLS = list(lex.columns)
    d = pd.concat([d, lex], axis=1)
    d["is_vn"] = d["registered_domain"].astype(str).str.endswith(".vn")

    pre_infra = ColumnTransformer([
        ("num", Pipeline([("imp", SimpleImputer(strategy="median")),
                          ("sc", StandardScaler())]), FEATURES_NUM),
        ("cat", OneHotEncoder(handle_unknown="ignore"), FEATURES_CAT)])
    pre_lex = ColumnTransformer([
        ("num", Pipeline([("imp", SimpleImputer(strategy="median")),
                          ("sc", StandardScaler())]), LEX_COLS)])
    pre_fuse = ColumnTransformer([
        ("num", Pipeline([("imp", SimpleImputer(strategy="median")),
                          ("sc", StandardScaler())]), FEATURES_NUM + LEX_COLS),
        ("cat", OneHotEncoder(handle_unknown="ignore"), FEATURES_CAT)])
    CHANNELS = {"lexical": (pre_lex, LEX_COLS),
                "fusion": (pre_fuse, FEATURES_NUM + FEATURES_CAT + LEX_COLS),
                "infra": (pre_infra, FEATURES_NUM + FEATURES_CAT)}   # infra: descriptive only

    seeds = range(3 if smoke else SEEDS)
    rows, balance = [], {}
    for seed in seeds:
        matched, coverage = match_benign(d, seed)
        use = pd.concat([d[d["arm"] == "phish"], matched])
        use["y"] = (use["arm"] == "phish").astype(int)
        tcol = use["first_detected"].fillna(use["captured_at"])
        use = use.assign(_t=tcol).sort_values("_t").reset_index(drop=True)
        for cut_frac in ((0.70,) if smoke else ROLL_CUTS):
            k = int(cut_frac * len(use))
            tr, te = use.iloc[:k], use.iloc[k:]
            if tr["y"].nunique() < 2 or te["y"].nunique() < 2:
                if not smoke:
                    raise SystemExit("temporal split degenerate — report, do not re-split")
                tr = use.sample(frac=0.7, random_state=0)
                te = use.drop(tr.index)      # smoke only: prove the path runs
            for fam, mk in (("CatBoost", lambda s: CatBoostClassifier(
                                iterations=300, random_seed=s, verbose=False)),
                            ("LogReg", lambda s: LogisticRegression(
                                max_iter=2000, random_state=s))):
                for chan, (pre, cols) in CHANNELS.items():
                    pipe = Pipeline([("pre", pre), ("clf", mk(seed))])
                    pipe.fit(tr[cols], tr["y"])
                    p_tr = pipe.predict_proba(tr[cols])[:, 1]
                    p_te = pipe.predict_proba(te[cols])[:, 1]
                    cal_be = p_tr[tr["y"].to_numpy() == 0]
                    cal_vn = tr.loc[tr["y"] == 0, "is_vn"].to_numpy()
                    q_te = qmap_scores(p_te, te["is_vn"].to_numpy(), cal_be, cal_vn)
                    thr = 1.0 - FPR_BUDGET     # one global threshold in benign-quantile space
                    pred = q_te >= thr
                    yte = te["y"].to_numpy()
                    vn_ph = (yte == 1) & te["is_vn"].to_numpy()
                    n_vn = int(vn_ph.sum())
                    miss_vn = float((~pred[vn_ph]).mean()) if n_vn else float("nan")
                    rows.append({
                        "seed": seed, "cut": cut_frac, "family": fam, "channel": chan,
                        "auc": roc_auc_score(yte, p_te),
                        "recall": float(pred[yte == 1].mean()),
                        "fpr": float(pred[yte == 0].mean()),
                        "miss_vn": miss_vn, "n_vn": n_vn,
                        "tp": int(pred[yte == 1].sum()), "fn": int((~pred[yte == 1]).sum()),
                        "fp": int(pred[yte == 0].sum()), "tn": int((~pred[yte == 0]).sum()),
                        "coverage": coverage})
        # Balance diagnostic (registered non-confirmatory): can a discriminator tell the arms
        # apart from the MATCHING covariates alone? Near 0.5 = matching achieved its purpose.
        if seed == 0:
            for tag, frame in (("before", d), ("after", use)):
                cov = pd.DataFrame({
                    "age": frame["cert_age_days"],
                    "sfx": frame["registered_domain"].map(public_suffix)})
                X = pd.get_dummies(cov, columns=["sfx"])
                y = (frame["arm"] == "phish").astype(int)
                if y.nunique() == 2 and y.sum() >= 5 and (1 - y).sum() >= 5:
                    oof = cross_val_predict(
                        HistGradientBoostingClassifier(random_state=0),
                        X.fillna(-1), y, cv=5, method="predict_proba")[:, 1]
                    balance[tag] = float(roc_auc_score(y, oof))

    res = pd.DataFrame(rows)
    os.makedirs(out_dir, exist_ok=True)
    res.to_csv(os.path.join(out_dir, "p4_main_runs.csv"), index=False)

    # Confirmatory T1: CatBoost fusion vs CatBoost lexical on .vn miss, registered origin only.
    m = res[(res["cut"] == 0.70) & (res["family"] == "CatBoost")]
    piv = m.pivot_table(index="seed", columns="channel", values="miss_vn")
    stat = corrected_paired_t((piv["lexical"] - piv["fusion"]).dropna().values)
    n_vn_te = int(m["n_vn"].median()) if len(m) else 0
    miss_f = piv["fusion"].mean() if "fusion" in piv else float("nan")
    lo, hi = wilson(miss_f * n_vn_te, n_vn_te) if n_vn_te else (float("nan"), float("nan"))

    smoke_banner = ("% SMOKE RUN on randomised arms — pipeline proof only, NEVER a result\n"
                    if smoke else "")
    body = [
        smoke_banner + "\\begin{table}[t]\\centering",
        "\\caption{Main comparison (\\S\\ref{ssec:success}): lexical baseline vs "
        "URL+infrastructure fusion on the matched arms, benign-quantile-mapped scores, one "
        "global threshold at the FPR $\\leq 0.30$ budget; mean$\\pm$std over "
        f"{3 if smoke else SEEDS} seeds at the registered 0.70 origin."
        + (" SMOKE: arms randomised.}" if smoke else "}"),
        "\\label{tab:main}",
        "\\small\\begin{tabular}{llcccc}\\toprule",
        "Family & Channel & ROC-AUC & Recall & \\texttt{.vn} miss & FPR \\\\ \\midrule"]
    for fam in ("CatBoost", "LogReg"):
        for chan in ("lexical", "fusion", "infra"):
            g = res[(res["cut"] == 0.70) & (res["family"] == fam) & (res["channel"] == chan)]
            if not len(g):
                continue
            body.append(
                f"{fam} & {chan} & {g['auc'].mean():.3f}$\\pm${g['auc'].std():.3f} & "
                f"{g['recall'].mean():.3f} & {g['miss_vn'].mean():.3f} & "
                f"{g['fpr'].mean():.3f} \\\\")
    body += [
        "\\midrule",
        f"\\multicolumn{{6}}{{l}}{{T1 (confirmatory): CatBoost lexical$-$fusion "
        f"\\texttt{{.vn}} miss $= {stat['mean']:+.3f}$, corrected $p={stat['p']:.3f}$ "
        f"({stat['wins']}/{stat['k']} seeds; BH over $m{{=}}2$ with the cascade test); "
        f"fusion miss Wilson 95\\% CI $[{lo:.2f}, {hi:.2f}]$, $n_{{vn}}={n_vn_te}$.}} \\\\",
        f"\\multicolumn{{6}}{{l}}{{Matching coverage {res['coverage'].mean():.2f}; balance "
        f"discriminator AUC before/after matching: "
        f"{balance.get('before', float('nan')):.3f} / "
        f"{balance.get('after', float('nan')):.3f} (diagnostic, non-confirmatory).}} \\\\",
        "\\bottomrule\\end{tabular}\\end{table}"]
    write_generated(os.path.join(out_dir, "tab_main.tex"), "\n".join(body) + "\n")
    print(f"[+] {'SMOKE ' if smoke else ''}main comparison -> {out_dir}/tab_main.tex "
          f"(runs CSV beside it; rolling origins {ROLL_CUTS} in the CSV)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--smoke", action="store_true",
                    help="run the fitting path on label-permuted data, writing only to "
                         f"{SMOKE_DIR}/ — proves the machinery without touching the outcome")
    args = ap.parse_args()
    if not os.path.exists(INFRA):
        print(f"[i] {INFRA} absent — sync from the collector first.")
        return 0
    pop, funnel = build_population()
    write_monitoring(pop, funnel)
    n = funnel["phish_conditioned"]
    trusted_pop, outcome_gate = trusted_positive_population(pop, TRIGGER)
    print(f"[+] dataset {DATASET} ({len(pop)} rows); monitoring assets regenerated "
          f"(phish {n}/{TRIGGER} toward trigger, benign[ct] {funnel['benign_conditioned']}, "
          f"comparator[tinnhiem] {funnel[f'{COMPARATOR_ARM}_conditioned']}, not pooled)")
    if args.smoke:
        fit_main(pop, SMOKE_DIR, smoke=True)
    elif n >= TRIGGER and outcome_gate.unlocked:
        fit_main(trusted_pop, SECTIONS, smoke=False)
    else:
        print(f"[i] outcome locked — candidates {n}/{TRIGGER}; {outcome_gate.reason}. "
              f"No real-outcome model is fitted. Expected labels: {OUTCOME_LABELS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
