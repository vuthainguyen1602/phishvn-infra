#!/usr/bin/env python3
"""
make_infra_data_assets.py — the generated assets of the PhishVN-Infra data article (papers/P4b_infra_data).

WHAT THIS IS. A thin wrapper over the population builder the companion infrastructure study ships
(`make_infra_assets.build_population`) and the funnel/accrual CSVs `make_capture_funnel.py` writes. It
DESCRIBES the corpus: file table, per-source row counts, headline counts sentence, feature
availability per arm, the benign arm's certificate-age marginal, and a survivorship sentence from
the capture audit. Every number the article prints comes from here, so it refreshes with the data
until the deposit freezes.

WHAT THIS IS NOT. A results generator. It never imports `fit_main`, prints no model metric,
compares no arm with another: a Data in Brief article describes data, and the companion study is
the one that will test them after its registered trigger. `check_paper_claims.py --paper p4b`
re-derives every count from the CSVs and forbids evaluation vocabulary in the built PDF.

    python scripts/make_infra_data_assets.py

Reads  data/raw/host_infra/host_infra.csv, data/processed/infra/funnel.csv, accrual.csv,
       label_audit.csv and wildcard_probe.csv (both written by build_population),
       data/interim/p4_content_map.csv, data/raw/ct_benign{,_vn}/seen_domains.txt (where
       present), data/processed/dataset_url.csv (the URL corpus, for the overlap count).
Writes papers/P4b_infra_data/sections/{tab_files,tab_sources,gen_counts,gen_macros,
       tab_funnel,tab_verdicts,tab_timestamps,tab_availability,tab_benign_age,gen_perish}.tex
       and papers/P4b_infra_data/figures/{cert_age_by_arm,funnel_accrual_p4b}.pdf. The accrual
       panel is this article's own: observed admissions per detection day and their running total,
       with no trigger line, projection or calendar bound — those belong to the companion study's
       pre-specification, not to a description of a table.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import os
import re
import sys

import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)

from genfile import write_generated
# The population rule is imported, never restated: the deposit must be exactly the population the
# companion study analyses, or the data article describes a different object from the one cited.
from make_infra_assets import (ARM_COLUMNS, COMPARATOR_ARM, FEATURES_CAT,
                            FEATURES_NUM, INFRA, TRIGGER, WATCHER_START, build_population,
                            most_complete)
from make_capture_funnel import accrual_rows, funnel_rows, write_csv
from audit_capture_labels import is_registry_wildcard, registrable

SEC = os.path.join(ROOT, "papers", "P4b_infra_data", "sections")
FIG = os.path.join(ROOT, "papers", "P4b_infra_data", "figures")
PROC = os.path.join(ROOT, "data", "processed")
INTERIM = os.path.join(ROOT, "data", "interim")
FUNNEL_CSV = os.path.join(PROC, "infra", "funnel.csv")
ACCRUAL_CSV = os.path.join(PROC, "infra", "accrual.csv")
DATASET_CSV = os.path.join(PROC, "infra", "infra_dataset.csv")
# Written by build_population (the per-candidate verdict table, with the funnel stage that removed
# each) and by the audit's wildcard probe; both are inputs here, never recomputed.
LABEL_AUDIT_CSV = os.path.join(PROC, "infra", "label_audit.csv")
PROBE_CSV = os.path.join(PROC, "infra", "wildcard_probe.csv")
CONTENT_MAP_CSV = os.path.join(INTERIM, "p4_content_map.csv")
VN_SUPP_CSV = os.path.join(ROOT, "data", "raw", "ct_benign_vn", "detections.csv")
P1_URL_CSV = os.path.join(PROC, "dataset_url.csv")
VN_SUPP_START = "2026-08-21"   # the amendment that registered the .vn supplement (PREREG)
VERDICTS = ("corroborated", "credential_form", "content_confirmed", "vn_lexical",
            "uncorroborated", "no_capture", "excluded_legitimate", "hosted_subdomain",
            "registry_wildcard")
ADMIT_VERDICTS = frozenset(VERDICTS[:4])

SOURCE_LABEL = {
    "vn_phishing_live": ("phish", "national blacklist, live poll"),
    "chongluadao_live": ("phish", "community blocklist, live poll"),
    "urlscan_brands": ("phish", "urlscan brand-token queries"),
    "ct_brands": ("phish", "CT brand-token polling"),
    "tinnhiem_benign": ("benign", "trust-registry comparator"),
    "ct_benign": ("benign", "CT-sampled, TLD- and age-matched"),
    "ct_benign_vn": ("benign", "CT-sampled \\texttt{.vn} supplement"),
}

# Timestamp conventions per source, as the collectors write them (verified 2026-08-21):
# watch_host_infra stamps captured_at with datetime.now(); the urlscan, blacklist, blocklist and
# comparator collectors stamp first_detected with the local clock; the two CT collectors write
# naive UTC; tls_* and whois_* carry +00:00. A source absent from this dict is a bug.
TZ_FIRST = {
    "vn_phishing_live": "naive local", "chongluadao_live": "naive local",
    "urlscan_brands": "naive local", "tinnhiem_benign": "naive local",
    "ct_brands": "naive UTC", "ct_benign": "naive UTC", "ct_benign_vn": "naive UTC",
}

# The deposit, as PLAN §3 fixes it: (path in the zip, local file or None, unit, contents). Row
# counts come from the local file; a source that has not written its first row prints 0.
DEPOSIT = [
    ("README.md", None, "", "Overview, composition counts, usage notes"),
    ("LICENSE", None, "", "CC BY 4.0 licence text"),
    ("CITATION.cff", None, "", "Machine-readable citation metadata"),
    ("MANIFEST.txt", None, "", "SHA-256 checksum and byte size of every file"),
    ("data/host_infra.csv", os.path.join(ROOT, INFRA), "rows",
     "Every capture row, all sources (25 columns)"),
    ("data/infra_dataset.csv", DATASET_CSV, "rows",
     "Conditioned population, arm and verdict (15 columns)"),
    ("data/funnel.csv", FUNNEL_CSV, "rows", "Phishing-arm funnel: stage, surviving, removed"),
    ("data/accrual.csv", ACCRUAL_CSV, "rows", "Cumulative admitted domains by detection day"),
    ("data/label_audit.csv", LABEL_AUDIT_CSV, "rows",
     "Verdict, evidence flags, removal stage per candidate"),
    ("data/wildcard_probe.csv", PROBE_CSV, "rows",
     "Wildcard probe: suffix, probe name, date, answers"),
    ("data/ct_benign_seen.txt", os.path.join(ROOT, "data", "raw", "ct_benign", "seen_domains.txt"),
     "lines", "Matched-arm sampler seen-set"),
    ("data/ct_benign_vn_seen.txt",
     os.path.join(ROOT, "data", "raw", "ct_benign_vn", "seen_domains.txt"), "lines",
     "\\texttt{.vn}-supplement sampler seen-set"),
    ("docs/datasheet.md", None, "", "Datasheet, incl.\\ the five artefacts and the amendment"),
    ("docs/schema.md", None, "", "Column dictionary for both CSV schemas"),
    ("docs/collection_protocol.md", None, "",
     "Collectors, cadence, age rotation, exclusions, gate"),
    ("docs/CHANGELOG.md", None, "", "Version history"),
]


def count_rows(path: str, unit: str) -> int | None:
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        if unit == "rows":
            return sum(1 for _ in csv.reader(f)) - 1
        return sum(1 for ln in f if ln.strip())


def tex_path(p: str) -> str:
    return "\\texttt{" + p.replace("_", "\\_") + "}"


def fmt(n: int) -> str:
    return f"{n:,}".replace(",", "{,}")


def write_files_table() -> dict[str, int]:
    counts: dict[str, int] = {}
    out = io.StringIO()
    out.write("\\begin{table}[h]\n\\centering\\footnotesize\n\\setlength{\\tabcolsep}{4pt}\n"
              "\\caption{Repository structure: every file in "
              "\\nolinkurl{PhishVN-Infra_v1.0.0_open.zip}, with its size or row count at the "
              "build snapshot.}\n\\label{tab:files}\n"
              "\\begin{tabular}{@{}l l l@{}}\n\\toprule\nPath & Size/count & Contents \\\\\n"
              "\\midrule\n")
    for path, local, unit, what in DEPOSIT:
        n = count_rows(local, unit) if unit else None
        if not unit:
            size = "n/a"
        else:
            n = n or 0
            counts[path] = n
            size = f"{fmt(n)} {unit}"
        out.write(f"\\quad{tex_path(path)} & {size} & {what} \\\\\n")
    out.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")
    write_generated(os.path.join(SEC, "tab_files.tex"), out.getvalue())
    return counts


def write_sources_table(df: pd.DataFrame, pop: pd.DataFrame) -> None:
    """Rows per source as collected, and what each contributes to the conditioned population."""
    out = io.StringIO()
    out.write("\\begin{table}[h]\n\\centering\\footnotesize\n"
              "\\caption{Sources in \\nolinkurl{host_infra.csv} at the build snapshot: capture "
              "rows, distinct hostnames, and the registrable domains each source contributes to "
              "the conditioned population.}\n\\label{tab:sources}\n"
              "\\begin{tabular}{@{}l l l r r r@{}}\n\\toprule\n"
              "Source & Label & Channel & Rows & Hostnames & Conditioned \\\\\n\\midrule\n")
    present = list(df["source"].value_counts().index)
    order = [s for s in SOURCE_LABEL if s in present] + sorted(set(present) - set(SOURCE_LABEL))
    for src in order:
        label, channel = SOURCE_LABEL.get(src, ("", "other"))
        sub = df[df["source"] == src]
        n_pop = int((pop["source"] == src).sum())
        out.write(f"{tex_path(src)} & {label or sub['label'].iloc[0]} & {channel} & "
                  f"{fmt(len(sub))} & {fmt(sub['domain'].nunique())} & {fmt(n_pop)} \\\\\n")
    out.write("\\midrule\nAll sources & & & "
              f"{fmt(len(df))} & {fmt(df['domain'].nunique())} & {fmt(len(pop))} \\\\\n"
              "\\bottomrule\n\\end{tabular}\n")
    # A near-empty row in a data descriptor invites exactly one question, so answer it in place.
    # The number is computed, not typed: whichever source is dry, and for how long, is read off the
    # data rather than asserted, so this note cannot go stale the way a hand-written date would.
    if len(df):
        last = (df.groupby("source")["captured_at"].max()
                  .sort_values())
        dry_src = last.index[0]
        dry_rows = int((df["source"] == dry_src).sum())
        if dry_rows < 0.001 * len(df):
            since = str(last.iloc[0])[:10]
            days = (pd.to_datetime(df["captured_at"].max()) - pd.to_datetime(last.iloc[0])).days
            # The last run's own summary line, not a remembered diagnosis. "HTTP 502" and
            # "fourteen unreachable" were hard-coded here and both went stale: crt.sh now answers
            # 404 from one host and 502 from another, and the failing-token count moved to 21 of
            # 34 while 13 tokens answered and genuinely found nothing. A note that asserts a
            # failure mode it is not reading is the hand-written date this comment warns about.
            queried = failed = new_cands = None
            log_path = os.path.join("data", "raw", dry_src, "watch.log")
            if os.path.exists(log_path):
                for line in open(log_path, encoding="utf-8", errors="replace"):
                    m = re.search(r"(\d+)/(\d+) tokens queried.*?-> (\d+) new candidate domains"
                                  r"(?:.*?\| (\d+) FAILED)?", line)
                    if m:
                        queried, new_cands = int(m.group(2)), int(m.group(3))
                        failed = int(m.group(4)) if m.group(4) else 0
            if queried:
                answered = queried - (failed or 0)
                upstream = (f"{failed} of its {queried} brand tokens came back unreachable after "
                            f"retries, and the {answered} that did answer yielded "
                            f"\\texttt{{{new_cands} new candidate domains}}"
                            if failed else
                            f"all {queried} tokens answered and yielded "
                            f"\\texttt{{{new_cands} new candidate domains}}")
            else:
                upstream = ("its run log records no summary line, so the split between an "
                            "unreachable upstream and an empty answer cannot be stated here")
            out.write(
                "\n\\noindent\\footnotesize\n"
                f"\\textit{{Note.}} \\nolinkurl{{{dry_src}}} holds {fmt(dry_rows)} rows because it has "
                f"produced nothing since {since}, {days} days before this snapshot. The collector runs on "
                "schedule and exits cleanly; its upstream, the certificate-transparency search at "
                "\\nolinkurl{crt.sh}, has been degraded rather than absent. On the most recent run "
                f"{upstream}. The row is reported at its true value rather than dropped: a source that ran "
                "and found nothing is a different fact from one that was never run, and a data descriptor "
                "that silently omits the first is describing a corpus it does not have.\\normalsize\n")
    out.write("\\end{table}\n")
    write_generated(os.path.join(SEC, "tab_sources.tex"), out.getvalue())


def write_counts(df: pd.DataFrame, pop: pd.DataFrame, funnel: dict) -> dict:
    """The headline-count sentence. Every value is also written as a `% key=value` header line
    so the claims checker can compare each one against its own recomputation from the CSVs.
    Returns the keys, which write_macros turns into the prose macros the sections share."""
    fun = list(csv.DictReader(open(FUNNEL_CSV, newline="", encoding="utf-8")))
    live = int(fun[0]["surviving"])
    hosted = next(r for r in fun if r["stage"].startswith("less hosted"))
    wild = next(r for r in fun if r["stage"].startswith("less registry"))
    gate = next(r for r in fun if r["stage"] == "label gate")
    final = int(fun[-1]["surviving"])
    n_hosted, n_wild, n_gate = int(hosted["removed"]), int(wild["removed"]), int(gate["surviving"])
    wild_share = round(100 * n_wild / int(hosted["surviving"]))

    cap = pd.to_datetime(df["captured_at"], errors="coerce")
    first_cap, last_cap = cap.min().date(), cap.max().date()
    n_rows, n_hosts = len(df), int(df["domain"].nunique())
    n_sources = int(df["source"].nunique())
    ph = pop[pop["arm"] == "phish"]
    be = pop[pop["arm"] == "benign"]
    cmp_ = pop[pop["arm"] == COMPARATOR_ARM]
    n_be, n_cmp = len(be), len(cmp_)
    ph_vn = int(ph["registered_domain"].astype(str).str.endswith(".vn").sum())
    be_vn = int(be["registered_domain"].astype(str).str.endswith(".vn").sum())
    assert final == len(ph) == funnel["phish_conditioned"]

    keys = {"rows": n_rows, "hosts": n_hosts, "sources": n_sources,
            "first_cap": first_cap.isoformat(), "last_cap": last_cap.isoformat(),
            "live": live, "hosted": n_hosted, "after_hosted": int(hosted["surviving"]),
            "wild": n_wild, "wild_share": wild_share,
            "wild_share_all": round(100 * n_wild / live),
            "gate": n_gate, "phish": final, "phish_vn": ph_vn,
            "benign": n_be, "benign_vn": be_vn, "comparator": n_cmp}
    header = "".join(f"% {k}={v}\n" for k, v in keys.items())
    body = (
        f"As of the build date (last capture {last_cap.isoformat()}), "
        f"\\texttt{{host\\_infra.csv}} holds {fmt(n_rows)} capture rows over {fmt(n_hosts)} "
        f"distinct hostnames from {n_sources} sources, captured between "
        f"{first_cap.isoformat()} and {last_cap.isoformat()}. In the live stratum (domains first "
        f"detected on or after {WATCHER_START.date().isoformat()}, the day the watcher started) "
        f"the phishing feeds contributed {fmt(live)} candidate registrable domains. Of these, "
        f"{n_hosted} were hosted subdomains; of the {fmt(int(hosted['surviving']))} left after "
        f"that screen, {fmt(n_wild)} ({wild_share}\\%) were registry-wildcard resolutions; "
        f"{n_gate} passed the label gate and "
        f"{final} of those resolved and served TLS at capture, {ph_vn} of them under "
        f"\\texttt{{.vn}}. The matched benign arm (\\texttt{{ct\\_benign}}) holds {fmt(n_be)} "
        f"conditioned registrable domains, {be_vn} of them under \\texttt{{.vn}}, and the "
        f"trust-registry comparator (\\texttt{{tinnhiem\\_benign}}) {n_cmp}; the two are never "
        f"pooled.\n")
    write_generated(os.path.join(SEC, "gen_counts.tex"), header + body)
    print(f"[i] counts: rows {n_rows:,}, live {live:,} -> gate {n_gate} -> conditioned {final} "
          f"(.vn {ph_vn}); benign {n_be} (.vn {be_vn}); comparator {n_cmp}")
    return keys


def write_macros(keys: dict, extra: dict[str, str]) -> dict[str, str]:
    """Prose macros shared by every section (names are a contract with the section authors and
    with check_p4b, which requires every macro defined here to be used). Numbers carry thin-space
    thousands separators, dates are ISO, shares are bare percents. No rate and no projection: the
    article reports observed accrual and leaves forecasting to the companion study."""
    supp = count_rows(VN_SUPP_CSV, "rows") or 0
    mapped = count_rows(CONTENT_MAP_CSV, "rows") or 0
    vn_share = round(100 * keys["phish_vn"] / max(keys["phish"], 1))
    macros = {
        "PbBuildDate": keys["last_cap"], "PbWindowStart": keys["first_cap"],
        "PbWindowEnd": keys["last_cap"], "PbRawRows": fmt(keys["rows"]),
        "PbCandidates": fmt(keys["live"]), "PbHosted": fmt(keys["hosted"]),
        "PbAfterHosted": fmt(keys["after_hosted"]),
        "PbWildcard": fmt(keys["wild"]), "PbWildcardShare": str(keys["wild_share"]),
        "PbWildcardShareOfAll": str(keys["wild_share_all"]),
        "PbGateKept": fmt(keys["gate"]), "PbGateRemoved": fmt(keys["after_hosted"]
                                                              - keys["wild"] - keys["gate"]),
        "PbAdmitted": fmt(keys["phish"]),
        "PbTriggerN": fmt(TRIGGER), "PbVnPhish": fmt(keys["phish_vn"]),
        "PbVnPhishShare": str(vn_share), "PbBenignCT": fmt(keys["benign"]),
        "PbBenignCTvn": fmt(keys["benign_vn"]), "PbBenignVnSupp": fmt(supp),
        "PbVnSuppStart": VN_SUPP_START,
        "PbComparator": fmt(keys["comparator"]), "PbContentMapped": fmt(mapped),
    }
    macros.update(extra)
    body = "% generated by scripts/make_infra_data_assets.py; do not edit\n" + "".join(
        f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in macros.items())
    write_generated(os.path.join(SEC, "gen_macros.tex"), body)
    return macros


def p1_overlap(df: pd.DataFrame, pop: pd.DataFrame) -> dict[str, str]:
    """Registrable domains the capture table shares with the PhishVN URL corpus, raw and
    per conditioned arm. The comparator overlaps by design (it re-measures that corpus' trust-registry
    benign source); the phishing arm is expected to be disjoint because the live stratum begins
    after that corpus was frozen. Both are counted, not assumed."""
    if not os.path.exists(P1_URL_CSV):
        return {}
    u = pd.read_csv(P1_URL_CSV, low_memory=False, usecols=["domain", "channel"])
    p1 = set(u.loc[u["channel"] == "url", "domain"].dropna().astype(str).map(registrable)) - {""}
    raw = set(df["domain"].astype(str).map(registrable)) - {""}
    out = {"PbPOneDomains": fmt(len(p1)), "PbPOneOverlapRaw": fmt(len(p1 & raw))}
    for arm, name in (("phish", "Phish"), ("benign", "Benign"), (COMPARATOR_ARM, "Comparator")):
        out[f"PbPOneOverlap{name}"] = fmt(len(p1 & set(pop.loc[pop["arm"] == arm,
                                                                 "registered_domain"])))
    print("[i] URL-corpus overlap: " + ", ".join(f"{k}={v}" for k, v in out.items()))
    return out


def whois_gap(df: pd.DataFrame, pop: pd.DataFrame) -> dict[str, str]:
    """How far a registry's publication policy alone moves the single bit "has any WHOIS field".
    VNNIC publishes neither WHOIS nor RDAP, so the bit is empty for every `.vn` domain whatever
    it is; outside `.vn` it is usually present. Background states the size of that gap, and it
    has to be measured rather than asserted: an arm whose `.vn` share differs from the other's
    differs on this bit before any property of the domains is considered. Descriptive shares,
    not a separability score -- this is a data article."""
    cols = [c for c in ("whois_created", "whois_expires", "whois_updated", "registrar",
                        "whois_age_days") if c in df.columns]
    if not cols or pop.empty:
        return {}
    has = df.groupby("registered_domain")[cols].apply(lambda g: g.notna().any().any())
    p = pop.assign(any_whois=pop["registered_domain"].map(has).fillna(False),
                   is_vn=pop["registered_domain"].astype(str).str.endswith(".vn"))
    vn = p[p["is_vn"]]
    out = {"PbWhoisVnDomains": fmt(len(vn)),
           "PbWhoisVnPresent": fmt(int(vn["any_whois"].sum()))}
    for arm, name in (("benign", "Benign"), ("phish", "Phish")):
        sub = p[(p["arm"] == arm) & ~p["is_vn"]]
        out[f"PbWhoisNonVn{name}"] = str(round(100 * sub["any_whois"].mean())) if len(sub) else "0"
    print("[i] WHOIS gap: " + ", ".join(f"{k}={v}" for k, v in out.items()))
    return out


def write_funnel_table() -> None:
    """The phishing-arm funnel, one row per stage, straight from funnel.csv."""
    fun = list(csv.DictReader(open(FUNNEL_CSV, newline="", encoding="utf-8")))
    out = io.StringIO()
    out.write("\\begin{table}[h]\\centering\\footnotesize\n"
              "\\caption{The phishing-arm funnel (\\nolinkurl{funnel.csv}) at the build snapshot: "
              "live-stratum registrable domains surviving each stage, in the order applied, and "
              "the number each stage removed.}\n\\label{tab:funnel}\n"
              "\\begin{tabular}{@{}l r r l@{}}\\toprule\n"
              "Stage & Surviving & Removed & Note \\\\ \\midrule\n")
    for r in fun:
        removed = fmt(int(r["removed"])) if r["removed"] else "--"
        out.write(f"{r['stage']} & {fmt(int(r['surviving']))} & {removed} & {r['note']} \\\\\n")
    out.write("\\bottomrule\\end{tabular}\\end{table}\n")
    write_generated(os.path.join(SEC, "tab_funnel.tex"), out.getvalue())


def write_verdicts_table(df: pd.DataFrame) -> None:
    """Per-source x verdict counts of the live-stratum phishing candidates, from the audit table
    build_population wrote. A registrable domain is attributed to the source that detected it
    first (earliest first_detected; ties broken by source name), so the rows add to the
    candidate count. Descriptive: it shows what each feed's rows become under the gate, it
    evaluates no feed."""
    aud = pd.read_csv(LABEL_AUDIT_CSV)
    ph = df[(df["label"] == "phish")].copy()
    ph["registered_domain"] = ph["domain"].map(registrable)
    ph["fd"] = pd.to_datetime(ph["first_detected"], errors="coerce")
    ph = ph[ph["fd"] >= WATCHER_START].sort_values(["fd", "source"])
    first_src = ph.drop_duplicates("registered_domain").set_index("registered_domain")["source"]
    aud["source"] = aud["registered_domain"].map(first_src).fillna("unknown")
    srcs = [s for s in SOURCE_LABEL if s in set(aud["source"])] + sorted(
        set(aud["source"]) - set(SOURCE_LABEL))
    cols = [v for v in VERDICTS if (aud["verdict"] == v).any()]
    # VERDICTS lists the admitting classes first; an absent class drops its column, so the
    # caption counts the admitting columns actually printed rather than asserting "four".
    n_admit = sum(1 for v in cols if v in ADMIT_VERDICTS)
    n_word = {1: "one", 2: "two", 3: "three", 4: "four"}.get(n_admit, str(n_admit))
    out = io.StringIO()
    out.write("\\begin{table}[h]\\centering\\footnotesize\n\\setlength{\\tabcolsep}{3.5pt}\n"
              "\\caption{Label-gate verdicts of the live-stratum phishing candidates "
              f"(\\nolinkurl{{label_audit.csv}}) by first-detecting source; the first {n_word} "
              "classes admit, the rest are removed and counted.}\n\\label{tab:verdicts}\n"
              "\\begin{tabular}{@{}l" + "r" * (len(cols) + 1) + "@{}}\\toprule\n"
              "Source & " + " & ".join("\\rotatebox{90}{\\texttt{" + v.replace("_", "\\_")
                                      + "}}" for v in cols) + " & total \\\\ \\midrule\n")
    for src in srcs:
        sub = aud[aud["source"] == src]
        cells = [fmt(int((sub["verdict"] == v).sum())) for v in cols]
        out.write(tex_path(src) + " & " + " & ".join(cells) + f" & {fmt(len(sub))} \\\\\n")
    out.write("\\midrule\nall & " + " & ".join(fmt(int((aud["verdict"] == v).sum()))
                                                 for v in cols)
              + f" & {fmt(len(aud))} \\\\\n\\bottomrule\\end{{tabular}}\\end{{table}}\n")
    write_generated(os.path.join(SEC, "tab_verdicts.tex"), out.getvalue())
    assert len(aud) == aud["verdict"].isin(VERDICTS).sum()


def write_timestamps_table(df: pd.DataFrame) -> None:
    """Which zone each timestamp column is written in, per source, from TZ_FIRST: the one table a
    user needs before subtracting any two columns. Every source in the capture must be listed."""
    present = [s for s in SOURCE_LABEL if s in set(df["source"])]
    missing = set(df["source"]) - set(TZ_FIRST)
    assert not missing, f"TZ_FIRST lacks {missing}"
    out = io.StringIO()
    out.write("\\begin{table}[h]\\centering\\footnotesize\n"
              "\\caption{Timestamp conventions of \\nolinkurl{host_infra.csv} by source; "
              "``naive'' means no offset is written, ``local'' is the collector's clock "
              "(Asia/Ho\\_Chi\\_Minh, UTC+7).}\n\\label{tab:timestamps}\n"
              "\\setlength{\\tabcolsep}{4pt}\\begin{tabular}{@{}l l l l l@{}}\\toprule\n"
              "Source & \\texttt{first\\_detected} & \\texttt{captured\\_at} & "
              "\\texttt{tls\\_not\\_before/after} & \\texttt{whois\\_*} \\\\ \\midrule\n")
    for src in present:
        out.write(f"{tex_path(src)} & {TZ_FIRST[src]} & naive local & UTC, offset written & "
                  "UTC, offset written \\\\\n")
    out.write("\\bottomrule\\end{tabular}\\end{table}\n")
    write_generated(os.path.join(SEC, "tab_timestamps.tex"), out.getvalue())


def write_availability(pop: pd.DataFrame) -> None:
    """Same logic as make_infra_assets.write_monitoring's availability table, captioned for a data
    user rather than for a pre-specification."""
    out = io.StringIO()
    out.write("\\begin{table}[h]\\centering\\footnotesize\n"
              "\\caption{Share of conditioned registrable domains, per arm, with each derived "
              "field of \\nolinkurl{infra_dataset.csv} populated.}\n"
              "\\label{tab:availability}\n"
              "\\begin{tabular}{lccc}\\toprule\n"
              "Field & " + " & ".join(h for _, h in ARM_COLUMNS) + " \\\\ \\midrule\n")
    for feat in FEATURES_NUM + FEATURES_CAT:
        row = []
        for arm, _ in ARM_COLUMNS:
            sub = pop[pop["arm"] == arm][feat]
            ok = sub.notna() & (sub.astype(str).str.strip() != "")
            row.append(f"{100 * ok.mean():.0f}\\%" if len(sub) else "--")
        out.write("\\texttt{" + feat.replace("_", "\\_") + "} & " + " & ".join(row) + " \\\\\n")
    out.write("\\bottomrule\\end{tabular}\\end{table}\n")
    write_generated(os.path.join(SEC, "tab_availability.tex"), out.getvalue())


def write_benign_age(pop: pd.DataFrame) -> None:
    be_age = pop[(pop["arm"] == "benign")][["captured_at", "cert_age_days"]].dropna()
    # Three regimes, not two. 2026-08-16: the cron went hourly, so `hour % 4` could finally visit all
    # four targets. 2026-08-24: those four turned out to sit inside ONE quartile of the phishing arm's
    # certificate age, starving three matching cells, so the rotation widened to six. A reader
    # matching on certificate age has to know which window a row came from.
    fix, widen = pd.Timestamp("2026-08-16"), pd.Timestamp("2026-08-24")
    rows = []
    for label, sub in (("collected before 2026-08-16 (target age pinned at 1\\,d)",
                        be_age[be_age["captured_at"] < fix]),
                       ("2026-08-16 to 2026-08-23 (rotation over 1/3/7/14\\,d)",
                        be_age[(be_age["captured_at"] >= fix)
                               & (be_age["captured_at"] < widen)]),
                       ("collected 2026-08-24 or later (rotation over 0.4/5/0.8/25/45/75\\,d)",
                        be_age[be_age["captured_at"] >= widen])):
        if len(sub):
            q = sub["cert_age_days"].quantile([0.25, 0.5, 0.75])
            rows.append(f"{label} & {fmt(len(sub))} & {q[0.25]:.1f} & {q[0.5]:.1f} & "
                        f"{q[0.75]:.1f} \\\\")
        else:
            rows.append(f"{label} & 0 & -- & -- & -- \\\\")
    write_generated(
        os.path.join(SEC, "tab_benign_age.tex"),
        "\\begin{table}[h]\\centering\\footnotesize\n"
        "\\caption{Certificate age at capture in the conditioned \\nolinkurl{ct_benign} arm "
        "(rows with a certificate), across the three regimes of the sampler's age rotation: "
        "pinned, repaired, then widened; quartiles in days.}\n"
        "\\label{tab:benignage}\n"
        "\\begin{tabular}{lcccc}\\toprule\n"
        "Collection window & $n$ & Q1 & median & Q3 \\\\ \\midrule\n"
        + "\n".join(rows) + "\n\\bottomrule\\end{tabular}\\end{table}\n")


def write_perish(df: pd.DataFrame) -> None:
    """Resolvability at capture per stratum, on the phishing arm, counted in HOSTS (one record
    per hostname, the most complete attempt) and with registry-wildcard hosts left out: a
    wildcard name resolves whether or not anyone registered it, so counting it would credit the
    registry's parking answer to the campaign. Descriptive, single-arm, no outcome."""
    ph = df[df["label"] == "phish"].copy()
    ph["fd"] = pd.to_datetime(ph["first_detected"], errors="coerce")
    ph = ph.dropna(subset=["fd"])
    best = ph.groupby("domain", group_keys=False)[ph.columns].apply(most_complete)
    best["stratum"] = (best["fd"] >= WATCHER_START).map({True: "live", False: "backfill"})
    ips = best["a_records"].fillna("").astype(str).map(
        lambda s: frozenset(x.strip() for x in s.split(";") if x.strip()))
    regs = best["domain"].map(registrable)
    wild = pd.Series([bool(i) and is_registry_wildcard(r, i) for r, i in zip(regs, ips)],
                     index=best.index)
    best, ips = best[~wild], ips[~wild]
    n_wild = int(wild.sum())
    agg = {}
    for stratum in ("live", "backfill"):
        m = best["stratum"] == stratum
        agg[stratum] = (int(m.sum()), int(ips[m].astype(bool).sum()))
    live, back = agg["live"], agg["backfill"]
    body = (f"On the phishing arm at the build snapshot, counting hostnames once each (most "
            f"complete attempt) and leaving out the {fmt(n_wild)} registry-wildcard hosts, "
            f"{100 * live[1] / max(live[0], 1):.1f}\\% of the {fmt(live[0])} live-stratum hosts "
            f"answered with an A record when enriched, against "
            f"{100 * back[1] / max(back[0], 1):.1f}\\% of the {fmt(back[0])} backfill hosts "
            f"(detected before the watcher started and reached days later)%\n")
    write_generated(os.path.join(SEC, "gen_perish.tex"), body)
    print(f"[i] perishability (hosts, wildcards out): live {live[1]}/{live[0]}, "
          f"backfill {back[1]}/{back[0]}, wildcard hosts {n_wild}")


def write_cert_age_figure(pop: pd.DataFrame) -> None:
    """Certificate age at capture per arm, as three empirical cumulative curves on a log axis.

    One panel, one variable, three files' worth of rows; nothing is fitted and no arm is scored
    against another. The log axis is forced by the comparator: a standing registry list carries
    certificates months to years old beside two arms sampled at days, and a linear axis would
    flatten both sampled arms into the first bin. Curves are direct-labelled at their right end
    (figstyle rule: colour is never the sole encoding), with the arm's n so the figure states
    its own support."""
    from figstyle import apply, BLUE, GRAY, ORANGE
    plt = apply()
    import numpy as np

    series = (("phish", "phishing", ORANGE),
              ("benign", "ct_benign", BLUE),
              (COMPARATOR_ARM, "tinnhiem_benign", GRAY))
    fig, ax = plt.subplots(figsize=(5.2, 3.0))
    for arm, name, colour in series:
        x = pd.to_numeric(pop.loc[pop["arm"] == arm, "cert_age_days"], errors="coerce").dropna()
        x = x[x > 0].sort_values().to_numpy()
        if not len(x):
            continue
        y = np.arange(1, len(x) + 1) / len(x)
        ax.step(x, y, where="post", color=colour, lw=1.6, zorder=3)
        # Direct labels stacked in the empty top-left corner: the curves converge at the top
        # right, so a label at each line's end sat on the other two lines.
        k = [a for a, _, _ in series].index(arm)
        ax.text(0.03, 0.96 - 0.075 * k, f"{name} (n = {len(x):,})", transform=ax.transAxes,
                fontsize=7.5, color=colour, ha="left", va="top")
    ax.set_xscale("log")
    ax.set_xlim(left=max(ax.get_xlim()[0], 0.02))
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("certificate age at capture, days (log axis)")
    ax.set_ylabel("share of the arm at or below this age")
    ax.grid(axis="both", alpha=0.6)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    os.makedirs(FIG, exist_ok=True)
    out = os.path.join(FIG, "cert_age_by_arm.pdf")
    fig.savefig(out)
    plt.close(fig)
    print(f"[+] figure written: {os.path.relpath(out, ROOT)}")


def write_funnel_accrual_figure() -> None:
    """This article's own two-panel figure. Left: the funnel of funnel.csv, as the companion
    draws it (same stages, same colouring of the artefact stage). Right: OBSERVED accrual only,
    admitted conditioned phishing registrable domains per detection day as bars and their running
    total as a line, read from accrual.csv. No trigger line, no projection, no calendar bound:
    a data article reports what was collected, not when a study expects to start."""
    from figstyle import apply, BLUE, INK, ORANGE
    plt = apply()
    fun = [{"stage": r["stage"], "surviving": int(r["surviving"]),
            "removed": int(r["removed"]) if r["removed"] else ""}
           for r in csv.DictReader(open(FUNNEL_CSV, newline="", encoding="utf-8"))]
    acc = [(dt.date.fromisoformat(r["date"]), int(r["cumulative"]))
           for r in csv.DictReader(open(ACCRUAL_CSV, newline="", encoding="utf-8"))]

    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(7.5, 3.2),
                                  gridspec_kw={"width_ratios": [1.15, 1]})
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
    ax.set_xlabel("registrable domains surviving the stage")
    ax.set_title("the phishing-arm funnel", fontsize=8.5)
    ax.grid(axis="x", alpha=0.6)

    # Per-day admissions on every calendar day of the window: a day without a row in
    # accrual.csv is a day on which no admitted domain was first detected.
    days = [acc[0][0] + dt.timedelta(days=i) for i in range((acc[-1][0] - acc[0][0]).days + 1)]
    cum = dict(acc)
    running, prev, daily, series = 0, 0, [], []
    for d in days:
        running = cum.get(d, running)
        daily.append(running - prev)
        series.append(running)
        prev = running
    ax2.bar(days, daily, width=0.8, color=BLUE, alpha=0.55, zorder=3)
    ax2.set_ylabel("admitted per detection day")
    # The year moves here when the ticks lose it to the short day-month format, so the panel
    # still says which year it covers without a reader going to the prose.
    ax2.set_xlabel(f"detection date ({acc[0][0].year})")
    ax3 = ax2.twinx()
    ax3.plot(days, series, "-", color=INK, lw=1.4, zorder=4)
    ax3.set_ylabel("running total")
    ax3.set_ylim(0, max(series) * 1.35)
    ax2.set_ylim(0, max(daily) * 1.35)
    # Direct labels (figstyle rule: colour is never the sole encoding): the bar label sits over
    # the tallest early bar, the line label at the line's end.
    ax2.annotate("admitted that day", (days[daily.index(max(daily))], max(daily)),
                 textcoords="offset points", xytext=(6, 4), fontsize=7, color=BLUE, ha="left")
    ax3.annotate("running total", (days[-1], series[-1]), textcoords="offset points",
                 xytext=(-2, 6), fontsize=7, color=INK, ha="right")
    ax2.set_title("observed accrual", fontsize=8.5)
    ax2.grid(axis="y", alpha=0.6)
    # Matplotlib's automatic date ticks put ten full ISO dates on a 3.2in panel and, rotated,
    # they overprinted each other end to end (2026-09-02). Weekly ticks in day-month form: six
    # short labels instead of ten long ones, and the axis title still says what the unit is.
    import matplotlib.dates as mdates
    ax2.xaxis.set_major_locator(mdates.DayLocator(interval=7))
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))
    for lab in ax2.get_xticklabels():
        lab.set_rotation(30)
        lab.set_ha("right")
    for a in (ax, ax2):
        a.spines[["top", "right"]].set_visible(False)
    ax3.spines[["top"]].set_visible(False)
    fig.tight_layout()
    os.makedirs(FIG, exist_ok=True)
    out = os.path.join(FIG, "funnel_accrual_p4b.pdf")
    fig.savefig(out)
    plt.close(fig)
    stale = os.path.join(FIG, "funnel_accrual.pdf")
    if os.path.exists(stale):
        os.remove(stale)   # the companion's burn-down figure must not linger in this article
    print(f"[+] figure written: {os.path.relpath(out, ROOT)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    os.chdir(ROOT)   # make_infra_assets addresses its inputs relative to the repository root
    for p in (INFRA, FUNNEL_CSV, ACCRUAL_CSV):
        if not os.path.exists(p):
            print(f"[!] {p} absent; sync the collector and run make_capture_funnel.py first",
                  file=sys.stderr)
            return 1
    df = pd.read_csv(INFRA, low_memory=False)
    pop, funnel = build_population()   # also writes label_audit.csv and wildcard_probe.csv
    # The funnel and accrual CSVs are rewritten from THIS population with the companion's own
    # functions: the wildcard screen live-resolves a candidate that never recorded an address, so two
    # builds minutes apart can differ by a domain, and every number here must come from one build.
    write_csv(FUNNEL_CSV, funnel_rows(funnel))
    write_csv(ACCRUAL_CSV, accrual_rows(pop))
    os.makedirs(SEC, exist_ok=True)
    write_files_table()
    write_sources_table(df, pop)
    keys = write_counts(df, pop, funnel)
    write_perish(df)
    extra = p1_overlap(df, pop)
    extra.update(whois_gap(df, pop))
    macros = write_macros(keys, extra)
    print("[i] macros: " + ", ".join(f"{k}={v}" for k, v in macros.items()))
    write_funnel_table()
    write_verdicts_table(df)
    write_timestamps_table(df)
    write_availability(pop)
    write_benign_age(pop)
    write_cert_age_figure(pop)
    write_funnel_accrual_figure()
    print(f"[+] assets -> {os.path.relpath(SEC, ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
