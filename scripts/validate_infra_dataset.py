#!/usr/bin/env python3
"""
validate_infra_dataset.py — the technical validation a data paper owes its reader.

Four questions, none of which the corpus answered in one place before this file existed.

1. HOW COMPLETE IS EACH RAW FIELD? `tab_availability` already reports the conditioned file's
   derived features. Nobody had reported the 25 columns of `host_infra.csv` itself, which is the
   file a reader downloads and joins against.

2. WHAT SUCCEEDED, GIVEN WHAT COULD HAVE? Marginal rates mislead here: TLS cannot succeed on a
   name that does not resolve, so a flat "49% have certificate data" reads as an instrument
   failure when it is mostly names that were already gone. The chain is reported conditionally --
   resolved, then handshake given resolution, then certificate data given handshake -- so the
   reader can see which stage actually loses rows.

3. WHAT IS A DUPLICATE HERE? Two different things, and conflating them miscounts the corpus.
   `attempt` 2 and 3 are deliberate re-visits of the same name (the perishability arm). Separately,
   `registered_domain` is not one-to-one with hostname: thanhhoa.gov.vn alone appears under 591
   distinct hostnames, and 3,096 registrable domains carry more than one. The conditioned file is
   one row per registrable domain, so it collapses both, and the ratio belongs in the paper.

4. DOES THE CONDITIONED FILE MATCH THE RULES IT CLAIMS? Every check here is a rule stated in the
   design, re-derived from the raw file: one row per registrable domain, no domain invented, the
   live-stratum restriction applied to the phishing arm and not to the comparators, and the
   surviving row chosen for completeness rather than for being first. Each prints its count, so a
   check that passes for the wrong reason is visible rather than silent.

    python scripts/validate_infra_dataset.py
"""
from __future__ import annotations

import io
import os
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
from make_capture_lag import first_capture, load, strata

POP = os.path.join(ROOT, "data", "processed", "infra", "infra_dataset.csv")
OUT = os.path.join(ROOT, "data", "processed", "infra", "validation.csv")
SEC = os.path.join(ROOT, "papers", "P4b_infra_data", "sections")
TRUE = ("1", "true", "yes", "t")


def filled(df: pd.DataFrame, col: str) -> pd.Series:
    s = df[col].astype(str).str.strip().str.lower()
    return (s != "") & (s != "nan") & (s != "none")


#: added by load()/strata() for the analysis, not columns of the published file
DERIVED = ("lag_h", "stratum")


def completeness(raw: pd.DataFrame) -> pd.DataFrame:
    """Completeness of the columns host_infra.csv actually ships. Reporting a column this
    pipeline invented would tell a reader nothing about the file they download."""
    cols = [c for c in raw.columns if c not in DERIVED]
    return pd.DataFrame([{"check": "field_populated", "subject": c,
                          "value": round(100.0 * filled(raw, c).mean(), 1), "unit": "%",
                          "n": int(filled(raw, c).sum()), "of": len(raw)}
                         for c in cols])


AUDIT = os.path.join(ROOT, "data", "processed", "infra", "label_audit.csv")


def screened_out() -> set[str]:
    """Phishing candidates the label gate removed as registry wildcards.

    They matter to this table more than anywhere else. A dotPH wildcard name resolves, completes a
    handshake against the registry's parking host and then presents a certificate that does not
    verify, so it depresses every conditional rate below without any instrument having failed:
    93% of the phishing rows that shake hands but yield no certificate are .ph, and all 2,704 of
    them carry tls_verified = 0. Reported pooled, the phishing arm looks like a broken collector."""
    if not os.path.exists(AUDIT):
        return set()
    a = pd.read_csv(AUDIT, low_memory=False)
    return set(a.loc[a["verdict"] == "registry_wildcard", "registered_domain"].astype(str))


def success_chain(raw: pd.DataFrame) -> pd.DataFrame:
    rows = []
    wildcard = screened_out()
    for arm in ("all", "phish", "phish_screened", "benign"):
        if arm == "all":
            d = raw
        elif arm == "phish_screened":
            d = raw[(raw["label"] == "phish")
                    & ~raw["registered_domain"].astype(str).isin(wildcard)]
        else:
            d = raw[raw["label"] == arm]
        res = filled(d, "a_records")
        shake = d["tls_present"].astype(str).str.strip().str.lower().isin(TRUE)
        cert = filled(d, "tls_issuer")
        who = filled(d, "whois_created")
        for name, num, den in (("resolved", res, pd.Series(True, index=d.index)),
                               ("tls_handshake_given_resolved", shake & res, res),
                               ("tls_cert_given_handshake", cert & shake, shake),
                               ("whois_given_resolved", who & res, res)):
            den_n = int(den.sum())
            rows.append({"check": "success_rate", "subject": f"{arm}:{name}",
                         "value": round(100.0 * num.sum() / den_n, 1) if den_n else float("nan"),
                         "unit": "%", "n": int(num.sum()), "of": den_n})
    return pd.DataFrame(rows)


def multiplicity(raw: pd.DataFrame) -> pd.DataFrame:
    per_dom = raw.groupby("registered_domain").agg(rows=("domain", "size"),
                                                   hosts=("domain", "nunique"))
    rows = [{"check": "captures", "subject": "rows", "value": len(raw), "unit": "n",
             "n": len(raw), "of": len(raw)},
            {"check": "captures", "subject": "distinct_hostnames",
             "value": int(raw["domain"].nunique()), "unit": "n",
             "n": int(raw["domain"].nunique()), "of": len(raw)},
            {"check": "captures", "subject": "distinct_registrable",
             "value": len(per_dom), "unit": "n", "n": len(per_dom), "of": len(raw)},
            {"check": "captures", "subject": "registrable_with_many_hostnames",
             "value": int((per_dom["hosts"] > 1).sum()), "unit": "n",
             "n": int((per_dom["hosts"] > 1).sum()), "of": len(per_dom)},
            {"check": "captures", "subject": "rows_under_those",
             "value": int(per_dom.loc[per_dom["hosts"] > 1, "rows"].sum()), "unit": "n",
             "n": int(per_dom.loc[per_dom["hosts"] > 1, "rows"].sum()), "of": len(raw)},
            {"check": "captures", "subject": "max_hostnames_one_registrable",
             "value": int(per_dom["hosts"].max()), "unit": "n",
             "n": int(per_dom["hosts"].max()), "of": len(per_dom)}]
    for att, n in raw["attempt"].value_counts().sort_index().items():
        rows.append({"check": "captures", "subject": f"attempt_{att}", "value": int(n),
                     "unit": "n", "n": int(n), "of": len(raw)})
    return pd.DataFrame(rows)


def consistency(raw: pd.DataFrame, pop: pd.DataFrame) -> pd.DataFrame:
    """Every row here re-derives a rule the design states, and prints what it counted."""
    raw_dom = set(raw["registered_domain"].astype(str))
    live = set(raw[raw["stratum"] == "live"]["registered_domain"].astype(str))
    pop_dom = pop["registered_domain"].astype(str)
    outside = pop[~pop_dom.isin(live)]
    first = first_capture(raw).set_index("registered_domain")
    joined = pop.set_index("registered_domain").join(first[["captured_at"]], rsuffix="_first")
    kept = pd.to_datetime(joined["captured_at"], errors="coerce")
    earliest = pd.to_datetime(joined["captured_at_first"], errors="coerce")
    differs = kept.notna() & earliest.notna() & (kept != earliest)
    later = (kept > earliest) & differs

    checks = [
        ("one row per registrable domain", len(pop) - pop_dom.nunique(), 0,
         f"{len(pop):,} rows, {pop_dom.nunique():,} distinct"),
        ("every conditioned domain exists in the raw log", len(set(pop_dom) - raw_dom), 0,
         f"{len(set(pop_dom)):,} checked"),
        ("no phishing row outside the live stratum",
         int((outside["arm"] == "phish").sum()), 0,
         f"{len(outside):,} rows outside it, all comparator arms"),
        ("a non-first capture is always a later one, never an earlier one",
         int(differs.sum() - later.sum()), 0,
         f"{int(differs.sum())} rows keep a later capture, the completeness rule"),
    ]
    return pd.DataFrame([{"check": "consistency", "subject": name,
                          "value": "pass" if got == want else "FAIL",
                          "unit": "", "n": got, "of": note} for name, got, want, note in checks])


def write_assets(tab: pd.DataFrame, raw: pd.DataFrame, pop: pd.DataFrame) -> None:
    if not os.path.isdir(SEC):
        return
    nl = "\n"
    sr = tab[tab["check"] == "success_rate"].set_index("subject")
    out = io.StringIO()
    out.write("\\begin{table}[h]\\centering\\footnotesize" + nl
              + "\\caption{Technical validation of \\nolinkurl{host_infra.csv}. Each stage is "
                "conditioned on the one above it, because a name that no longer resolves cannot "
                "present a certificate and its failure is not an instrument failure. The "
                "post-screen column drops the registry-wildcard names, which resolve and shake "
                "hands against a registry's parking host and then present nothing that "
                "verifies.}" + nl
              + "\\label{tab:validation}" + nl
              + "\\begin{tabular}{lrrrr}\\toprule" + nl
              + "Stage & All & Phishing & \\quad post-screen & Benign \\\\ \\midrule" + nl)
    labels = [("resolved", "Resolved (A record)"),
              ("tls_handshake_given_resolved", "TLS handshake $\\mid$ resolved"),
              ("tls_cert_given_handshake", "Certificate read $\\mid$ handshake"),
              ("whois_given_resolved", "WHOIS answered $\\mid$ resolved")]
    for key, label in labels:
        cells = []
        for arm in ("all", "phish", "phish_screened", "benign"):
            r = sr.loc[f"{arm}:{key}"]
            cells.append(f"{r['value']:.1f}\\%")
        out.write(f"{label} & " + " & ".join(cells) + " \\\\" + nl)
    out.write("\\bottomrule\\end{tabular}\\end{table}" + nl)
    write_generated(os.path.join(SEC, "tab_validation.tex"), out.getvalue())

    cap = tab[tab["check"] == "captures"].set_index("subject")["value"]
    body = "".join([
        f"\\newcommand{{\\ValRows}}{{{int(cap['rows']):,}}}{nl}",
        f"\\newcommand{{\\ValHosts}}{{{int(cap['distinct_hostnames']):,}}}{nl}",
        f"\\newcommand{{\\ValRegistrable}}{{{int(cap['distinct_registrable']):,}}}{nl}",
        f"\\newcommand{{\\ValMultiHost}}{{{int(cap['registrable_with_many_hostnames']):,}}}{nl}",
        f"\\newcommand{{\\ValMultiRows}}{{{int(cap['rows_under_those']):,}}}{nl}",
        f"\\newcommand{{\\ValMaxHosts}}{{{int(cap['max_hostnames_one_registrable']):,}}}{nl}",
        f"\\newcommand{{\\ValResolved}}{{{sr.loc['all:resolved', 'value']:.1f}\\%}}{nl}",
        f"\\newcommand{{\\ValConditioned}}{{{len(pop):,}}}{nl}",
    ])
    write_generated(os.path.join(SEC, "gen_validation.tex"), body)


def main() -> None:
    raw, unparsed = load()
    raw = strata(raw)
    pop = pd.read_csv(POP, low_memory=False)
    tab = pd.concat([completeness(raw), success_chain(raw), multiplicity(raw),
                     consistency(raw, pop)], ignore_index=True)
    write_generated(OUT, tab.to_csv(index=False))
    write_assets(tab, raw, pop)

    print(f"[+] {OUT}")
    print(f"    unparsed timestamp rows excluded upstream: {unparsed}")
    for _, r in tab[tab["check"] == "consistency"].iterrows():
        mark = "ok  " if r["value"] == "pass" else "FAIL"
        print(f"    [{mark}] {r['subject']} — {r['of']}")
    # `value` deliberately mixes numbers and pass/FAIL, so coerce before comparing.
    fields = tab[tab["check"] == "field_populated"].copy()
    fields["value"] = pd.to_numeric(fields["value"], errors="coerce")
    worst = fields[fields["value"] < 100].sort_values("value")
    print(f"    fields below 100% populated: {len(worst)} of {len(fields)} shipped columns"
          + (f" (lowest: {worst.iloc[0]['subject']} at {worst.iloc[0]['value']:.1f}%)"
             if len(worst) else ""))


if __name__ == "__main__":
    main()
