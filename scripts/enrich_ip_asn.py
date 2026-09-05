#!/usr/bin/env python3
"""
enrich_ip_asn.py — resolve every A record in the corpus to its autonomous system.

WHY. `host_infra.csv` records where a name pointed, and an IP address on its own answers almost
nothing a reader wants: whether Vietnamese phishing concentrates on a handful of hosting providers,
whether it is hosted in-country or abroad, whether the benign comparator sits on the same networks.
Those are AS-level questions, and this file is the join that makes them askable.

A SEPARATE FILE ON PURPOSE. This writes `data/processed/infra/ip_asn.csv` and never touches
`host_infra.csv`. The capture files are an observational record with a timestamp on every row;
routing is a moving target queried later, from a third party, and folding today's AS into a row
stamped six weeks ago would quietly date-stamp it wrong. Keeping the join separate also means the
corpus stays reproducible when the routing table moves under it, which it will.

SOURCE. Team Cymru's bulk IP-to-ASN service (whois.cymru.com:43), which exists for exactly this
and is queried in batches over one connection rather than once per address. The addresses sent are
already published in the corpus, so the query discloses nothing the dataset does not. Results are
cached: re-running only asks about addresses the CSV does not already carry.

BOGONS ARE NOT LOOKED UP. Private, loopback, link-local, multicast and unspecified addresses are
recorded with `asn = NA` and a reason, because they are answers about the capture (a wildcard
resolver, a parked null route) rather than about routing, and sending them to a routing oracle
would return nothing and imply we had asked a meaningful question.

    python scripts/enrich_ip_asn.py            # fill in what is missing
    python scripts/enrich_ip_asn.py --refresh  # re-query everything
    python scripts/enrich_ip_asn.py --offline  # summarise the cache, query nothing
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys
import time

import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)
from genfile import write_generated
from make_infra_assets import INFRA

OUT = os.path.join(ROOT, "data", "processed", "infra", "ip_asn.csv")
HOST, PORT = "whois.cymru.com", 43
BATCH = 1500          # addresses per connection; the service documents bulk use in this range
COLUMNS = ["ip", "asn", "as_name", "cc", "registry", "allocated", "bgp_prefix", "note"]


def a_record_ips(path: str = INFRA) -> list[str]:
    """Every distinct IPv4 literal in `a_records`, which packs multiples with ';'."""
    col = pd.read_csv(path, low_memory=False, usecols=["a_records"])["a_records"]
    seen: set[str] = set()
    for cell in col.dropna().astype(str):
        for tok in cell.replace(",", ";").split(";"):
            tok = tok.strip()
            if not tok:
                continue
            try:
                ip = ipaddress.ip_address(tok)
            except ValueError:
                continue
            if ip.version == 4:
                seen.add(str(ip))
    return sorted(seen)


def bogon_reason(ip: str) -> str | None:
    """Why an address is not a routing question. Empty string means it is one."""
    a = ipaddress.ip_address(ip)
    for flag, why in (("is_unspecified", "unspecified"), ("is_loopback", "loopback"),
                      ("is_link_local", "link-local"), ("is_multicast", "multicast"),
                      ("is_reserved", "reserved"), ("is_private", "private")):
        if getattr(a, flag):
            return why
    return None


def query(ips: list[str]) -> list[dict]:
    """One connection, many addresses. Cymru's verbose bulk format is pipe-separated:
    AS | IP | BGP prefix | CC | registry | allocated | AS name."""
    if not ips:
        return []
    payload = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    sock = socket.create_connection((HOST, PORT), timeout=60)
    try:
        sock.sendall(payload.encode())
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()
    rows = []
    for line in b"".join(chunks).decode(errors="replace").splitlines():
        if "|" not in line or line.lower().startswith("bulk mode"):
            continue
        f = [p.strip() for p in line.split("|")]
        if len(f) < 7:
            continue
        rows.append({"ip": f[1], "asn": f[0], "bgp_prefix": f[2], "cc": f[3],
                     "registry": f[4], "allocated": f[5], "as_name": f[6], "note": ""})
    return rows


def load_cache() -> pd.DataFrame:
    if os.path.exists(OUT):
        df = pd.read_csv(OUT, dtype=str).fillna("")
        return df.reindex(columns=COLUMNS, fill_value="")
    return pd.DataFrame(columns=COLUMNS)


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    """Per-arm AS concentration on the CONDITIONED population, joined through each domain's first
    capture.

    Conditioning is not a detail here, it is the whole result. On the raw live stratum 78.8% of
    phishing domains sit in AS63949, which reads as a campaign hosted on one network and is not:
    3,098 of those 3,108 names resolve to the single address 45.79.222.138, all under .ph, all with
    ns_count = 0. That is the dotPH registry wildcard already documented as artefact #5, and
    audit_capture_labels.is_registry_wildcard screens it out of every arm. Reading AS shares off the
    unscreened stratum would have published a registry's parking page as an attacker's hosting
    choice."""
    pop_path = os.path.join(ROOT, "data", "processed", "infra", "infra_dataset.csv")
    if not os.path.exists(pop_path):
        return pd.DataFrame()
    from make_capture_lag import first_capture, load, strata
    raw, _ = load()
    dom = first_capture(strata(raw))
    a_by_domain = dict(zip(dom["registered_domain"].astype(str), dom["a_records"].astype(str)))
    lookup = {r.ip: r for r in df.itertuples()}

    def first_known(domain: str):
        for tok in str(a_by_domain.get(domain, "")).replace(",", ";").split(";"):
            tok = tok.strip()
            if tok in lookup:
                return lookup[tok]
        return None

    pop = pd.read_csv(pop_path, low_memory=False)
    hit = pop["registered_domain"].astype(str).map(first_known)
    pop = pop[hit.notna()].copy()
    hit = hit.dropna()
    pop["asn"], pop["as_name"] = [h.asn for h in hit], [h.as_name for h in hit]
    pop["cc"] = [h.cc for h in hit]

    rows = []
    for arm, sub in pop.groupby("arm"):
        counts = sub.groupby(["asn", "as_name", "cc"]).size().sort_values(ascending=False)
        for (asn, name, cc), n in counts.items():
            rows.append({"arm": arm, "asn": asn, "as_name": name, "cc": cc, "domains": n,
                         "share_pct": round(100.0 * n / len(sub), 2),
                         "arm_domains": len(sub), "arm_distinct_asn": sub["asn"].nunique(),
                         "arm_vn_pct": round(100.0 * (sub["cc"] == "VN").mean(), 1)})
    return pd.DataFrame(rows)


def write_asn_table(summary: pd.DataFrame) -> None:
    sec = os.path.join(ROOT, "papers", "P4b_infra_data", "sections")
    if summary.empty or not os.path.isdir(sec):
        return
    import io
    nl = "\n"
    out = io.StringIO()
    out.write("\\begin{table}[h]\\centering\\footnotesize" + nl
              + "\\caption{Autonomous systems hosting the conditioned population, five largest "
                "per arm, joined on the first A record of each domain's first capture. Shares are "
                "of the arm. The phishing arm is still accruing, so read it as composition rather "
                "than as a rate.}" + nl
              + "\\label{tab:asn}" + nl
              + "\\begin{tabular}{llrr}\\toprule" + nl
              + "Arm & Autonomous system & Domains & Share \\\\ \\midrule" + nl)
    for arm in sorted(summary["arm"].unique()):
        sub = summary[summary["arm"] == arm].head(5)
        head = sub.iloc[0]
        out.write("\\multicolumn{4}{l}{\\textit{" + arm.replace("_", "\\_")
                  + f": {head['arm_domains']:,} domains, {head['arm_distinct_asn']} distinct AS, "
                  + f"{head['arm_vn_pct']:.0f}\\% Vietnam-hosted" + "}} \\\\" + nl)
        for _, r in sub.iterrows():
            name = str(r["as_name"]).split(" - ")[0].replace("_", "\\_")
            out.write(f"& AS{r['asn']}~{name} ({r['cc']}) & {int(r['domains']):,} & "
                      f"{r['share_pct']:.1f}\\% \\\\" + nl)
    out.write("\\bottomrule\\end{tabular}\\end{table}" + nl)
    write_generated(os.path.join(sec, "tab_asn.tex"), out.getvalue())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true", help="re-query addresses already cached")
    ap.add_argument("--offline", action="store_true", help="summarise the cache without querying")
    args = ap.parse_args()

    ips = a_record_ips()
    cache = load_cache()
    known = set() if args.refresh else set(cache["ip"])
    todo = [i for i in ips if i not in known]
    print(f"[.] {len(ips):,} distinct A-record addresses, {len(known):,} cached, "
          f"{len(todo):,} to look up")

    rows = [] if args.refresh else cache.to_dict("records")
    if not args.offline and todo:
        routable = []
        for ip in todo:
            why = bogon_reason(ip)
            if why:
                rows.append({"ip": ip, "asn": "NA", "as_name": "", "cc": "", "registry": "",
                             "allocated": "", "bgp_prefix": "", "note": why})
            else:
                routable.append(ip)
        for i in range(0, len(routable), BATCH):
            batch = routable[i:i + BATCH]
            got = query(batch)
            back = {r["ip"] for r in got}
            rows += got
            # An address the service declines to answer for is unrouted, which is itself a finding.
            rows += [{"ip": ip, "asn": "NA", "as_name": "", "cc": "", "registry": "",
                      "allocated": "", "bgp_prefix": "", "note": "no route"}
                     for ip in batch if ip not in back]
            print(f"    {min(i + BATCH, len(routable)):,}/{len(routable):,}")
            time.sleep(1)

    df = pd.DataFrame(rows).reindex(columns=COLUMNS, fill_value="")
    df = df.drop_duplicates("ip").sort_values("ip")
    write_generated(OUT, df.to_csv(index=False))

    routed = df[df["asn"].astype(str).str.isdigit()]
    print(f"[+] {OUT}: {len(df):,} addresses, {len(routed):,} routed, "
          f"{len(df) - len(routed):,} without a route")
    if len(routed):
        top = routed.groupby(["asn", "as_name"]).size().sort_values(ascending=False).head(5)
        for (asn, name), n in top.items():
            print(f"    AS{asn:<8} {n:5,}  {name[:60]}")

    summary = summarise(df)
    if not summary.empty:
        out_sum = os.path.join(ROOT, "data", "processed", "infra", "asn_summary.csv")
        write_generated(out_sum, summary.to_csv(index=False))
        write_asn_table(summary)
        for arm in sorted(summary["arm"].unique()):
            h = summary[summary["arm"] == arm].iloc[0]
            print(f"    {arm:16s} n={int(h['arm_domains']):6,} "
                  f"AS={int(h['arm_distinct_asn']):4d} VN={h['arm_vn_pct']:.0f}%  "
                  f"top AS{h['asn']} {h['share_pct']:.1f}%")


if __name__ == "__main__":
    main()
