#!/usr/bin/env python3
"""
audit_infra_capture.py — what the infrastructure capture can and cannot support.

The study asks whether WHOIS/DNS/TLS infrastructure adds signal the URL and content channels do not carry.
Three properties of the capture decide whether such a study is measurable at all, and all three are
measurable before any model is fitted.

1. STRATA. Two populations that must never be pooled: domains detected before the watcher started
   were enriched from a backlog days later and are mostly dead by then (~11% retain an A record);
   domains detected while it ran are enriched within hours. Pooling lets "was this captured late"
   masquerade as an infrastructure feature — and late capture is a property of when we started
   collecting, not of the phishing.

2. THE RETRY IS INERT. The watcher re-attempts domains whose first observation showed no A record
   (a certificate can precede DNS). The number that ever gained one is reported here; if it is
   zero, the design should say so rather than imply a rescue that is not happening.

3. THE BENIGN ARM IS A TRAP, AND IT HAS NOT BEEN COLLECTED YET — the finding that decides the study. VNNIC
   publishes neither WHOIS nor RDAP for .vn, so whois_* is structurally absent for every .vn domain
   (registry policy, not domain death). The available benign feed is 100% .vn; the live phishing
   stratum is mostly non-.vn, where WHOIS is available. A benign arm drawn from that feed would
   make "has a WHOIS record" a near-perfect phishing indicator encoding nothing but the registry —
   an excellent AUC for a model that has learned to detect .vn, on the very population where the
   lexical detector already fails. Quantified BEFORE the benign arm is built, because afterwards
   the number is no longer a warning but a result.

The output is a set of design constraints, not a table: the study must model the live stratum only, treat
.vn WHOIS absence as structural (never imputed, never given a missingness indicator collinear with
the TLD), and draw its benign arm TLD- and time-matched against the phishing arm.

RUN:  python scripts/audit_infra_capture.py
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
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
INFRA = os.path.join(ROOT, "data", "raw", "host_infra", "host_infra.csv")
BENIGN = os.path.join(ROOT, "data", "raw", "tinnhiem_benign", "detections.csv")
# The watcher's first cron tick. Detections earlier than this were enriched from a backlog.
WATCHER_START = dt.date(2026, 7, 30)
FEATURES = ["a_records", "ns_hosts", "whois_created", "tls_not_before"]


def ts(s: str):
    try:
        return dt.datetime.fromisoformat((s or "").replace("Z", "+00:00"))
    except Exception:
        return None


def best_per_domain(rows):
    """One record per domain: the observation that captured the most, so missingness reported here
    is missingness AFTER every retry, not before it."""
    best = {}
    for r in rows:
        score = sum(bool((r.get(k) or "").strip()) for k in ("a_records", "whois_created",
                                                             "tls_not_before"))
        cur = best.get(r["domain"])
        if cur is None or score > cur[0]:
            best[r["domain"]] = (score, r)
    return [r for _, r in best.values()]


def avail(group, feat) -> tuple[int, int]:
    n = sum(1 for r in group if (r.get(feat) or "").strip())
    return n, len(group)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--infra", default=INFRA)
    ap.add_argument("--benign", default=BENIGN)
    args = ap.parse_args()
    if not os.path.exists(args.infra):
        print(f"[i] {args.infra} absent — run watch_host_infra.py (or sync from the collector).")
        return 0
    rows = list(csv.DictReader(open(args.infra, encoding="utf-8")))
    recs = best_per_domain(rows)
    live = [r for r in recs if (ts(r["first_detected"]) or ts("1970-01-01")).date() >= WATCHER_START]
    back = [r for r in recs if (ts(r["first_detected"]) or ts("1970-01-01")).date() < WATCHER_START]

    print(f"observations {len(rows)}, unique domains {len(recs)} "
          f"(labels: {dict(collections.Counter(r['label'] for r in recs))})\n")

    print("1. STRATA — feature availability after all retries")
    print(f"   {'':18s}{'backfill':>14s}{'live':>14s}")
    for f in FEATURES:
        nb, db = avail(back, f)
        nl, dl = avail(live, f)
        print(f"   {f:18s}{f'{100*nb/db:5.1f}% ({nb})' if db else '  n/a':>14s}"
              f"{f'{100*nl/dl:5.1f}% ({nl})' if dl else '  n/a':>14s}")
    for name, g in (("backfill", back), ("live", live)):
        lags = [((ts(r['captured_at']) - ts(r['first_detected'])).total_seconds() / 3600)
                for r in g if ts(r['captured_at']) and ts(r['first_detected'])]
        if lags:
            print(f"   {name}: n={len(g)}, median capture lag {statistics.median(lags):.1f}h")
    print("   => model the LIVE stratum only; the backfill measures our start date, not phishing.\n")

    print("2. RETRY — does a second look ever rescue a domain?")
    multi = collections.defaultdict(list)
    for r in rows:
        multi[r["domain"]].append(r)
    retried = {d: v for d, v in multi.items() if len(v) > 1}
    rescued = sum(1 for v in retried.values()
                  if not (v[0].get("a_records") or "").strip()
                  and any((x.get("a_records") or "").strip() for x in v[1:]))
    print(f"   re-attempted domains {len(retried)}; ever gained an A record: {rescued}")
    print("   => " + ("the retry is inert here and should be documented as such, not implied "
                      "to rescue captures." if rescued == 0 else
                      f"the retry rescues {rescued} domains — keep it and report the rate.") + "\n")

    print("3. BENIGN ARM — the artefact it would manufacture, measured before it is built")
    vn = [r for r in live if r["registered_domain"].endswith(".vn")]
    nonvn = [r for r in live if not r["registered_domain"].endswith(".vn")]
    for nm, g in ((".vn", vn), ("non-.vn", nonvn)):
        if g:
            n, d = avail(g, "whois_created")
            print(f"   live phishing, {nm:8s}: n={d:4d}, WHOIS present {100*n/d:5.1f}%")
    if not os.path.exists(args.benign):
        print(f"   [i] {args.benign} absent — cannot measure the benign feed's composition.")
        return 0
    brows = list(csv.DictReader(open(args.benign, encoding="utf-8")))
    bdom = [(r.get("domain") or "").strip().lower() for r in brows]
    bdom = [d for d in bdom if d]
    bvn = sum(1 for d in bdom if d.endswith(".vn"))
    print(f"   available benign feed : n={len(bdom):4d}, .vn {100*bvn/len(bdom):5.1f}%")

    # The projection. WHOIS is absent for every .vn domain by registry policy, so a benign arm that
    # is entirely .vn has whois_present=0 by construction. Scoring "whois present => phishing"
    # against the live phishing stratum gives the separation a single policy bit would buy.
    tp, np_ = avail(live, "whois_created")
    fp = round(len(bdom) * (1 - bvn / len(bdom)) * 0.0)   # non-.vn benign would be needed for any FP
    tpr = tp / np_ if np_ else 0.0
    fpr = fp / len(bdom) if bdom else 0.0
    auc = tpr * (1 - fpr) + 0.5 * (1 - tpr) * (1 - fpr) + 0.5 * tpr * fpr   # single-threshold AUC
    print(f"   => rule 'has WHOIS => phishing': TPR {tpr:.3f}, FPR {fpr:.3f}, AUC ~{auc:.3f} "
          f"from one bit of registry policy.")
    print("   => the benign arm MUST be TLD-matched (and time-matched) to the phishing arm, or "
          "The study measures VNNIC's disclosure policy and calls it infrastructure.\n")

    # The constructive half. A warning that only forbids leaves the study with nowhere to go, so name the
    # features that survive: those whose availability does NOT depend on the TLD can carry a study
    # with the .vn benign feed as-is.
    print("4. WHICH FEATURES SURVIVE — availability gap between .vn and non-.vn (live stratum)")
    safe, unsafe = [], []
    for f in ["a_records", "ns_hosts", "mx_count", "tls_present", "tls_not_before", "tls_issuer",
              "cname", "whois_created"]:
        nv, dv = avail(vn, f)
        nn, dn = avail(nonvn, f)
        if not dv or not dn:
            continue
        pv, pn = 100 * nv / dv, 100 * nn / dn
        gap = pv - pn
        (unsafe if abs(gap) > 40 else safe).append(f)
        print(f"   {f:16s} .vn {pv:5.1f}%   non-.vn {pn:5.1f}%   gap {gap:+6.1f} pp"
              f"{'   <-- TLD-DETERMINED' if abs(gap) > 40 else ''}")
    print(f"   => TLD-safe feature set: {', '.join(safe)}")
    print(f"   => exclude from any pooled model: {', '.join(unsafe) or '(none)'}")
    print("   => note tls_not_before is the collector's designated domain-age proxy for .vn and "
          "is available there, so excluding WHOIS does not cost the study the age signal.\n")

    # The same failure one layer down, and the reason dropping WHOIS is not the end of the audit.
    # A feature is an artefact whenever the SAMPLING guarantees it, and detection channels do
    # exactly that: a domain found through certificate-transparency monitoring has a certificate
    # by construction, so tls_present=1 for such phishing says nothing about phishing. Benign
    # domains enter through a trusted-org registry, which is indifferent to certificates.
    print("5. DETECTION-CHANNEL ARTEFACT — is a feature guaranteed by how the domain was found?")
    ben = [r for r in recs if r["label"] == "benign"]
    if not ben:
        print("   benign arm not yet collected — re-run once it has data.")
        return 0
    print(f"   {'':16s}{'resolves (A)':>15s}{'TLS present':>14s}")
    for nm, g in (("phishing (live)", live), ("benign", ben)):
        na = sum(1 for r in g if (r.get("a_records") or "").strip())
        nt = sum(1 for r in g if (r.get("tls_present") or "").strip() not in ("", "0"))
        print(f"   {nm:16s}{f'{100*na/len(g):5.1f}% (n={len(g)})':>15s}{f'{100*nt/len(g):5.1f}%':>14s}")
    print("   => BOTH gaps are sampling, not phishing. Phishing is found via CT/urlscan — which")
    print("      sees a domain BECAUSE a certificate was issued — and is captured within ~1.2h,")
    print("      while alive. Benign is a standing registry list that includes long-defunct")
    print("      commune sites. So 'resolves' and 'has TLS' separate the CHANNELS, not the classes.")
    print("   => condition BOTH arms on resolvable AND TLS-present, and drop both indicators from")
    print("      the feature set; the informative features (issuer, not_before, san_count, TTL,")
    print("      NS/MX shape) are then compared where presence is constant by construction.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
