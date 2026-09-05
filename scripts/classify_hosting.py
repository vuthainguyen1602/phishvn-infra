#!/usr/bin/env python3
"""
classify_hosting.py — did the operator of this name register a domain, or take a subdomain?

WHY IT CHANGES WHAT A FEATURE MEANS. `vpbank.awsapps.com` and `vpbank-verify.com` are the same
kind of lure and completely different registrations. Nobody registered the first: they signed up
for a subdomain on a platform that owns the apex, so its WHOIS age is Amazon's, its registrar is
Amazon's registrar and its certificate is Amazon's. Any model reading registration-level features
across the two is reading a property of the provider on one row and a property of the actor on the
next. The study's design already excludes these names from modelling; this file is where the rule that
identifies them is written down, measured and made reproducible.

THE RULE, AND WHY IT IS A UNION. Two independent sources, because each catches what the other
misses and neither is complete on its own.

  psl      The Public Suffix List's PRIVATE section, contributed by the platforms themselves.
           A name is platform-hosted when its registrable domain computed WITH private suffixes
           differs from the one computed under ICANN rules alone: `x.pages.dev` is its own
           registrable domain privately and sits under `pages.dev` publicly, so the apex is the
           platform's. This is versioned, third-party and needs no judgement from us.
  curated  audit_capture_labels.HOSTED_SUFFIXES, the list the label gate already used.

Measured against each other on this corpus, the PSL finds 45 phishing names the curated list
misses (appspot.com, framer.app, awsapps.com, dweb.link) and the curated list finds 93 the PSL
misses, every one under weebly.com, which Weebly has never submitted to the PRIVATE section.
Either alone is wrong by a few dozen names; the union is what both agree the reader should see,
and `rule` records which source fired so the disagreement stays auditable.

THREE CLASSES, AND THE THIRD IS NOT A HEDGE.
  platform_hosted      either rule fires: the apex belongs to a provider, not to the operator.
  attacker_registered  the name IS its own registrable domain, so whoever runs it registered it.
  uncertain            a subdomain of an ordinary registrable domain. It could be a platform the
                       PSL does not list, a compromised legitimate site, or an internal subdomain
                       of a large organisation. Those three are not separable from DNS and TLS
                       alone, and pretending otherwise would put a guess in a data paper.

WHAT THIS CANNOT SUPPORT. Platform-hosted names are 4.5% of distinct phishing hostnames and
essentially absent from the comparators, and that contrast is NOT a behavioural finding. The
benign arms are drawn from certificate logs and a registry of trusted organisations, both of which
enumerate registered domains, so a platform subdomain could hardly appear in them. The number
describes the phishing arm; it does not compare the arms.

    python scripts/classify_hosting.py
"""
from __future__ import annotations

import io
import os
import sys

import pandas as pd
import tldextract

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)
from genfile import write_generated
from audit_capture_labels import HOSTED_SUFFIXES
from make_infra_assets import INFRA

OUT = os.path.join(ROOT, "data", "processed", "infra", "hosting_class.csv")
SEC = os.path.join(ROOT, "papers", "P4b_infra_data", "sections")

# suffix_list_urls=() pins both extractors to the bundled snapshot, so the classification does not
# change under us when the live list does. tldextract is pinned exactly in requirements for the
# same reason the psl.py note gives.
_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_ICANN = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)


def classify(host: str) -> tuple[str, str, str]:
    """Returns (class, rule that decided it, the apex the name sits under)."""
    h = str(host).strip().lower().removeprefix("www.")
    if not h:
        return "unclassified", "", ""
    priv, icann = _PRIVATE(h), _ICANN(h)
    if not priv.suffix or not priv.domain:
        return "unclassified", "", ""
    private_rd = f"{priv.domain}.{priv.suffix}"
    icann_rd = f"{icann.domain}.{icann.suffix}"
    by_psl = private_rd != icann_rd
    by_curated = any(h.endswith("." + s) for s in HOSTED_SUFFIXES)
    if by_psl or by_curated:
        rule = "+".join(([" psl"] if by_psl else []) + (["curated"] if by_curated else [])).strip()
        return "platform_hosted", rule, icann_rd if by_psl else _curated_apex(h)
    if h == private_rd:
        return "attacker_registered", "self", private_rd
    return "uncertain", "subdomain", private_rd


def _curated_apex(host: str) -> str:
    for s in HOSTED_SUFFIXES:
        if host.endswith("." + s):
            return s
    return ""


def main() -> None:
    df = pd.read_csv(INFRA, low_memory=False, usecols=["domain", "label", "source"])
    hosts = df.drop_duplicates("domain").copy()
    out = hosts["domain"].map(classify)
    hosts["hosting_class"] = [c for c, _, _ in out]
    hosts["rule"] = [r for _, r, _ in out]
    hosts["apex"] = [a for _, _, a in out]
    write_generated(OUT, hosts[["domain", "label", "source", "hosting_class", "rule",
                                "apex"]].to_csv(index=False))

    if os.path.isdir(SEC):
        nl = "\n"
        o = io.StringIO()
        o.write("\\begin{table}[h]\\centering\\footnotesize" + nl
                + "\\caption{Whether the operator of each distinct hostname registered a domain or "
                  "took a subdomain on a platform that owns the apex. Platform-hosted names carry "
                  "the provider's registration and certificate, not the operator's. The "
                  "comparators are drawn from certificate logs and a registry of organisations, "
                  "both of which enumerate registered domains, so their near-zero platform share "
                  "is a property of the sampling and not a contrast with the phishing arm.}" + nl
                + "\\label{tab:hosting}" + nl
                + "\\begin{tabular}{lrrr}\\toprule" + nl
                + "Class & Phishing & Benign & Benign (\\texttt{.vn}) \\\\ \\midrule" + nl)
        arms = [("phish", lambda d: d["label"] == "phish"),
                ("benign", lambda d: (d["label"] == "benign")
                 & (d["source"] != "tinnhiem_benign")),
                ("tinnhiem", lambda d: d["source"] == "tinnhiem_benign")]
        for cls, label in (("attacker_registered", "Registered by the operator"),
                           ("platform_hosted", "Subdomain on a platform"),
                           ("uncertain", "Subdomain, provider unknown")):
            cells = []
            for _, sel in arms:
                sub = hosts[sel(hosts)]
                n = int((sub["hosting_class"] == cls).sum())
                cells.append(f"{n:,} ({100.0 * n / max(len(sub), 1):.1f}\\%)")
            o.write(f"{label} & " + " & ".join(cells) + " \\\\" + nl)
        o.write("\\bottomrule\\end{tabular}\\end{table}" + nl)
        write_generated(os.path.join(SEC, "tab_hosting.tex"), o.getvalue())

        ph = hosts[hosts["label"] == "phish"]
        plat = ph[ph["hosting_class"] == "platform_hosted"]
        body = (f"\\newcommand{{\\HostPlatformN}}{{{len(plat):,}}}{nl}"
                f"\\newcommand{{\\HostPlatformPct}}"
                f"{{{100.0 * len(plat) / max(len(ph), 1):.1f}\\%}}{nl}"
                f"\\newcommand{{\\HostPlatformTop}}"
                f"{{{plat['apex'].value_counts().index[0] if len(plat) else '--'}}}{nl}"
                f"\\newcommand{{\\HostUncertainPct}}"
                f"{{{100.0 * (ph['hosting_class'] == 'uncertain').mean():.1f}\\%}}{nl}")
        write_generated(os.path.join(SEC, "gen_hosting.tex"), body)

    print(f"[+] {OUT}")
    for lab in ("phish", "benign"):
        sub = hosts[hosts["label"] == lab]
        share = sub["hosting_class"].value_counts()
        print(f"    {lab:6s} n={len(sub):6,} " + "  ".join(
            f"{k}={v:,}({100 * v / len(sub):.1f}%)" for k, v in share.items()))
    plat = hosts[(hosts["label"] == "phish") & (hosts["hosting_class"] == "platform_hosted")]
    print(f"    rule agreement on the phishing arm: "
          + "  ".join(f"{k}={v}" for k, v in plat["rule"].value_counts().items()))


if __name__ == "__main__":
    main()
