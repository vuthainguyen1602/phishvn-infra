#!/usr/bin/env python3
"""
watch_urlscan_brands.py — Live feed of Vietnamese brand-impersonation phishing, via urlscan search.

Replaces the SOURCE behind watch_chongluadao.py, not the parser: its mirror (urls.txt) last moved
2024-05-16 and the site went client-side-rendered, so ~83% of what it scans is already dead.
Searches `page.domain:*<brand>*` — Vietnamese phishing puts the domestic brand in the hostname;
`page.country:VN` misses almost all of it since hosting is abroad (P9: only 2.7% on .vn).
Cheap because a search hit carries the scan UUID (download the existing capture: no scan quota,
no 45 s wait) and the infra fields (ASN, server, TLS/domain age, HTTP status) come with it.

Free-tier limits (verified 2026-07-26): `verdicts.overall.malicious` is NOT searchable, so every
hit is a candidate — the official-domain filter plus downstream labelling do the rest; `page.tld`,
`page.asnname`, `page.mimeType` return HTTP 400; `total` saturates at 10,000; search quota is
1,000/day (~one search per token per run).

RUN:
  python scripts/collect/watch_urlscan_brands.py --days 2 --max-captures 60
  python scripts/collect/watch_urlscan_brands.py --days 30 --no-capture   # backfill identities only
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs  # noqa: E402
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)
from watch_chongluadao import clean_title, fetch_external_js  # noqa: E402  (shared capture helpers)

H = {"User-Agent": "Mozilla/5.0 (research; contact nvthai@utc2.edu.vn)"}
SEARCH = "https://urlscan.io/api/v1/search/"
OUTDIR = os.path.join("data", "raw", "urlscan_brands")
SEEN_PATH = os.path.join(OUTDIR, "seen_domains.txt")
DET_PATH = os.path.join(OUTDIR, "detections.csv")
DOM_DIR = os.path.join("data", "raw", "landing_live")
SHOT_DIR = os.path.join("data", "raw", "landing_live_shots")
JS_DIR = os.path.join("data", "raw", "landing_live_js")
TOKENS_JSON = os.path.join("data", "processed", "brand_tokens.json")

# Curated, not brand_tokens.json wholesale (1,798 tokens incl. generic place names — noise, not
# coverage): only Vietnamese-specific strings a foreign hostname has no innocent reason to carry.
# `shopee`/`momo` excluded: 4,679 and 1,305 scans in 30 days, nearly all legitimate/non-Vietnamese.
DEFAULT_TOKENS = [
    # banks — dropped after a 7-day trial: `tpbank` = OTP Bank (HU), `abbank` = Charles Schwab,
    # `eximbank`/`seabank` = PH/ID banks, `ghtk` (4 chars) = "shinebri-ghtk-its" etc.
    "vietcombank", "techcombank", "vietinbank", "agribank", "bidv", "sacombank", "vpbank",
    "hdbank", "lienvietpostbank", "namabank", "vietabank", "pvcombank", "shinhanbank",
    # telecom / carriers
    "viettel", "vinaphone", "mobifone", "vnpt", "fptshop", "fpttelecom",
    # public services and identity
    "vneid", "dichvucong", "baohiemxahoi", "thuedientu", "tongcucthue",
    # logistics
    "viettelpost", "vnpost", "giaohangtietkiem",
    # Added 2026-07-26 after corpus scoring + a live 7-day urlscan trial (only the trial sees
    # global noise): mbbank (mbbank-vn.com), vssid (vssidgovn.com), vietlott (vietlott4d.com),
    # pharmacity, vnpay, chinhphu; gplx returned 0 hits in 7d but no noise — kept as a cheap
    # probe for driving-licence scams (10 in the corpus).
    "mbbank", "vietlott", "pharmacity", "vnpay", "vssid", "gplx", "chinhphu",
    # REJECTED by the same trial — corpus prevalence does not mean the string is safe to search:
    #   lazada (54 hits: real regional Lazada), tiki (41: tikitaka1.de etc.), lotte (31: prefix
    #   of "lottery"), sendo (30: sendoui.com etc.), ocb (22) / msb (18): 3-char tokens unusable
    #   for substring search (ocbcsekuritas.org.ph, msbureau.com).
]

# A SECOND LENS, on page content: the token list is blind to e.g. `56bfrd3jrn.pages.dev` rendering
# a bank login under a random name. Measured 7-day window 2026-07-26 (found -> surviving the
# official-domain filter): "Ngân hàng" 44->28, "Dịch vụ công" 33->10, *nhanqua* 6->6,
# *dangnhap* 6->6, *xacminh* 1->1. `page.title:"Đăng nhập"` deliberately absent despite the
# highest volume (95->95): it matches every Vietnamese login page there is.
CONTENT_QUERIES = [
    ('page.title:"Ngân hàng"', "title:bank"),
    ('page.title:"Dịch vụ công"', "title:public-service"),
    ("task.url:*xacminh*", "url:xacminh"),      # "xác minh" — verify (identity/account)
    ("task.url:*nhanqua*", "url:nhanqua"),      # "nhận quà" — claim a gift
    ("task.url:*dangnhap*", "url:dangnhap"),    # "đăng nhập" — log in, as a PATH not a title
]

FIELDS = ["domain", "first_detected", "brand", "scan_uuid", "task_url", "scan_time", "status",
          "country", "asn", "asnname", "server", "domain_age_days", "tls_age_days",
          "found", "dom_file", "shot_file", "js_count", "title"]


def load_official() -> set[str]:
    """Registered domains of the real organisations, so `*vietcombank*` does not report
    vietcombank.com.vn as an impersonation. Sourced from the trusted-org registry the project
    already builds; falls back to a minimal set if the file is absent."""
    # Real domains the filter kept reporting: techcombank.com / viettel.com.vn (first run);
    # vnpay.vn / chinhphu.vn (2026-07-26 trial — `chinhphu` alone returned 40 legitimate
    # government subdomains, since chinhphu.vn escapes the .gov.vn suffix rule)
    official = {"techcombank.com", "viettel.com.vn", "vnpay.vn", "chinhphu.vn",
                # from the content lens: the Government newspaper and a real digital bank
                "baochinhphu.vn", "vikkibank.vn",
                "vietcombank.com.vn", "techcombank.com.vn", "vietinbank.vn", "agribank.com.vn",
                "bidv.com.vn", "sacombank.com.vn", "vpbank.com.vn", "tpbank.vn", "acb.com.vn",
                "viettel.vn", "vinaphone.com.vn", "mobifone.vn", "vnpt.com.vn", "vnpt.vn",
                "vneid.gov.vn", "vnpost.vn", "viettelpost.com.vn", "viettelmoney.vn",
                "vietteltelecom.vn", "hdbank.com.vn", "namabank.com.vn", "pvcombank.com.vn",
                "shinhan.com.vn", "giaohangtietkiem.vn", "fptshop.com.vn", "fpt.vn"}
    try:
        with open(TOKENS_JSON, encoding="utf-8") as f:
            for t in json.load(f).get("tokens", []):
                for d in t.get("domains", []):
                    official.add(d.lower().removeprefix("www."))
    except (OSError, ValueError):
        pass
    return official


def token_at_boundary(domain: str, tok: str) -> bool:
    """urlscan's `*token*` is raw substring match. Require the token to start a label or follow
    a non-letter: keeps `bidv-diem`, `vietcombank88`, `ffsandusr0vpbank`; drops `shinebri(ghtk)its`,
    `o(tpbank)`, `charlessschwa(bbank)`. Tokens of 9+ chars are exempt — too long to land inside an
    English word by accident; keeps run-ons like `tamtaiviet-vietcombank`."""
    for label in re.split(r"[.\-_]", domain.lower()):
        i = label.find(tok)
        while i != -1:
            if i == 0 or not label[i - 1].isalpha() or len(tok) >= 9:
                return True
            i = label.find(tok, i + 1)
    return False


# Registration under these is restricted to verified government bodies / accredited schools, so a
# hostname there is the real organisation — without this every provincial social-insurance and tax
# subdomain becomes a candidate.
RESTRICTED_SUFFIXES = (".gov.vn", ".edu.vn", ".mil.vn")


def is_official(domain: str, official: set[str]) -> bool:
    d = domain.lower().rstrip(".")
    if d.endswith(RESTRICTED_SUFFIXES):
        return True
    return any(d == o or d.endswith("." + o) for o in official)


def load_seen(path: str = None) -> set[str]:
    path = path or SEEN_PATH
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        # normalize here too, so legacy www.* lines still suppress their apex twin
        return {l.strip().removeprefix("www.") for l in f if l.strip()}


def search(query: str, days: int, key: str, size: int = 100) -> list[dict]:
    """`query` is a full urlscan lucene expression, not just a token, so the caller can search by
    page CONTENT as well as by hostname — see CONTENT_QUERIES."""
    q = f"{query} AND date:>now-{days}d"
    for attempt in range(3):
        try:
            r = requests.get(SEARCH, headers={**H, "API-Key": key},
                             params={"q": q, "size": size}, timeout=30)
        except requests.RequestException:
            time.sleep(3)
            continue
        if r.status_code == 200:
            return r.json().get("results", [])
        if r.status_code == 429:            # search quota is per-minute as well as per-day
            time.sleep(6 * (attempt + 1))
            continue
        print(f"[!] {query}: HTTP {r.status_code} {r.text[:90]}")
        return []
    return []


def download_capture(uuid: str, key: str) -> dict:
    """Pull an EXISTING scan's DOM, screenshot and external JS. Unlike the ChongLuaDao path this
    submits nothing, so it costs `retrieve` quota (10,000/day) rather than a scan."""
    out = {"found": 0, "dom_file": "", "shot_file": "", "js_count": 0, "title": ""}
    try:
        rr = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/",
                          headers={**H, "API-Key": key}, timeout=30)
        if rr.status_code != 200:
            return out
        res = rr.json()
    except (requests.RequestException, ValueError):
        return out
    out["found"] = 1
    out["title"] = clean_title((res.get("page") or {}).get("title", ""))
    try:
        dr = requests.get(f"https://urlscan.io/dom/{uuid}/", headers={**H, "API-Key": key}, timeout=30)
        if dr.status_code == 200 and dr.text:
            os.makedirs(DOM_DIR, exist_ok=True)
            out["dom_file"] = os.path.join(DOM_DIR, f"{uuid}.html")
            open(out["dom_file"], "w", encoding="utf-8").write(dr.text)
    except requests.RequestException:
        pass
    try:
        sr = requests.get(f"https://urlscan.io/screenshots/{uuid}.png",
                          headers={**H, "API-Key": key}, timeout=30)
        if sr.status_code == 200 and sr.content:
            os.makedirs(SHOT_DIR, exist_ok=True)
            out["shot_file"] = os.path.join(SHOT_DIR, f"{uuid}.png")
            open(out["shot_file"], "wb").write(sr.content)
    except requests.RequestException:
        pass
    try:
        _, out["js_count"] = fetch_external_js(uuid, res, key, JS_DIR)
    except Exception:
        pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=2, help="search window; 2 suits a 6-hourly cron")
    ap.add_argument("--tokens", nargs="+", default=DEFAULT_TOKENS)
    ap.add_argument("--max-captures", type=int, default=60,
                    help="cap DOM/screenshot downloads per run (wall-clock, not quota)")
    ap.add_argument("--no-capture", action="store_true", help="record identities only")
    ap.add_argument("--no-content", action="store_true",
                    help="hostname-token passes only, skipping the page-content queries")
    ap.add_argument("--delay", type=float, default=1.2, help="seconds between searches")
    ap.add_argument("--outdir", default=OUTDIR,
                    help="where detections.csv and seen_domains.txt live; override to trial "
                         "new queries without writing into the live feed")
    args = ap.parse_args()
    det_path = os.path.join(args.outdir, "detections.csv")
    seen_path = os.path.join(args.outdir, "seen_domains.txt")

    key = os.environ.get("URLSCAN_API_KEY", "")
    if not key:
        print("[!] URLSCAN_API_KEY not set (source scripts/.env)")
        return 1

    official, seen = load_official(), load_seen(seen_path)
    os.makedirs(args.outdir, exist_ok=True)
    fresh = not os.path.exists(det_path)

    # collect first, capture second: one domain can match several tokens, and capturing inside the
    # search loop would spend the capture budget on whichever token happened to be searched first
    cand: dict[str, dict] = {}
    passes = [(f"page.domain:*{t}*", t, t) for t in args.tokens]
    if not args.no_content:
        passes += [(q, label, None) for q, label in CONTENT_QUERIES]
    for query, label, tok in passes:
        for r in search(query, args.days, key):
            page, task = r.get("page") or {}, r.get("task") or {}
            # www and apex are the same site to urlscan (same scan content); keeping both
            # double-counted every hit whose submitter used the www form
            dom = (page.get("domain") or task.get("domain") or "").lower().removeprefix("www.")
            if not dom or dom in seen or dom in cand or is_official(dom, official):
                continue
            # the boundary rule only means something for a hostname token; a content hit has no
            # token in the name at all, which is the entire point of that pass
            if tok is not None and not token_at_boundary(dom, tok):
                continue
            cand[dom] = {
                "domain": dom, "brand": label, "scan_uuid": r.get("_id", ""),
                "task_url": task.get("url", ""), "scan_time": task.get("time", ""),
                "status": page.get("status", ""), "country": page.get("country", ""),
                "asn": page.get("asn", ""), "asnname": page.get("asnname", ""),
                "server": page.get("server", ""),
                "domain_age_days": page.get("domainAgeDays", ""),
                "tls_age_days": page.get("tlsAgeDays", ""),
            }
        time.sleep(args.delay)

    print(f"[i] {len(args.tokens)} tokens + {0 if args.no_content else len(CONTENT_QUERIES)} content queries, window {args.days}d -> {len(cand)} new candidate domains")
    if not cand:
        return 0

    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    n_cap = 0
    with open(det_path, "a", newline="", encoding="utf-8") as f, \
            open(seen_path, "a", encoding="utf-8") as sf:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if fresh:
            w.writeheader()
        for dom, row in cand.items():
            row["first_detected"] = now
            if not args.no_capture and n_cap < args.max_captures and row["scan_uuid"]:
                row.update(download_capture(row["scan_uuid"], key))
                n_cap += 1
            else:
                row.update({"found": 0, "dom_file": "", "shot_file": "", "js_count": 0, "title": ""})
            w.writerow({k: row.get(k, "") for k in FIELDS})
            sf.write(dom + "\n")
            print(f"[+] {dom} ({row['brand']}) -> {'captured' if row.get('found') else 'recorded'}")
            f.flush()
            sf.flush()
    print(f"Done: {len(cand)} new, {n_cap} captured -> {det_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
