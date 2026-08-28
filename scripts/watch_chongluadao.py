#!/usr/bin/env python3
"""
watch_chongluadao.py — Crawl-AT-DETECTION-TIME watcher for the current ChongLuaDao denylist.

Motivation (see the P1b data-quality finding): retrospectively crawling an aged blacklist yields
mostly mislabelled survivors, because genuine phishing is taken down within days. The fix is to
capture each domain WHILE IT IS STILL LIVE. This watcher does exactly that:

  1. fetch the community denylist — the full daily-refreshed GitHub mirror (tens of thousands of
     domains) UNIONed with the live webpage's freshest rotating sample; either source may fail and
     the other still carries the cycle;
  2. keep only NEW domains (a persistent seen-set), and among those the VIETNAMESE-TARGETING ones
     (vn_filter.is_vn_target: .vn TLD, a Vietnamese unaccented token in the name — vietcombank247,
     247-napas, ... — or a registry-generated brand token from data/processed/brand_tokens.json);
  3. immediately submit each new VN domain to urlscan.io for a FRESH capture of its current DOM +
     screenshot (urlscan visits it in its sandbox; we never render the page locally);
  4. append a dated row to data/raw/chongluadao_live/detections.csv (domain, first_detected,
     scan_uuid, dom_file, shot_file, title) — a growing, time-stamped, capture-at-detection corpus.

Run it periodically — canonically on the Jetson via the systemd units deploy/phishvn-cldwatch.{service,timer}
(see deploy/JETSON_DEPLOY.md §3b; the old macOS launchd plist scripts/com.phishvn.cldwatch.plist is kept
for reference but TCC blocks launchd from a repo under ~/Desktop). Each run is cheap; coverage grows
with frequency because the denylist sample rotates.

ENV:   URLSCAN_API_KEY=...    (required for the fresh-scan submission)
RUN:   python scripts/watch_chongluadao.py                 # one polling cycle
       python scripts/watch_chongluadao.py --no-scan       # just record new VN domains, don't scan
"""
from __future__ import annotations
import argparse
import csv
import datetime as _dt
import os
import re
import sys

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs  # noqa: E402
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)
from vn_filter import host_of, is_vn_target  # noqa: E402

DENYLIST_URL = "https://chongluadao.vn/database/denylist"
# Full community denylist (MIT-licensed daily-refreshed mirror of the ChongLuaDao API). The webpage
# above only server-renders a small ROTATING sample; the mirror is the complete list (tens of
# thousands), which is the real backlog of Vietnamese victim-reported scams.
MIRROR_URL = ("https://raw.githubusercontent.com/elliotwutingfeng/"
              "ChongLuaDao-Phishing-Blocklist/main/urls.txt")
OUTDIR = os.path.join("data", "raw", "chongluadao_live")
SEEN_PATH = os.path.join(OUTDIR, "seen_domains.txt")
DET_PATH = os.path.join(OUTDIR, "detections.csv")
DOM_DIR = os.path.join("data", "raw", "landing_live")
SHOT_DIR = os.path.join("data", "raw", "landing_live_shots")
JS_DIR = os.path.join("data", "raw", "landing_live_js")   # external JS bodies per scan uuid
H = {"User-Agent": "Mozilla/5.0 (research; contact thaivn_ph@utc.edu.vn)"}
MAX_JS = 15            # cap external JS files saved per page (edge storage / quota)
MAX_JS_BYTES = 600_000  # skip a single JS body larger than this

# denylist entries are wrapped in a span whose class starts with _urlText_ (the hash suffix
# changes on rebuilds, so match the prefix). This scopes extraction to the TABLE, excluding the
# page's footer/nav <a href> links (e.g. the anti-scam orgs' own .vn sites), which were otherwise
# false-positives when filtering for .vn.
# The class value is followed by other attributes (the page gained title="<url>" in a late-July
# 2026 redeploy), so anything up to the closing > must be tolerated. Pinning '">' here matched
# nothing from 2026-07-29 to 2026-08-18 while still returning 200 -- a silent zero, see
# fetch_denylist_webpage.
ENTRY_RE = re.compile(r'class="_urlText_[^"]*"[^>]*>\s*(https?://[^<\s]+)', re.I)
SKIP_HOST = ("chongluadao.vn", "google", "gstatic", "cloudflare", "recaptcha", "w3.org")


def clean_title(t) -> str:
    """Attacker-controlled page title -> safe single-line CSV cell. NUL/control chars written raw
    into detections.csv once corrupted the file and broke every downstream csv reader."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(t or ""))[:200].strip()


def _keep(h: str) -> bool:
    return bool(h) and not any(s in h for s in SKIP_HOST) and "." in h


def fetch_denylist_webpage() -> list[str]:
    """The freshest slice: a small rotating sample the denylist page server-renders into its HTML."""
    r = requests.get(DENYLIST_URL, headers=H, timeout=30)
    r.raise_for_status()
    hosts = [host_of(m) for m in ENTRY_RE.findall(r.text)]  # only URLs inside denylist table cells
    if not hosts:
        # A served page that parses to nothing means the markup moved, not that the denylist
        # emptied. Returning [] here reads as success and hides the breakage for weeks; raise so
        # fetch_denylist reports it degraded and the mirror visibly carries the run alone.
        raise RuntimeError(f"denylist page returned {len(r.text)} bytes but ENTRY_RE matched none")
    return hosts


def fetch_denylist_mirror() -> list[str]:
    """The full backlog: the complete community denylist from the daily-refreshed GitHub mirror."""
    r = requests.get(MIRROR_URL, headers=H, timeout=60)
    r.raise_for_status()
    return [host_of(l) for l in r.text.lower().splitlines() if l.strip() and not l.startswith("#")]


def fetch_denylist() -> list[str]:
    """Union of the full mirror (depth) and the live webpage sample (freshness), deduped. Tolerates
    either source failing; raises only if BOTH do. The mirror leads so its ordering is stable."""
    hosts, errs = [], []
    for src in (fetch_denylist_mirror, fetch_denylist_webpage):
        try:
            hosts.extend(src())
        except Exception as e:
            errs.append(f"{src.__name__}: {type(e).__name__}")
    if not hosts:
        raise RuntimeError("; ".join(errs) or "no denylist sources reachable")
    if errs:
        print(f"[i] denylist source(s) degraded: {'; '.join(errs)}", file=sys.stderr)
    return list(dict.fromkeys(h for h in hosts if _keep(h)))


def load_seen() -> set:
    if os.path.exists(SEEN_PATH):
        return {ln.strip() for ln in open(SEEN_PATH, encoding="utf-8") if ln.strip()}
    return set()


def urlscan_submit(domain: str, key: str, dom_dir: str = DOM_DIR, shot_dir: str = SHOT_DIR,
                   js_dir: str = JS_DIR):
    """Submit a fresh scan, poll, download DOM + screenshot. Returns a dict or None.
    Output dirs default to the phishing capture dirs; the benign-org crawler passes its own."""
    import time
    try:
        r = requests.post("https://urlscan.io/api/v1/scan/",
                          headers={**H, "API-Key": key, "Content-Type": "application/json"},
                          json={"url": "http://" + domain, "visibility": "unlisted"}, timeout=30)
        if r.status_code != 200:
            return {"rate": r.status_code == 429}
        uuid = r.json().get("uuid")
    except requests.RequestException:
        return None
    res = None
    # a live scan finishes in ~15-30s; cap the wait at ~45s so dead domains fail fast (they are the
    # majority and would otherwise each waste ~72s), keeping each run roughly 2x faster
    for _ in range(9):
        time.sleep(5)
        try:
            rr = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", headers={**H, "API-Key": key}, timeout=30)
            if rr.status_code == 200:
                res = rr.json(); break
        except requests.RequestException:
            pass
    if not res:
        return {"scan_uuid": uuid, "found": 0}
    dom_file = shot_file = ""
    try:
        dr = requests.get(f"https://urlscan.io/dom/{uuid}/", headers={**H, "API-Key": key}, timeout=30)
        if dr.status_code == 200 and dr.text:
            os.makedirs(dom_dir, exist_ok=True)
            dom_file = os.path.join(dom_dir, f"{uuid}.html")
            open(dom_file, "w", encoding="utf-8").write(dr.text)
    except requests.RequestException:
        pass
    try:
        sr = requests.get(f"https://urlscan.io/screenshots/{uuid}.png", headers={**H, "API-Key": key}, timeout=30)
        if sr.status_code == 200 and sr.content:
            os.makedirs(shot_dir, exist_ok=True)
            shot_file = os.path.join(shot_dir, f"{uuid}.png")
            open(shot_file, "wb").write(sr.content)
    except requests.RequestException:
        pass
    js_out, js_n = fetch_external_js(uuid, res, key, js_dir)
    return {"scan_uuid": uuid, "found": 1, "dom_file": dom_file, "shot_file": shot_file,
            "js_dir": js_out, "js_count": js_n,
            "title": clean_title((res.get("page", {}) or {}).get("title", ""))}


def fetch_external_js(uuid, res, key, js_dir: str = JS_DIR):
    """Download the page's EXTERNAL JavaScript bodies from urlscan's stored responses (safe — served
    from urlscan's sandbox, never a direct hit on the phishing host). Bodies come gzip-encoded, so
    decompress. Returns (js_dir, count)."""
    import gzip
    reqs = (res.get("data", {}) or {}).get("requests", []) or []
    seen, saved = set(), 0
    out_dir = os.path.join(js_dir, uuid)
    for r in reqs:
        if saved >= MAX_JS:
            break
        resp = r.get("response", {}) or {}
        inner = resp.get("response", {}) or {}
        mime = (inner.get("mimeType") or "").lower()
        url = inner.get("url") or ""
        h = resp.get("hash") or ""
        is_js = "javascript" in mime or url.lower().split("?")[0].endswith(".js")
        if not is_js or not h or h in seen:
            continue
        seen.add(h)
        try:
            rr = requests.get(f"https://urlscan.io/responses/{h}/",
                              headers={**H, "API-Key": key}, timeout=30)
            if rr.status_code != 200 or not rr.content or len(rr.content) > MAX_JS_BYTES:
                continue
            body = rr.content
            if body[:2] == b"\x1f\x8b":          # gzip magic -> decompress
                try:
                    body = gzip.decompress(body)
                except Exception:
                    pass
            os.makedirs(out_dir, exist_ok=True)
            open(os.path.join(out_dir, f"{h[:16]}.js"), "wb").write(body)
            saved += 1
        except requests.RequestException:
            continue
    return (out_dir if saved else ""), saved


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-scan", action="store_true", help="Record new VN domains but skip urlscan capture")
    ap.add_argument("--now", default="", help="Detection timestamp; default: current time (capture-at-detection)")
    ap.add_argument("--max-scans", type=int, default=25, help="Cap urlscan submissions per cycle (quota)")
    args = ap.parse_args()
    now = args.now or _dt.datetime.now().replace(microsecond=0).isoformat()
    key = os.environ.get("URLSCAN_API_KEY", "")

    os.makedirs(OUTDIR, exist_ok=True)
    try:
        hosts = fetch_denylist()
    except Exception as e:
        print(f"[!] fetch failed: {e}", file=sys.stderr); return
    seen = load_seen()
    new_vn = [h for h in hosts if h not in seen and is_vn_target(h)]
    print(f"[i] denylist: {len(hosts)} domains, {len(new_vn)} NEW Vietnamese-targeting")
    if not new_vn:
        return
    # Process only a BOUNDED batch per cycle and mark ONLY the domains we actually attempt as seen
    # (like collect_vn_phishing) — so the rest of the backlog carries to later cycles. The full mirror
    # yields thousands of new VN domains; marking the whole set seen while capturing max-scans would
    # strand the remainder forever. (--no-scan records the whole new set, as before.)
    batch = new_vn if args.no_scan else new_vn[:args.max_scans]

    is_new_file = not os.path.exists(DET_PATH)
    fields = ["domain", "first_detected", "scan_uuid", "found", "dom_file", "shot_file", "title"]
    scans = 0
    processed = []
    with open(DET_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        if is_new_file:
            w.writeheader()
        for h in batch:
            row = {"domain": h, "first_detected": now, "found": 0}
            if not args.no_scan and key:
                res = urlscan_submit(h, key)
                if res and res.get("rate"):
                    print("[!] urlscan rate-limited; stopping this cycle (rest stay unseen)", file=sys.stderr)
                    break  # do NOT mark h seen — retry it next cycle
                elif res:
                    row.update({k: res.get(k, "") for k in ("scan_uuid", "found", "dom_file", "shot_file", "title")})
                    scans += 1
            w.writerow(row); f.flush()
            processed.append(h)
            print(f"[+] {h} -> {'captured' if row.get('found') else 'recorded'}")
    # mark only the domains we actually attempted (a rate-limit break leaves the rest for next cycle)
    with open(SEEN_PATH, "a", encoding="utf-8") as f:
        for h in processed:
            f.write(h + "\n")
    print(f"Done: processed {len(processed)}/{len(new_vn)} new VN ({scans} captured live) -> {DET_PATH}")


if __name__ == "__main__":
    main()
