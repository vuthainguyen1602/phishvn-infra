#!/usr/bin/env python3
"""
watch_ct_brands.py — Certificate Transparency feed of Vietnamese brand-impersonation domains.

urlscan only sees a domain after someone submits it; CT publishes the hostname the moment a cert
is issued — which VN phishing kits do before the page has content. Polls crt.sh with one
prefix query per brand token (see patterns()) rather than tailing raw CT logs. THE WINDOW is far wider than the cadence (168h) because
crt.sh's ingestion lag is hours and anything outside the window is lost silently. A hit is a
CANDIDATE, not a labelled phish; capture happens elsewhere. Brand tokens, the official-domain
whitelist and the token boundary rule are imported from watch_urlscan_brands.py so the two feeds
cannot drift apart.

RUN:
  python scripts/watch_ct_brands.py --hours 6            # normal cron tick
  python scripts/watch_ct_brands.py --hours 168          # one-off backfill of the past week
Why crt.sh over certstream, and how 168h was measured: docs/design-notes/watch-ct-brands.md
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)
from watch_urlscan_brands import (
    DEFAULT_TOKENS, load_official, is_official, token_at_boundary,
)
from vn_filter import (
    FOREIGN_CCTLDS, FOREIGN_KEYWORDS, VN_CONTEXT_TOKENS,
    NON_POLICE_CONGANH, NON_PUBLIC_SERVICE_DVC,
)

H = {"User-Agent": "Mozilla/5.0 (research; contact thaivn_ph@utc.edu.vn)"}
CRTSH = "https://crt.sh/"
OUTDIR = os.path.join("data", "raw", "ct_brands")

FIELDS = ["domain", "first_detected", "brand", "wildcard", "crtsh_id", "common_name",
          "issuer", "entry_timestamp", "not_before", "not_after"]

# Registered domains this feed reported that belong to the brand itself, confirmed by the author on
# 2026-09-19 after reading all 103 rows (docs/decisions/ct-brands-brand-owned.md). Kept HERE and
# not added to load_official(): that whitelist also filters urlscan_brands, a source named in a
# registration, and a CT-side finding should not move it. A prefix query makes these likelier than
# they were: `viettel%` answers with every host the operator runs under a name it owns.
# Rows already in detections.csv stay; whatever reads that file applies this set (it is imported,
# not copied).
CT_BRAND_OWNED = frozenset({
    "viettel.io", "viettelcloud.vn", "viettelstore.vn", "viettelmedia.vn", "vnptcloud.vn",
    "ahamove.com", "bidv.com.mm", "ebanking-vietinbank.de",
    # added later the same day, on measured evidence (decision file): same two Viettel addresses
    # and name servers as viettelcloud.vn; and one tenant HOST on cloudhms.io, whose registrant is
    # Vingroup's hotel-software company. The platform itself is multi-tenant and is not listed.
    "viettelcloud.com.vn", "vinpearltravel.cloudhms.io",
    # the registry's own WHOIS, read by the author on 2026-09-19: registrant Ngan Hang TMCP Tien
    # Phong, registered 2008, delegated to the two Akamai name servers measured the same morning
    "tpbankgroup.com.vn",
    # registrar-API record of 2026-09-19: the same VNPT cloud centre that registered vnptcloud.vn
    "vnptplatform.vn",
})

# Two noise rules, decided 2026-09-19 on the same reading of the 103 rows (same decision file).
# Both are consequences of asking by prefix, so both live in this feed.
# (a) A managed cache or database endpoint gets a machine-made hostname, and some of those happen
# to begin with four letters that spell a token (`bidvqipiy....cache.amazonaws.com`). Nobody is
# shown such a name; 3 of the first 103 rows were these.
CLOUD_INTERNAL_SUFFIXES = (".amazonaws.com",)
# (b) `bidv%` returned 23 names and 17 were English words that start the same way (`bidvest*`,
# `bidverse*`, `bidvault`). token_at_boundary() cannot help: under a prefix query the token always
# starts the name. So a token this short must also END at a boundary.
SHORT_TOKEN_MAX = 4


def short_token_closed(domain: str, tok: str) -> bool:
    """A token of SHORT_TOKEN_MAX characters or fewer must be followed by a non-letter or end its
    label: keeps `bidv-kiemtra`, `bidv2026.ato.vn`, `bidv.com.mm`, `vnpt365`; drops `bidvest`,
    `bidverse`, `utc2cly1...`. The stated cost: `vnptmytv.com` and `vnptwifi24h.com`, which read
    like resellers, are dropped with them. Longer tokens pass untouched."""
    if len(tok) > SHORT_TOKEN_MAX:
        return True
    for label in re.split(r"[.\-_]", domain.lower()):
        i = label.find(tok)
        while i != -1:
            j = i + len(tok)
            if (i == 0 or not label[i - 1].isalpha()) and (j == len(label) or not label[j].isalpha()):
                return True
            i = label.find(tok, i + 1)
    return False


def load_seen(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return {l.strip().removeprefix("www.") for l in f if l.strip()}


def patterns(token: str, seen_rows: dict[str, int]) -> list[str]:
    """The crt.sh identity patterns asked for one token. `token%` always; `%token%` only for a
    token that form has answered before.

    Measured 2026-09-18, same minute, crt.sh healthy (8 of 8 requests 200): `%techcombank%` -> an
    empty 200 in 0.9s; `techcombank.com.vn` -> 121 certs; `techcombank%` -> 866 certs naming 396
    hosts that carry the token, 51 of them neither the bank's nor a .ph registry wildcard
    (`techcombanks.com`, `techcombank.icu`). `%mbbank%` and `%shopeevn%` were empty the same way,
    while `vnpay%` returned 656 certs and `dichvucong%` 435. crt.sh cannot serve a pattern with a
    wildcard at BOTH ends against hostnames — what `%vietcombank%` does return are
    organizationName matches — and it says so with an empty 200, not an error. That, not an
    outage, is why ~170 of 190 tokens sat UNRESOLVED for 82 consecutive ticks.
    The prefix form only sees names that BEGIN with the token (`techcombank-vn.com`, not
    `login-techcombank.com`): partial coverage, stated as such. The substring form is kept for
    the tokens it has answered, since those organizationName matches are a different set of
    certificates; asking it of the rest would spend the run deadline on a question already
    answered empty 82 times."""
    pats = [f"{token}%"]
    if seen_rows.get(token, 0) > 0:
        pats.append(f"%{token}%")
    return pats


def history_key(token: str, pattern: str) -> str:
    """token_rows.json key for a pattern's high-water mark. The substring form keeps the bare
    token it has been stored under since 2026-08; the prefix form is stored under the pattern."""
    return token if pattern.startswith("%") else pattern


def search(pattern: str, attempts: int = 3, backoff: float = 20.0) -> list[dict] | None:
    """One identity query against crt.sh (see patterns()). Returns None (not []) on failure — the
    caller must tell 'crt.sh was down' from 'no matches'. No server-side date filter exists; the
    caller windows client-side. deduplicate=Y collapses precert/cert pairs. exclude=expired is what
    makes heavy tokens answerable at all (measured 2026-07-26: `%viettel%` 61s -> gateway death
    without it, 7.6s with it; nothing in-window can already be expired). Retries are patient
    (crt.sh 502s often — 5 failures in 6 tries in one bad spell) but bounded by main()'s run
    deadline; a failed or unreached token just rides a later tick — the window overlaps the
    cadence several times over and `seen` makes re-reporting free."""
    for i in range(attempts):
        try:
            r = requests.get(CRTSH, headers=H, timeout=90,
                             params={"q": pattern, "output": "json",
                                     "deduplicate": "Y", "exclude": "expired"})
            if r.status_code == 200:
                return r.json()
            # Every other status, 404 included, is a failure: "no matches" is an empty 200 array,
            # so a 404 means the front end is unwell or the API moved — not a quiet day.
        except (requests.RequestException, ValueError):
            pass                          # timeout, 5xx-as-HTML, truncated JSON: retry
        if i < attempts - 1:
            time.sleep(backoff * (i + 1))
    return None


def parse_ts(s: str):
    """crt.sh timestamps are UTC, second or sub-second precision, no zone suffix."""
    try:
        return datetime.strptime((s or "")[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=168,
                    help="report certs whose CT entry (or not_before) falls in the last N hours; "
                         "far wider than the cadence on purpose — see THE WINDOW in the docstring")
    ap.add_argument("--tokens", nargs="+", default=DEFAULT_TOKENS)
    ap.add_argument("--delay", type=float, default=5.0,
                    help="seconds between crt.sh queries (be polite; it is a shared free service)")
    ap.add_argument("--deadline-min", type=float, default=90,
                    help="abandon the remaining tokens after this long; they ride the next tick")
    # 25 was the original budget and it was spent by FAILURES, not by work: search() is
    # deliberately patient, so one unreachable token costs up to 3*90s of timeout plus 20+40s of
    # backoff = 5.5 min, while a token that answers costs ~8s plus the 5s delay. On 2026-08-28
    # crt.sh was failing 10 of 34 tokens a tick: 10*5.5 = 55 min of the 25 available, so 15
    # tokens were deferred every tick and the far end of the list went unqueried for days.
    # 90 fits the observed bad case (10 failures + 24 answers ~= 61 min) inside the 2-hourly
    # cadence with margin for the capture bridge that runs after this under the same lock. It
    # does NOT shorten the retries: giving up faster on a service that 502s in bursts would buy
    # coverage by lowering the answer rate, which is the wrong trade for a feed this thin.
    ap.add_argument("--outdir", default=OUTDIR)
    args = ap.parse_args()

    det_path = os.path.join(args.outdir, "detections.csv")
    seen_path = os.path.join(args.outdir, "seen_domains.txt")
    os.makedirs(args.outdir, exist_ok=True)

    official, seen = load_official() | CT_BRAND_OWNED, load_seen(seen_path)
    # naive-UTC on purpose: crt.sh timestamps are naive UTC strings, and .replace(tzinfo=None)
    # keeps this working on the Jetson's pre-3.11 Python (no datetime.UTC there)
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=args.hours)
    cand: dict[str, dict] = {}
    failed: list[str] = []

    # Resume cursor advances by tokens ACTUALLY queried, not by clock: a clock-derived offset
    # walks one token per tick while the deadline can defer twenty-odd, leaving the far end of
    # the list unqueried for days during a crt.sh bad spell — silent permanent loss.
    toks = list(args.tokens)
    cur_path = os.path.join(args.outdir, "cursor.txt")
    start = 0
    if toks and os.path.exists(cur_path):
        try:
            with open(cur_path, encoding="utf-8") as f:
                start = int(f.read().strip()) % len(toks)
        except (OSError, ValueError):
            start = 0
    toks = toks[start:] + toks[:start]

    # per-token high-water mark of rows crt.sh has ever returned, used to tell a genuine
    # "no matches" apart from an empty 200 (see the loop below)
    rows_path = os.path.join(args.outdir, "token_rows.json")
    try:
        with open(rows_path, encoding="utf-8") as f:
            _raw = json.load(f)
            seen_rows = {str(k): int(v) for k, v in _raw.get("rows", _raw).items()}
            tries = {str(k): int(v) for k, v in _raw.get("unresolved_ticks", {}).items()}
    except (OSError, ValueError):
        seen_rows = {}
        tries = {}

    deadline = time.monotonic() + args.deadline_min * 60
    skipped: list[str] = []
    unproven: list[str] = []      # empty 200s from tokens with no row history (verdict below)
    unresolved_now: list[str] = []  # the subset the verdict could not settle, for the summary
    answered = False              # did crt.sh return a single row this tick?
    for i, tok in enumerate(toks):
        if time.monotonic() > deadline:
            skipped = toks[i:]
            print(f"[!] deadline reached — {len(skipped)} tokens deferred to the next tick",
                  flush=True)
            break
        for pat in patterns(tok, seen_rows):
            key = history_key(tok, pat)
            rows = search(pat)
            if rows is None:
                failed.append(pat)
                print(f"[!] {pat}: crt.sh unreachable after retries", flush=True)
                time.sleep(args.delay)
                continue
            # crt.sh's third, quietest failure mode: under load it answers 200 with no rows. A token
            # that has returned rows before is expected to keep doing so, so an empty answer for it
            # is a failed query, not coverage.
            if not rows:
                if seen_rows.get(key, 0) > 0:
                    failed.append(pat)
                    print(f"[!] {pat}: empty 200 from crt.sh, but it returned "
                          f"{seen_rows[key]} certs before — treating as a failed query", flush=True)
                else:
                    # COLD START (2026-08-25): the high-water guard above can never fire for a token
                    # whose FIRST query came back empty — it stays at 0, so every later empty 200 was
                    # silently booked as coverage. 22 of the 34 tokens sat at 0 for a month that
                    # way — only 12 have ever returned a row.
                    # With no history, the only evidence about an empty answer is whether crt.sh
                    # proved this tick it can answer at all, so the verdict waits for `answered`.
                    unproven.append(pat)
                time.sleep(args.delay)
                continue
            seen_rows[key] = max(seen_rows.get(key, 0), len(rows))
            answered = True
            print(f"[.] {pat}: {len(rows)} certs in history", flush=True)
            for row in rows:
                # window on entry_timestamp OR not_before: a late-ingested-but-fresh cert should
                # still surface rather than fall outside both edges
                ets, nbf = parse_ts(row.get("entry_timestamp", "")), parse_ts(row.get("not_before", ""))
                if not ((ets and ets >= cutoff) or (nbf and nbf >= cutoff)):
                    continue
                # name_value carries every SAN, newline-separated; wildcards mark kit infrastructure.
                # common_name is read as a name source too, not just recorded as metadata: crt.sh's
                # LIKE search (q=%token%) returns only the identity that MATCHED, and for most VN
                # brand tokens that is an organizationName, never a dNSName — measured 2026-08-25,
                # %vietcombank% returns 47 rows whose name_value parses to ZERO domains ("VIETCOMBANK
                # SECURITIES COMPANY LIMITED") while the cert's hostname sits in common_name
                # (www.vcbs.com.vn), so such a row was unusable. The filters below keep this honest:
                # an org name loses on the space check, and a host that merely belongs to the brand
                # loses on is_official / token_at_boundary.
                names = str(row.get("name_value", "")).split("\n")
                names.append(str(row.get("common_name", "")))
                for name in names:
                    name = name.strip().lower().rstrip(".")
                    wildcard = 1 if name.startswith("*.") else 0
                    dom = name.removeprefix("*.").removeprefix("www.")
                    # SANs are not all hostnames: rfc822 names (admin@x-vietcombank.com) and
                    # multi-level wildcards (*.*.x.com) would otherwise reach urlscan as garbage URLs
                    if not dom or "." not in dom or any(c in dom for c in " @*_"):
                        continue
                    if dom in seen or dom in cand or is_official(dom, official):
                        continue
                    # Screen out foreign sovereign ccTLDs (.in, .lk, .ph, .id, .br, etc.)
                    if any(dom.endswith(sfx) for sfx in FOREIGN_CCTLDS):
                        continue
                    # Screen out foreign language lure words (Indonesian, Portuguese, etc.)
                    if FOREIGN_KEYWORDS.search(dom) and not VN_CONTEXT_TOKENS.search(dom):
                        continue
                    # Screen out "Bồ Công Anh" (dandelion) falsely matching "bocongan" / "congan"
                    if NON_POLICE_CONGANH.search(dom):
                        continue
                    # Screen out non-public-service compound businesses falsely matching "dichvucong"
                    if NON_PUBLIC_SERVICE_DVC.search(dom):
                        continue
                    if not token_at_boundary(dom, tok):
                        continue
                    if dom.endswith(CLOUD_INTERNAL_SUFFIXES) or not short_token_closed(dom, tok):
                        continue
                    cand[dom] = {
                        "domain": dom, "brand": tok, "wildcard": wildcard,
                        "crtsh_id": row.get("id", ""),
                        "common_name": str(row.get("common_name", "")).lower(),
                        "issuer": row.get("issuer_name", ""),
                        "entry_timestamp": row.get("entry_timestamp", ""),
                        "not_before": row.get("not_before", ""),
                        "not_after": row.get("not_after", ""),
                    }
            time.sleep(args.delay)

    # Deferred verdict on the cold-start empties: if not one token returned a row all tick, crt.sh
    # was unwell and those empty 200s are failed queries, not evidence that the brand has no certs.
    if unproven:
        if answered:
            # NOT "no certs". Measured 2026-09-11: `%dichvucong%` answered 200 with an empty
            # array while `dichvucong.gov.vn` returned 15 certs minutes apart, and urlscan had
            # already found 182 live domains carrying that token. crt.sh appears to answer a
            # broad pattern it cannot compute in time with an empty 200 rather than an error,
            # and the cheap patterns that do answer say nothing about the expensive ones -- the
            # high-water guard above has not fired once in 562 ticks. So an empty answer from a
            # token that has never returned a row is an UNRESOLVED query, and calling it coverage
            # is how this watcher spent three weeks reporting "0 new candidates" as a finding.
            # 2026-09-18: the cause turned out to be the both-ends pattern itself (patterns()), and
            # the prefix form answers. An empty `token%` is likelier to be a true absence than an
            # empty `%token%` ever was, but one answer cannot tell the two apart either, so the
            # accounting is unchanged and is now kept per pattern.
            unresolved_now = list(unproven)
            for t in unproven:
                tries[t] = tries.get(t, 0) + 1
            worst = max(tries.get(t, 1) for t in unproven)
            print(f"[?] {len(unproven)} pattern(s) UNRESOLVED — crt.sh returned an empty 200 and "
                  f"they have never returned a row (up to {worst} ticks now); this is not "
                  f"evidence that the brand has no certs: {', '.join(unproven)}", flush=True)
        else:
            failed.extend(unproven)
            print(f"[!] {len(unproven)} empty 200(s) and not one row returned all tick — counting "
                  f"them as failed queries, not coverage: {', '.join(unproven)}", flush=True)

    try:
        with open(rows_path, "w", encoding="utf-8") as f:
            json.dump({"rows": seen_rows, "unresolved_ticks": tries}, f, sort_keys=True)
    except OSError as e:
        print(f"[!] could not persist token row counts ({e})", flush=True)

    queried = len(toks) - len(skipped)
    if toks:                       # persist the resume point before anything else can fail
        try:
            with open(cur_path, "w", encoding="utf-8") as f:
                f.write(str((start + queried) % len(toks)))
        except OSError as e:
            print(f"[!] could not persist cursor ({e}) — next run restarts at the same token",
                  flush=True)
    status = (f"[i] {queried}/{len(toks)} tokens queried, window {args.hours:g}h "
              f"-> {len(cand)} new candidate domains")
    if failed:
        status += f" | {len(failed)} FAILED (crt.sh unreachable): {', '.join(failed)}"
    # The summary line is what the cron log shows and what a human reads. Without this it said
    # "179/179 tokens queried -> 0 new candidate domains" on a tick where 152 of them were never
    # actually answered, which reads as coverage and was the whole defect.
    if unresolved_now:
        status += f" | {len(unresolved_now)} UNRESOLVED (empty 200, never proven)"
    if skipped:
        status += f" | {len(skipped)} deferred: {', '.join(skipped)}"
    print(status)
    if not cand:
        return 0

    # UTC, matching the crt.sh timestamps in the row: local time would add +7h of fictitious
    # latency to first_detected - not_before, the very quantity this feed exists to make small.
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    fresh = not os.path.exists(det_path)
    with open(det_path, "a", newline="", encoding="utf-8") as f, \
            open(seen_path, "a", encoding="utf-8") as sf:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if fresh:
            w.writeheader()
        for dom, row in cand.items():
            row["first_detected"] = now
            w.writerow({k: row.get(k, "") for k in FIELDS})
            sf.write(dom + "\n")
            # flush BOTH every row: the files buffer independently, so a crash between them
            # loses or duplicates a detection, and a torn CSV line misfeeds the bridge's reader
            f.flush()
            sf.flush()
            print(f"[+] {dom} ({row['brand']}) cert not_before={str(row.get('not_before') or '')[:10]}")
    print(f"Done: {len(cand)} new -> {det_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
