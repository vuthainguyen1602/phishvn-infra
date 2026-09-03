#!/usr/bin/env python3
"""
watch_ct_benign.py — the TLD- and age-matched BENIGN arm for P4, sampled from raw CT logs.

WHY: `tinnhiem_benign` is 100% `.vn`; once the phishing arm dropped its `.vn` restriction, TLD
alone would separate the arms — the artefact family already caught three times in this study.

WHY NOT existing sources (measured 2026-08-03): urlscan is submission-biased toward threats
(first page: `schwab-open.cc`, `s1ndlyvpn.online`), so it would seed the benign arm with
phishing; crt.sh does not serve TLD-wide queries (`%.cc` 502, `%.online` 60 s timeout); Tranco is
years old against a days-old phishing arm — a comparator, not a match. Raw CT works because this
is SAMPLING, not filtering: a few batches per tick is a uniform draw from everything getting a
certificate, and the arm needs only a few hundred domains.

AGE MATCHING: reading the log head would make benign `cert_age_days` ~0 by construction and
manufacture "benign has newer certs". So `--age-days` names a target age, a binary search over
leaf timestamps finds the log offset where that age lives, and ticks spread across several ages
give the arm an age DISTRIBUTION the protocol can match to the phishing arm's.

EXCLUSIONS: drop Vietnamese brand tokens / common words, blocklisted names, free-hosting suffixes
(else the arm collects Vietnamese phishing by accident). Resulting asymmetry — benign guaranteed
NOT Vietnamese-targeting, phishing guaranteed to be — is safe only while the NAME is never a P4
feature; adding a name-derived feature invalidates this arm. State it in the paper.

OUTPUT. `data/raw/ct_benign/detections.csv`, the schema `watch_host_infra.py` reads. Add
    "ct_benign": ("benign", "first_detected")
to its SOURCES map and the infrastructure queue picks these up with no further wiring.

THE .vn SUPPLEMENT (2026-08-21 amendment to P4's pre-specification). The arm above never admits a
`.vn` name — TARGET_TLDS was measured over the phishing arm's non-.vn domains and `is_excluded`
drops the suffix — so the registered `.vn` group had no benign support (0 of 7,226 on 2026-08-21
against 33 `.vn` phishing). `--stratum vn` is that supplement: the SAME sampler, age search and
exclusions minus exactly the two rules that bar `.vn`, written to `data/raw/ct_benign_vn/` and
tagged by directory name as its own source. `.vn` is about one apex in 2,700 in the logs, so the
supplement reads the log tail SEQUENTIALLY from the age offset until `--target` names are found
or `--max-entries` are read. It fills `.vn` matching cells only; the default stratum is unchanged.

RUN:
  python scripts/watch_ct_benign.py --age-days 3 --batches 4    # one cron tick
  python scripts/watch_ct_benign.py --stratum vn --age-days 3   # the .vn supplement
  python scripts/watch_ct_benign.py --dry-run                   # sample, print, write nothing
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as _dt
import os
import random
import struct
import sys

import requests
import tldextract

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)
from audit_p4_labels import (HOSTED_SUFFIXES, VN_LEXICAL, load_blocklists,
                             registrable)
from psl import apex

# `registrable` reads the PSL with the private section on; this reads it with the private section
# off. Neither answer is wrong — the pair is the measurement, see under_private_suffix.
_ICANN_ONLY = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

H = {"User-Agent": "Mozilla/5.0 (research; contact thaivn_ph@utc.edu.vn)"}
LOG_LIST = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
STRATA = {"matched": "ct_benign", "vn": "ct_benign_vn"}


def paths(stratum: str) -> tuple[str, str, str]:
    """(outdir, detections.csv, seen_domains.txt) for a stratum; each stratum keeps its own."""
    outdir = os.path.join("data", "raw", STRATA[stratum])
    return outdir, os.path.join(outdir, "detections.csv"), os.path.join(outdir, "seen_domains.txt")


OUTDIR, DET_PATH, SEEN_PATH = paths("matched")
FIELDS = ["domain", "first_detected", "tld", "ct_log", "entry_index", "cert_not_before"]

# The phishing arm's TLD mix, measured 2026-08-03 over its 51 confirmed non-.vn domains: com 25,
# net 6, cc 5, info 2, online 2, then one each. Collection is deliberately BROADER than the
# target -- matching happens at analysis time, which is robust to the phishing mix drifting.
TARGET_TLDS = {"com", "net", "cc", "info", "online", "vip", "website", "bet", "site", "co",
               "org", "id", "me", "top", "su", "store", "xyz", "click", "link", "life"}


def usable_logs() -> list[str]:
    """Current usable logs, newest shards first. Google's own list is the authority on which logs
    are still accepting and serving entries; hardcoding a shard means breaking every January."""
    j = requests.get(LOG_LIST, headers=H, timeout=30).json()
    out = []
    for op in j.get("operators", []):
        for lg in op.get("logs", []):
            if "usable" in lg.get("state", {}):
                out.append(lg["url"].rstrip("/") + "/ct/v1/")
    return out


def leaf_timestamp(log: str, index: int) -> int | None:
    """Milliseconds since epoch recorded in the Merkle leaf at `index`, or None if unreadable."""
    try:
        r = requests.get(log + "get-entries", params={"start": index, "end": index},
                         headers=H, timeout=30)
        ents = r.json().get("entries", [])
        if not ents:
            return None
        return struct.unpack(">Q", base64.b64decode(ents[0]["leaf_input"])[2:10])[0]
    except (requests.RequestException, ValueError, KeyError, struct.error):
        return None


def find_offset(log: str, tree_size: int, target_ms: int, probes: int = 24) -> int | None:
    """Binary search the log for the first entry at or after `target_ms`.

    Entries are appended in submission order, so leaf timestamps are monotone enough to land within
    minutes of the target -- all the age control this arm needs. Unreadable probes shrink the window
    from whichever side is safe rather than aborting the search."""
    lo, hi = 0, tree_size - 1
    for _ in range(probes):
        if lo >= hi:
            break
        mid = (lo + hi) // 2
        ts = leaf_timestamp(log, mid)
        if ts is None:
            lo = mid + 1
            continue
        if ts < target_ms:
            lo = mid + 1
        else:
            hi = mid
    return lo if lo < tree_size else None


def names_from_entry(entry: dict) -> list[str]:
    """DNS names in one CT entry, for both leaf types.

    An X509 entry carries the certificate in the leaf; a precert carries only the TBS portion, which
    no X.509 loader accepts alone, so the certificate is read from `extra_data`. Skipping precerts
    would be simpler and would throw away about half the sample for no reason."""
    from cryptography import x509

    def sans(der: bytes) -> list[str]:
        cert = x509.load_der_x509_certificate(der)
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)

    try:
        leaf = base64.b64decode(entry["leaf_input"])
        if struct.unpack(">H", leaf[10:12])[0] == 0:            # X509 entry
            ln = struct.unpack(">I", b"\x00" + leaf[12:15])[0]
            return sans(leaf[15:15 + ln])
        extra = base64.b64decode(entry["extra_data"])           # precert: cert lives here
        ln = struct.unpack(">I", b"\x00" + extra[0:3])[0]
        return sans(extra[3:3 + ln])
    except Exception:
        return []                                                # must never stop the tick


def under_private_suffix(host: str) -> bool:
    """True when `host` is a tenant of a free-subdomain provider rather than a registration.

    The apex test in main() cannot see these. Under a PSL private-section suffix the registrable
    domain IS the full hostname, so a tenant passes the apex test as its own apex -- a live run
    admitted `d2w2y0vo2fk78q.amplifyapp.com` that way, and HOSTED_SUFFIXES missed it because no
    hand-listed set of providers is ever complete.

    So the question is asked of the PSL itself, by reading it twice: a name whose private-section
    registrable differs from its ICANN-only registrable is by definition under a suffix somebody
    registered as a hosting boundary, and a real registration reads identically both ways. That
    difference IS the definition, so it is the primary test and HOSTED_SUFFIXES is belt and braces."""
    h = str(host).lower()
    return registrable(h) != apex(_ICANN_ONLY(h)).lower()


def is_excluded(host: str, blocked: set[str], brand_re, keep_vn: bool = False) -> bool:
    """Anything that could be Vietnamese phishing is not eligible for the BENIGN arm.

    `keep_vn` lifts ONLY the suffix test, for the `.vn` supplement stratum; the Vietnamese-word
    list, brand tokens, blocklists and hosted/private suffixes apply to it unchanged (the
    amendment keeps them on purpose: they are what keeps phishing out of a benign arm)."""
    h = host.lower().lstrip("*.")
    if not h or "." not in h:
        return True
    if under_private_suffix(h):
        return True
    if any(h.endswith("." + s) or h == s for s in HOSTED_SUFFIXES):
        return True
    if (h.endswith(".vn") and not keep_vn) or VN_LEXICAL.search(h):
        return True
    if brand_re is not None and brand_re.search(h):
        return True
    return registrable(h) in blocked


def load_seen(path: str = SEEN_PATH) -> set[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return {x.strip() for x in f if x.strip()}
    except OSError:
        return set()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--age-days", type=float, default=3.0,
                    help="target certificate age to sample at; the point of the binary search")
    ap.add_argument("--batches", type=int, default=4, help="entry batches to draw this tick")
    ap.add_argument("--batch-size", type=int, default=32,
                    help="entries per request; logs cap this well below what is asked")
    ap.add_argument("--dry-run", action="store_true", help="print the sample, write nothing")
    ap.add_argument("--stratum", choices=sorted(STRATA), default="matched",
                    help="matched = the TLD-matched arm (default); vn = the .vn supplement")
    ap.add_argument("--target", type=int, default=10,
                    help="vn stratum: stop a tick once this many .vn names are kept")
    ap.add_argument("--max-entries", type=int, default=60000,
                    help="vn stratum: CT entries to read per tick before giving up")
    args = ap.parse_args()
    vn = args.stratum == "vn"
    outdir, det_path, seen_path = paths(args.stratum)

    from watch_urlscan_brands import load_official
    from vn_filter import BRAND_TOKENS

    logs = usable_logs()
    if not logs:
        print("[!] no usable CT logs in the published list", file=sys.stderr)
        return 1
    random.shuffle(logs)

    blocked = set().union(*load_blocklists().values()) if load_blocklists() else set()
    official = {d.lower() for d in load_official()}
    seen = load_seen(seen_path)
    target_ms = int((_dt.datetime.now(_dt.timezone.utc)
                     - _dt.timedelta(days=args.age_days)).timestamp() * 1000)

    kept, scanned, read = [], 0, 0
    # The matched arm draws `--batches` short batches per log. The .vn supplement instead walks the
    # tail from the age offset in the largest batches the log serves, until `--target` or `--max-entries`.
    if vn:
        # Depth, not breadth: every log costs ~24 probe requests to find the age offset, so the
        # supplement walks a few logs far rather than forty logs shallowly.
        logs = logs[:4]
    # Logs serve far fewer entries per request than asked (~85 of 256 on the first live tick), so the
    # supplement's per-log budget is in ENTRIES READ, with a request cap only as a runaway guard.
    per_log = args.batches if not vn else 400
    per_log_entries = args.max_entries // len(logs) if vn else None
    bsize = args.batch_size if not vn else 256
    for log in logs:
        if (not vn and len(kept) >= args.batches * 4) or (vn and len(kept) >= args.target) \
                or (vn and read >= args.max_entries):
            break
        try:
            size = requests.get(log + "get-sth", headers=H, timeout=30).json()["tree_size"]
        except (requests.RequestException, ValueError, KeyError):
            continue
        off = find_offset(log, size, target_ms)
        if off is None:
            continue
        start = off
        log_read = 0
        for _b in range(per_log):
            if vn and (len(kept) >= args.target or read >= args.max_entries
                       or log_read >= per_log_entries):
                break
            try:
                r = requests.get(log + "get-entries",
                                 params={"start": start, "end": start + bsize - 1},
                                 headers=H, timeout=45)
                entries = r.json().get("entries", [])
            except (requests.RequestException, ValueError):
                break
            if not entries:
                break
            read += len(entries)
            log_read += len(entries)
            for i, e in enumerate(entries):
                ts = struct.unpack(">Q", base64.b64decode(e["leaf_input"])[2:10])[0]
                when = _dt.datetime.fromtimestamp(ts / 1000, _dt.timezone.utc)
                for host in names_from_entry(e):
                    scanned += 1
                    h = host.lower().lstrip("*.")
                    reg = registrable(h)
                    # One certificate lists many SANs that are not registrations of their own (`www.` duplicates,
                    # tenant infra). P4's unit is the registration, so only the apex counts -- subdomains would file
                    # a host's DNS/TLS under its tenants, the `pages.dev` collapse in reverse.
                    if h not in (reg, "www." + reg):
                        continue
                    tld = reg.rsplit(".", 1)[-1]
                    # The stratum's TLD rule: the matched arm keeps the allow-list; the .vn supplement keeps exactly
                    # the names it could never admit (`.vn` and every second-level `.com.vn`/`.gov.vn` suffix).
                    if (tld != "vn" if vn else tld not in TARGET_TLDS) or reg in seen:
                        continue
                    if reg in official:
                        continue
                    if is_excluded(reg, blocked, BRAND_TOKENS, keep_vn=vn):
                        continue
                    seen.add(reg)
                    kept.append({"domain": reg,
                                 "first_detected": when.replace(microsecond=0,
                                                                tzinfo=None).isoformat(),
                                 # removesuffix, not rstrip: rstrip("/ct/v1/") strips CHARACTERS,
                                 # so a log whose name ends in c, t, v or 1 loses them.
                                 "tld": tld,
                                 "ct_log": log.removesuffix("/ct/v1/").rsplit("/", 1)[-1],
                                 "entry_index": start + i, "cert_not_before": ""})
            start += len(entries)

    print(f"[i] {args.stratum}: sampled {scanned} DNS names in {read} entries at "
          f"~{args.age_days:g}d old -> {len(kept)} benign candidates "
          f"({'.vn' if vn else 'target TLDs'})")
    if args.dry_run:
        for row in kept[:25]:
            print("   ", row["domain"], row["tld"], row["first_detected"])
        return 0

    os.makedirs(outdir, exist_ok=True)
    new_file = not os.path.exists(det_path)
    with open(det_path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new_file:
            w.writeheader()
        w.writerows(kept)
    with open(seen_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(seen)) + "\n")
    print(f"[+] {det_path} (+{len(kept)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
