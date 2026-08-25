#!/usr/bin/env python3
"""
watch_host_infra.py — Capture WHOIS/DNS/TLS infrastructure of detected domains AT DETECTION TIME.

WHY: phishing infrastructure (registrar, NS, hosting IP, cert issuer, domain age) dies within
days and cannot be reconstructed later, unlike URL/HTML features. Tails every detections.csv,
enriches unseen domains, appends one row per observation to data/raw/host_infra/host_infra.csv.
Raw values stored (IPs, NS hosts, dates, issuer DN), never derived booleans — raw can be
recomputed forever.

RETRIES: CT sees a lookalike at cert issuance, often before its DNS exists, so a no-A-record
domain is re-attempted (up to --max-attempts, while younger than --max-age-days). A domain with
an A record is done; the append-only log is the retry state. MEASURED 2026-08-03
(scripts/audit_infra_capture.py): of 1,950 re-attempted domains ZERO gained an A record — the
backlog was enriched days late, already dead. Kept (cost negligible, CT-before-DNS real for live
detections), but do NOT claim the retry recovers captures until that number is non-zero.

WHOIS SCOPE: WHOIS and NS/MX on the REGISTERED domain, which since 2026-08-03 means the tenant's
own name on a free-subdomain host (foo.weebly.com, not weebly.com — see registered_domain below).
Such names have no registration, so blank whois_*/ns_count 0 is the honest observation — the
alternative files Weebly's WHOIS under the attacker. Both full host and registered domain are
recorded. DNS A/CNAME and TLS are on the full host — the machine serving the lure.

KNOWN LIMIT: .vn has no public WHOIS (verified 2026-07-30: whois.net.vn refuses :43,
rdap.vnnic.vn does not resolve, .vn absent from IANA RDAP bootstrap) — whois_* stays blank there;
use tls_not_before as the age proxy (fresh phishing certs postdate registration by hours).

RUN (cron tick on the Jetson, via host_infra_run.sh):
  python3 scripts/watch_host_infra.py
  python3 scripts/watch_host_infra.py --max-domains 10 --delay 0.2   # gentle manual run
"""
from __future__ import annotations

import argparse
import csv
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs  # noqa: E402
    add_script_dirs()
except ImportError:          # flat layout (public mirror): scripts/ sits under ROOT
    ROOT = os.path.dirname(_HERE)
from psl import registered_domain  # noqa: E402  (shared with the evaluation code)

OUTDIR = os.path.join("data", "raw", "host_infra")
OUT = os.path.join(OUTDIR, "host_infra.csv")

# source dir -> (label, date column). Every detections.csv has `domain` as its first column.
SOURCES = {
    "vn_phishing_live": ("phish", "first_detected"),
    "chongluadao_live": ("phish", "first_detected"),
    "urlscan_brands": ("phish", "first_detected"),
    "ct_brands": ("phish", "first_detected"),
    "tinnhiem_benign": ("benign", "first_captured"),
    # TLD- and age-matched benign arm for P4 (watch_ct_benign.py). tinnhiem_benign is 100% .vn and
    # stopped matching the phishing arm the moment that arm dropped its .vn restriction.
    "ct_benign": ("benign", "first_detected"),
    # The .vn supplement of that arm (watch_ct_benign.py --stratum vn; 2026-08-21 amendment).
    # Its own source so the analysis can confine it to .vn matching cells.
    "ct_benign_vn": ("benign", "first_detected"),
}

FIELDS = [
    "domain", "registered_domain", "source", "label", "first_detected", "captured_at", "attempt",
    # DNS on the full host
    "a_records", "a_ttl", "cname",
    # DNS on the registered domain
    "ns_count", "ns_hosts", "mx_count",
    # WHOIS on the registered domain
    "whois_created", "whois_expires", "whois_updated", "registrar", "whois_age_days",
    # TLS on the full host
    "tls_present", "tls_verified", "tls_issuer", "tls_subject_cn",
    "tls_not_before", "tls_not_after", "tls_san_count",
]

# registered_domain() moved to scripts/psl.py on 2026-08-18: the strict-temporal evaluation
# drops same-registrable-domain re-detections and must fold hosts exactly as this collector does,
# so the two share one implementation rather than two copies that can drift apart. The unit and
# its 2026-08-03 change of convention are documented there.


def _resolver():
    """The resolver, or a loud death. The import used to sit inside the try that catches NXDOMAIN,
    so a machine without dnspython silently recorded empty a_records indistinguishable from real
    measurements — it cost a run of 360 observations (spot-check: 47/50 resolved fine). A missing
    dependency must stop the collector, never generate null results."""
    try:
        import dns.resolver
    except ImportError:
        raise SystemExit(
            "dnspython is not installed, so no DNS question can be asked. Refusing to run: every\n"
            "row this produces would record 'no A record' for domains that were never queried, and\n"
            "downstream conditioning cannot tell that apart from a domain that is genuinely dead.\n"
            "    pip install dnspython")
    r = dns.resolver.Resolver()
    r.lifetime = 5
    return r


def dns_host(host: str) -> dict:
    """A records (following CNAMEs), TTL, and the CNAME target if one exists."""
    out = {"a_records": "", "a_ttl": "", "cname": ""}
    r = _resolver()
    # Broad on purpose: NXDOMAIN, SERVFAIL and timeout are all real answers, honestly recorded as
    # empty fields. Only the missing-library case above is a non-answer, hence the raise there.
    try:
        ans = r.resolve(host, "A")
        out["a_records"] = ";".join(sorted(a.address for a in ans))
        out["a_ttl"] = ans.rrset.ttl
    except Exception:
        pass
    try:
        out["cname"] = str(r.resolve(host, "CNAME")[0].target).rstrip(".")
    except Exception:
        pass
    return out


def dns_reg(reg: str) -> dict:
    out = {"ns_count": "", "ns_hosts": "", "mx_count": ""}
    r = _resolver()
    try:
        ns = sorted(str(x.target).rstrip(".") for x in r.resolve(reg, "NS"))
        out["ns_count"], out["ns_hosts"] = len(ns), ";".join(ns)
    except Exception:
        out["ns_count"] = 0
    try:
        out["mx_count"] = len(list(r.resolve(reg, "MX")))
    except Exception:
        out["mx_count"] = 0
    return out


def whois_reg(reg: str) -> dict:
    out = {"whois_created": "", "whois_expires": "", "whois_updated": "", "registrar": "",
           "whois_age_days": ""}

    def one(v):
        if isinstance(v, list):
            v = v[0] if v else None
        return v

    try:
        import whois
        try:
            w = whois.whois(reg, quiet=True)  # quiet: NICClient prints socket errors to stderr
        except TypeError:                     # older python-whois without the flag
            w = whois.whois(reg)
        c, e, u = one(w.creation_date), one(w.expiration_date), one(w.updated_date)
        if c:
            out["whois_created"] = c.isoformat()
            if c.tzinfo is None:
                c = c.replace(tzinfo=timezone.utc)
            out["whois_age_days"] = (datetime.now(timezone.utc) - c).days
        if e:
            out["whois_expires"] = e.isoformat()
        if u:
            out["whois_updated"] = u.isoformat()
        out["registrar"] = (w.registrar or "").strip()
    except Exception:
        pass
    return out


def tls_host(host: str) -> dict:
    """Verified handshake first (full cert dict). If verification fails — self-signed, expired,
    hostname mismatch — fall back to CERT_NONE just to record that a listener presented a cert:
    the stdlib returns no parseable cert dict on an unverified handshake, so details stay blank
    and tls_verified=0 marks the observation."""
    out = {"tls_present": 0, "tls_verified": 0, "tls_issuer": "", "tls_subject_cn": "",
           "tls_not_before": "", "tls_not_after": "", "tls_san_count": ""}

    def rdn(seq, key):
        for r in seq or ():
            for k, v in r:
                if k == key:
                    return v
        return ""

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(8)
            s.connect((host, 443))
            cert = s.getpeercert()
        out["tls_present"] = out["tls_verified"] = 1
        out["tls_issuer"] = rdn(cert.get("issuer"), "organizationName") or \
            rdn(cert.get("issuer"), "commonName")
        out["tls_subject_cn"] = rdn(cert.get("subject"), "commonName")
        for src, dst in (("notBefore", "tls_not_before"), ("notAfter", "tls_not_after")):
            if cert.get(src):
                out[dst] = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(cert[src]), tz=timezone.utc).isoformat()
        out["tls_san_count"] = len(cert.get("subjectAltName", ()))
    except ssl.SSLError:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(8)
                s.connect((host, 443))
            out["tls_present"] = 1
        except Exception:
            pass
    except Exception:
        pass
    return out


# A detection older than this was already dead by the time we could reach it: measured over the
# backlog, domains enriched a median 84.9h after detection retained an A record 11% of the time,
# against 100% for domains reached within ~1.2h (scripts/audit_infra_capture.py).
FRESH_HOURS = 24.0


def load_candidates(fresh_hours: float = FRESH_HOURS) -> list:
    """(domain, source, label, first_detected) ordered by PERISHABILITY, not label: perishable
    phishing first, then benign, stale backlog last. Sorting all phishing first put 4,748
    long-dead backlog domains ahead of every benign domain — starving the benign arm on captures
    yielding ~11% that the study discards anyway. Stale phishing is already spoiled."""
    rows, seen = [], set()
    now = datetime.now()
    for src, (label, datecol) in SOURCES.items():
        path = os.path.join("data", "raw", src, "detections.csv")
        if not os.path.exists(path):
            continue
        with open(path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                d = (r.get("domain") or "").strip().lower()
                if d and d not in seen:
                    seen.add(d)
                    rows.append((d, src, label, (r.get(datecol) or "").strip()))

    def age_hours(first: str) -> float:
        try:
            return (now - datetime.fromisoformat(first)).total_seconds() / 3600
        except ValueError:
            return float("inf")            # undated: treat as stale, never as perishable

    def priority(t) -> int:
        _, _, label, first = t
        if label == "phish":
            return 0 if age_hours(first) <= fresh_hours else 2
        return 1

    rows.sort(key=lambda t: t[3], reverse=True)      # newest first ...
    rows.sort(key=priority)                          # ... within perishable / benign / stale
    return rows


def load_state() -> dict:
    """domain -> (attempts, ever_had_a) from the append-only log."""
    state = {}
    if not os.path.exists(OUT):
        return state
    with open(OUT, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            d = r["domain"]
            att, had = state.get(d, (0, False))
            state[d] = (max(att, int(r.get("attempt") or 1)), had or bool(r.get("a_records")))
    return state


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-domains", type=int, default=150, help="cap per run (cron tick)")
    ap.add_argument("--max-attempts", type=int, default=3,
                    help="re-attempts for domains that never showed an A record")
    ap.add_argument("--max-age-days", type=float, default=7,
                    help="stop retrying once the detection is older than this")
    ap.add_argument("--delay", type=float, default=0.8, help="pause between domains (be polite)")
    args = ap.parse_args()

    socket.setdefaulttimeout(10)  # python-whois opens raw sockets with no timeout of its own
    os.makedirs(OUTDIR, exist_ok=True)
    state = load_state()
    now = datetime.now()

    todo = []
    for d, src, label, first in load_candidates():
        att, had_a = state.get(d, (0, False))
        if att == 0:
            todo.append((d, src, label, first, 1))
        elif not had_a and att < args.max_attempts:
            try:
                age = (now - datetime.fromisoformat(first)).total_seconds() / 86400
            except ValueError:
                age = args.max_age_days + 1
            if age <= args.max_age_days:
                todo.append((d, src, label, first, att + 1))
    todo = todo[:args.max_domains]
    if not todo:
        print(f"[{now.isoformat(timespec='seconds')}] nothing new")
        return

    new = os.path.getsize(OUT) == 0 if os.path.exists(OUT) else True
    with open(OUT, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        for i, (d, src, label, first, attempt) in enumerate(todo, 1):
            reg = registered_domain(d)
            row = {"domain": d, "registered_domain": reg, "source": src, "label": label,
                   "first_detected": first, "attempt": attempt,
                   "captured_at": datetime.now().isoformat(timespec="seconds")}
            row.update(dns_host(d))
            row.update(dns_reg(reg))
            row.update(whois_reg(reg))
            row.update(tls_host(d))
            w.writerow(row)
            f.flush()
            print(f"[{i}/{len(todo)}] {d} a={row['a_records'] or '-'} "
                  f"age={row['whois_age_days'] or '-'} tls={row['tls_present']}")
            time.sleep(args.delay)
    print(f"[+] {len(todo)} observations -> {OUT}")


if __name__ == "__main__":
    main()
