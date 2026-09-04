#!/usr/bin/env python3
"""
audit_p4_labels.py — is P4's phishing arm actually phishing?

urlscan's free tier cannot filter `verdicts.overall.malicious` (watch_urlscan_brands.py:23), so
`label=phish` really means "hostname with a Vietnamese brand token that urlscan happened to scan".
The feed's `is_official()` correction is exact-domain only: it holds `bidv.com.vn` but not
`bidv.vn`, and knows nothing of `sepay.vn`, `teko.vn`, `vbsp.vn`. P4 reads the label as ground
truth, so this measures the damage before the registered n>=500 trigger locks it in — using only
evidence INDEPENDENT of infrastructure (Tranco, the project's allowlists, the three blocklists on
disk), since DNS/TLS/hosting are P4's dependent variables and a label derived from them would be
circular.

Two questions, kept separate: EXCLUSION (positive evidence of a legitimate operator) vs
CORROBORATION (an independent blocklist named it). Neither -> UNCORROBORATED, the honest state for
most of this feed: reporting it as phishing is the audited error, but silently dropping it would
make the arm look clean rather than small, so it prints as its own row.

ONE DELIBERATE EXCEPTION to the no-DNS rule: the registry-wildcard guard. dotPH resolves any
unregistered `.ph`/`.com.ph` name to its ParkLogic parking IP (45.79.222.138, observed 2026-08-16
when 797 brand-token ".ph phishing domains" turned out to be this: one shared IP, zero NS/MX,
unverifiable cert, capture = dotPH's "Redirecting..." ad page). Probe a name that cannot have been
registered; if it resolves, the suffix wildcards, and a candidate inside the wildcard's addresses
has NO REGISTRATION AT ALL. Not the forbidden circularity: the address is the registry's, fixed by
TLD policy (the same artefact family as the `.vn` WHOIS gap) — no phisher, no choice. Like
`hosted_subdomain`, the verdict marks a unit whose registration-level features are undefined.

RUN:  python scripts/audit_p4_labels.py            # audit the conditioned P4 phishing arm
      python scripts/audit_p4_labels.py --all      # audit every live urlscan_brands detection
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import re
import socket
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

# BELOW the bootstrap, not above it: psl.py lives in scripts/, which is only on sys.path once
# add_script_dirs() has run. Imported above, this module could still be IMPORTED (watch_ct_benign,
# make_p4_assets and four others bootstrap before importing it, so their path is already set) but
# could not be RUN -- and running it is how the gate is audited and how p4_content_map.csv is
# exported on the collector. It was that way from 2026-08-28 (435e6f9) to 2026-08-31, three days
# in which every importer worked and `python3 scripts/audit_p4_labels.py` raised
# ModuleNotFoundError on both machines.
from psl import apex  # noqa: E402

P4_DATASET = os.path.join("data", "processed", "p4", "p4_infra_dataset.csv")
DETECTIONS = os.path.join("data", "raw", "urlscan_brands", "detections.csv")
TOKENS_JSON = os.path.join("data", "processed", "brand_tokens.json")
OUT = os.path.join("data", "interim", "p4_label_audit.csv")
# Every suffix the wildcard guard probed during a run, with what the resolver answered, so the
# data article can publish the probe instead of asking readers to trust the verdicts.
WILDCARD_PROBE_OUT = os.path.join("data", "processed", "p4", "p4_wildcard_probe.csv")
WATCHER_START = "2026-07-30"   # same boundary make_p4_assets.py uses for the live stratum

# include_psl_private_domains=True -- without it every site on a free subdomain host collapses to
# the HOST's registration (`login-bidv.pages.dev` -> `pages.dev`): distinct phishing sites merge
# into one unit carrying Cloudflare's DNS/TLS, which then ranks in Tranco and is excluded as
# "legitimate". watch_host_infra.py used the default until 2026-08-03, so split host_infra.csv
# rows on `captured_at` before trusting `registered_domain`.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

# No registration of its own: NS/TTL/WHOIS belong to the host, so registration-level features are
# undefined -- counted as their own stratum, not mixed into either arm. `translate.goog` added
# 2026-08-24 (PREREG amendment): it is a rewriting PROXY, so the capture carries Google's
# address, Google's certificate and ns_count 0 whatever the proxied site is, and the language
# evidence is the PROXIED page's -- which may be a legitimate one. Both admitted rows were that.
HOSTED_SUFFIXES = ("pages.dev", "netlify.app", "vercel.app", "web.app", "firebaseapp.com",
                   "webflow.io", "weebly.com", "wixsite.com", "blogspot.com", "github.io",
                   "duckdns.org", "ddns.net", "r2.dev", "workers.dev", "glitch.me", "repl.co",
                   "translate.goog")


# LEXICAL subset of vn_filter.VN_TOKENS: Vietnamese common nouns/verbs only, every brand name
# removed -- brand tokens produced this audit's false positives (`bidv` sits innocently in
# Bidvest, bidvine.de). `dichvucong`, `baohiemxahoi`, `kekhai` are Vietnamese WORDS: spelling
# one out addresses Vietnamese speakers, a fact about LANGUAGE independent of P4's dependent
# variables. Not proof of malice, so the exclusion filters still run first.
VN_LEXICAL = re.compile(
    r"(nganhang|taikhoan|thanhtoan|chuyentien|nhantien|naptien|ruttien|vaytien|tietkiem|tindung|"
    r"chinhphu|congan|thuedientu|baohiem|bhxh|bhyt|dichvucong|kekhai|khaibao|vneid|cccd|canhcuoc|"
    r"muahang|khuyenmai|trungthuong|nhanqua|tichdiem|giaohang|vanchuyen|buukien|donhang|napthe|"
    r"muathe|thecao|khachhang|dangnhap|dangky|xacminh|xacnhan|capnhat|kichhoat|baomat|luadao|"
    r"quocgia|tuvan|vieclam|hosokhaithue)", re.I)


def registrable(host: str) -> str:
    return apex(_EXTRACT(str(host))).lower()


# FIXED probe label, not random: a random one would make two runs disagree about which suffixes
# wildcard whenever resolution is flaky. stdlib resolution on purpose -- dnspython is not on the
# analysis Mac and must not be quietly imported (b15ed86 turned DNS failures into observations).
_WILDCARD_PROBE_LABEL = "phishvn-wildcard-probe-x7q9z3"


def _resolve(name: str) -> frozenset[str]:
    try:
        return frozenset(socket.gethostbyname_ex(name)[2])
    except OSError:
        return frozenset()


_WILDCARD_CACHE: dict[str, frozenset[str]] = {}
_WILDCARD_PROBED_ON: dict[str, str] = {}
# Names the screen had to resolve live because their capture carried no address. Persisted for
# the same reason as the probe answers: two builds minutes apart must see the same registry.
LIVE_RESOLVE_OUT = os.path.join("data", "processed", "p4", "p4_live_resolve_cache.csv")
_LIVE_RESOLVE_CACHE: dict[str, frozenset[str]] = {}
_LIVE_RESOLVE_ON: dict[str, str] = {}
_CACHES_LOADED = False
# PHISHVN_REPROBE=1 (or audit --reprobe) discards both stored caches and asks the network again.
REPROBE = os.environ.get("PHISHVN_REPROBE", "") not in ("", "0")


def _today() -> str:
    return _dt.datetime.now(_dt.timezone.utc).date().isoformat()


def _load_caches() -> None:
    """Read the persisted probe answers so the funnel is a function of the data on disk.

    DETERMINISM (2026-08-21). The registry probe and the no-address fallback both ask live DNS, and
    two builds minutes apart disagreed (wildcard 1,471 vs 1,472) because one suffix answered
    differently. A time-stamped pre-specified design cannot have a population that depends on the minute it was
    built. So the answers are records: read from disk, probed only for names the file has never
    seen, refreshed as a whole only on --reprobe. The file IS the probe; the network is its source."""
    global _CACHES_LOADED
    if _CACHES_LOADED:
        return
    _CACHES_LOADED = True
    if REPROBE:
        return
    for path, cache, when, key in ((WILDCARD_PROBE_OUT, _WILDCARD_CACHE, _WILDCARD_PROBED_ON,
                                    "suffix"),
                                   (LIVE_RESOLVE_OUT, _LIVE_RESOLVE_CACHE, _LIVE_RESOLVE_ON,
                                    "domain")):
        try:
            df = pd.read_csv(path, keep_default_na=False, dtype=str)
        except OSError:
            continue
        for r in df.itertuples(index=False):
            k = getattr(r, key)
            cache[k] = frozenset(a for a in str(r.answers).split(";") if a)
            when[k] = getattr(r, "probed_on", "") or getattr(r, "resolved_on", "")


def wildcard_ips(suffix: str) -> frozenset[str]:
    """The addresses the registry hands out for names that do not exist, one probe per public
    suffix, read from the persisted probe file and asked of the network only for a suffix the
    file has never seen (see _load_caches). Empty set = the suffix does not wildcard."""
    _load_caches()
    if suffix not in _WILDCARD_CACHE:
        _WILDCARD_CACHE[suffix] = (_resolve(f"{_WILDCARD_PROBE_LABEL}.{suffix}")
                                   if suffix else frozenset())
        _WILDCARD_PROBED_ON[suffix] = _today()
    return _WILDCARD_CACHE[suffix]


def _resolve_cached(domain: str) -> frozenset[str]:
    _load_caches()
    if domain not in _LIVE_RESOLVE_CACHE:
        _LIVE_RESOLVE_CACHE[domain] = _resolve(domain)
        _LIVE_RESOLVE_ON[domain] = _today()
    return _LIVE_RESOLVE_CACHE[domain]


def is_registry_wildcard(domain: str, recorded_ips: frozenset[str] | None = None) -> bool:
    """Does this name exist only as its registry's wildcard answer?

    Prefers capture-time recorded addresses, resolving live only when no recording exists. A
    registered domain parked on the registry's IP is excluded too -- its infrastructure is still the
    registry's. Known miss: a parking address rotated since capture falls through to the lexical
    verdicts, so this under-excludes, never over-excludes."""
    wc = wildcard_ips(_EXTRACT(str(domain)).suffix)
    if not wc:
        return False
    ips = recorded_ips if recorded_ips else _resolve_cached(domain)
    return bool(ips) and ips <= wc


# Cong An followed by H must be a province starting with H (Hanoi, Haiphong, Hatinh, Haiduong, Hanam, Haugiang, Hoabinh, Hungyen).
# Otherwise "conganh" / "boconganh" is "Bồ Công Anh" (dandelion) or personal name "Công Anh".
NON_POLICE_CONGANH = re.compile(
    r"conganh(?!(?:anoi|aiphong|atinh|aiduong|anam|augiang|oabinh|ungyen))", re.I)

# Dich vu cong followed by nghiep (industrial), nghe (tech), chung (notary), ty (company).
NON_PUBLIC_SERVICE_DVC = re.compile(
    r"dichvucong(?:nghiep|nghe|chung|ty)", re.I)


def is_vn_lexical(domain: str) -> bool:
    d = domain.lower()
    if NON_POLICE_CONGANH.search(d):
        d = NON_POLICE_CONGANH.sub("", d)
    if NON_PUBLIC_SERVICE_DVC.search(d):
        d = NON_PUBLIC_SERVICE_DVC.sub("", d)
    return bool(VN_LEXICAL.search(d))


def is_hosted_subdomain(domain: str) -> bool:
    return any(domain.endswith("." + s) for s in HOSTED_SUFFIXES)


def load_tranco() -> set[str]:
    """Global top-100k plus the Vietnamese slice. A registrable domain that ranks is an
    established site with real traffic; phishing domains are days old and unranked."""
    out: set[str] = set()
    for path in (os.path.join("data", "external", "tranco_top100k.csv"),
                 os.path.join("data", "raw", "tranco_vn", "benign.csv")):
        try:
            df = pd.read_csv(path, header=None, low_memory=False, on_bad_lines="skip")
        except OSError:
            continue
        for col in df.columns:
            s = df[col].astype(str).str.lower().str.removeprefix("www.")
            if s.str.contains(".", regex=False, na=False).mean() > 0.5:
                out |= set(s)
    return {d for d in out if d and d != "nan"}


def load_allowlists() -> set[str]:
    """The feed's own official-domain set, the brand-token registry's domains, and the
    trusted-org registry. Absence proves nothing (these are certification lists, not censuses),
    so this is used only to exclude, never to confirm."""
    from watch_urlscan_brands import load_official

    out = {d.lower() for d in load_official()}
    try:
        with open(TOKENS_JSON, encoding="utf-8") as f:
            for tok in json.load(f).get("tokens", []):
                for d in tok.get("domains", []):
                    out.add(d.lower().removeprefix("www."))
    except (OSError, ValueError):
        pass
    for path in glob.glob(os.path.join("data", "raw", "tinnhiem_org", "*.csv")):
        try:
            df = pd.read_csv(path, on_bad_lines="skip", low_memory=False)
        except OSError:
            continue
        for col in df.columns:
            if col.lower() in ("domain", "host", "website", "url"):
                s = (df[col].astype(str).str.lower()
                     .str.replace(r"^https?://", "", regex=True)
                     .str.split("/").str[0].str.removeprefix("www."))
                out |= set(s)
    LEGIT_VN_ENTITIES = {
        "duhocalpha.vn", "giaiphapduhoc.com", "kienthucduhocmy.com",
        "eduwork.vn", "ecinvest.vn", "ntcs.com.vn", "vemaybay2424.com",
        "mobiedu.vn", "edu4life.com.vn", "phatnguoi.com.vn", "checkphatnguoi.com.vn",
        "damsenwaterpark.com.vn", "evnspc.vn", "coopbank.co.tz", "byltbasics.com",
        "booking.com", "safekidsfoundation.org", "nutri-ana.online",
        # partner, fintech integration & legitimate educational/career platforms
        "sobanhang.com", "truedoc.vn", "siten.vn", "bluestar.com.vn", "nghebanker.com",
        "hairbank.net", "honguyenvietnam.org", "isb.vn",
        # notary, technology & industrial compound entities
        "dichvucongchung.com.vn", "dichvucongchung.org", "dichvucongnghe.io.vn",
        "dichvucongnghiephc.vn", "xaydungvadichvucongnghiepvanan.com", "dichvucongtybacninh.vn",
        # verified official e-commerce & shipping platforms
        "shopee.vn", "lazada.vn", "tiki.vn", "sendo.vn", "aeon.com.vn", "aeon.vn",
        "giaohangnhanh.vn", "ghn.vn"
    }
    out |= LEGIT_VN_ENTITIES
    return {d for d in out if d and d != "nan"}


def load_blocklists() -> dict[str, set[str]]:
    """The three independent phishing sources already on disk. Matching is at registrable-domain
    granularity so a blocklisted hostname corroborates its parent registration."""
    lists: dict[str, set[str]] = {}
    cld = os.path.join("data", "raw", "chongluadao_live", "seen_domains.txt")
    try:
        with open(cld, encoding="utf-8") as f:
            lists["chongluadao"] = {registrable(x.strip()) for x in f if x.strip()}
    except OSError:
        pass
    for name, path, col in (
            ("openphish", os.path.join("data", "raw", "openphish", "feed.csv"), None),
            ("tinnhiemmang", os.path.join("data", "raw", "tinnhiemmang", "blacklist_hist.csv"), None)):
        try:
            df = pd.read_csv(path, on_bad_lines="skip", low_memory=False)
        except OSError:
            continue
        hosts: set[str] = set()
        for c in df.columns:
            if col and c != col:
                continue
            s = df[c].astype(str)
            if s.str.contains(".", regex=False, na=False).mean() > 0.5:
                hosts |= {registrable(x.replace("https://", "").replace("http://", "").split("/")[0])
                          for x in s}
        lists[name] = {h for h in hosts if h}
    return lists


# A rendered password input -- the strongest content evidence here: a page ASKING for a credential
# is doing the thing the study is about, whatever its language. Matched on the stored DOM, so a
# form assembled by JavaScript after capture is missed: under-admits, never over-admits.
CRED_INPUT = re.compile(r"type\s*=\s*[\"']?password", re.I)


def content_evidence() -> dict[str, dict[str, bool]]:
    """registrable domain -> {renders_vietnamese, credential_form}, from the stored captures.

    Blocklist corroboration is structurally unavailable for the live stratum (all three lists
    stopped publishing before the watcher started), so content is the only positive evidence that
    keeps working. The language test is `vn_filter.is_vietnamese_text`, the same gate as P1b's
    content manifest, so the two papers cannot disagree about what "Vietnamese" means. A brand-token
    hit rendering no Vietnamese is substring collision or an out-of-scope global site. NEITHER test
    separates a brand's own portal from an impersonation, so exclusions run first and both are
    evidence, not proof."""
    from vn_filter import is_vietnamese_text, visible_text

    try:
        det = pd.read_csv(DETECTIONS, low_memory=False)
    except OSError:
        return {}
    out: dict[str, dict[str, bool]] = {}
    for _, r in det.iterrows():
        path = r.get("dom_file")
        if not isinstance(path, str) or not os.path.exists(path):
            continue
        reg = registrable(r["domain"])
        cur = out.get(reg)
        if cur and cur["renders_vietnamese"] and cur["credential_form"]:
            continue
        with open(path, encoding="utf-8", errors="ignore") as f:
            html = f.read()
        # visible text, not the raw file: the density threshold cannot survive markup dilution, and scoring
        # html here is what made this gate disagree with P1b's on 73 domains.
        ev = {"renders_vietnamese": is_vietnamese_text(visible_text(html)),
              "credential_form": bool(CRED_INPUT.search(html))}
        # a domain may have several captures; any capture carrying the evidence carries it
        out[reg] = ({k: cur[k] or ev[k] for k in ev} if cur else ev)
    return out


def load_content_map(path: str) -> dict[str, dict[str, bool]]:
    """Content evidence computed elsewhere: captures live on the Jetson, exclusion lists (Tranco
    especially) on the Mac -- running the whole audit on the Jetson disables every exclusion and
    promotes `sepay.vn`/`vnptpay.vn` to "content_confirmed", the exact error this script exists to
    catch. Hence `--export-content` on the collector, `--content-map` here. Maps exported before
    2026-08-16 lack credential_form; that evidence loads as absent, never guessed."""
    df = pd.read_csv(path)
    has_cred = "credential_form" in df.columns
    return {r["registered_domain"]: {"renders_vietnamese": bool(r["renders_vietnamese"]),
                                     "credential_form": bool(r["credential_form"]) if has_cred
                                     else False}
            for _, r in df.iterrows()}


def audit(domains: list[str], use_content: bool = False,
          content_map: dict[str, bool] | None = None,
          ipmap: dict[str, frozenset[str]] | None = None) -> pd.DataFrame:
    tranco, allow, blocks = load_tranco(), load_allowlists(), load_blocklists()
    if not tranco:
        print("[!] Tranco lists absent — every exclusion is disabled. Results are NOT valid; "
              "run on the analysis host, or pass --content-map from the collector.",
              file=sys.stderr)
    content = content_map if content_map is not None else (content_evidence() if use_content else {})
    ipmap = ipmap or {}
    rows = []
    for d in sorted(set(domains)):
        hits = [name for name, s in blocks.items() if d in s]
        in_tranco, in_allow = d in tranco, d in allow
        ev = content.get(d)
        vi = None if ev is None else ev["renders_vietnamese"]
        pw = None if ev is None else ev["credential_form"]
        lex = is_vn_lexical(d)
        # The wildcard guard outranks the positive-evidence verdicts: `vn_lexical` reads only the NAME,
        # and a Vietnamese-rendering capture of a wildcard name predates what the row's infra fields
        # describe. `renders_vietnamese` still lands in the CSV, so past content evidence stays visible.
        if is_hosted_subdomain(d):
            verdict = "hosted_subdomain"
        elif in_tranco or in_allow:
            verdict = "excluded_legitimate"
        elif is_registry_wildcard(d, ipmap.get(d)):
            verdict = "registry_wildcard"
        elif hits:
            verdict = "corroborated"
        elif pw:
            verdict = "credential_form"
        elif vi:
            verdict = "content_confirmed"
        elif lex:
            verdict = "vn_lexical"
        elif vi is None and (use_content or content):
            verdict = "no_capture"
        else:
            verdict = "uncorroborated"
        rows.append({"registered_domain": d, "verdict": verdict, "in_tranco": int(in_tranco),
                     "in_allowlist": int(in_allow), "blocklists": ",".join(hits),
                     "renders_vietnamese": "" if vi is None else int(vi),
                     "credential_form": "" if pw is None else int(pw),
                     "vn_lexical": int(lex)})
    write_wildcard_probe()
    return pd.DataFrame(rows)


def write_wildcard_probe(path: str = WILDCARD_PROBE_OUT) -> int:
    """Persist the probe cache (one row per suffix probed this run). Records only: the verdicts
    never read this file. Returns the number of rows written (0 = nothing probed, no file)."""
    if not _WILDCARD_CACHE:
        return 0
    host = socket.gethostname()
    rows = [{"suffix": s, "probe_name": f"{_WILDCARD_PROBE_LABEL}.{s}",
             "probed_on": _WILDCARD_PROBED_ON.get(s) or _today(),
             "resolver_host": host, "answers": ";".join(sorted(ips)), "wildcards": bool(ips)}
            for s, ips in sorted(_WILDCARD_CACHE.items()) if s]
    if _LIVE_RESOLVE_CACHE:
        lrows = [{"domain": d, "resolved_on": _LIVE_RESOLVE_ON.get(d) or _today(),
                  "resolver_host": host, "answers": ";".join(sorted(ips))}
                 for d, ips in sorted(_LIVE_RESOLVE_CACHE.items())]
        ltmp = f"{LIVE_RESOLVE_OUT}.{os.getpid()}.tmp"
        pd.DataFrame(lrows, columns=["domain", "resolved_on", "resolver_host", "answers"]
                     ).to_csv(ltmp, index=False)
        os.replace(ltmp, LIVE_RESOLVE_OUT)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # Atomic replace: asset builds import this module and can run concurrently with a manual
    # audit; two writers sharing one open file interleave rows.
    tmp = f"{path}.{os.getpid()}.tmp"
    pd.DataFrame(rows, columns=["suffix", "probe_name", "probed_on", "resolver_host",
                                "answers", "wildcards"]).to_csv(tmp, index=False)
    os.replace(tmp, path)
    return len(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true",
                    help="audit every urlscan_brands detection, not just P4's conditioned arm")
    ap.add_argument("--live", action="store_true",
                    help="audit the live-stratum conditioned phishing arm with NO TLD restriction, "
                         "recomputed from host_infra.csv (the direction-1 population)")
    ap.add_argument("--content", action="store_true",
                    help="add the Vietnamese-rendering content gate (needs the captures on disk; "
                         "they live on the Jetson, so run this there)")
    ap.add_argument("--export-content", metavar="PATH",
                    help="collector host: write the content map (domain,renders_vietnamese) and "
                         "exit, for --content-map on the analysis host")
    ap.add_argument("--reprobe", action="store_true",
                    help="discard the stored probe/resolve caches and ask the network afresh "
                         "(same as PHISHVN_REPROBE=1); the new answers are written back")
    ap.add_argument("--content-map", metavar="PATH",
                    help="analysis host: read content evidence exported by --export-content")
    args = ap.parse_args()
    if args.reprobe:
        global REPROBE
        REPROBE = True

    if args.export_content:
        ev = content_evidence()
        pd.DataFrame([{"registered_domain": k,
                       "renders_vietnamese": int(v["renders_vietnamese"]),
                       "credential_form": int(v["credential_form"])}
                      for k, v in sorted(ev.items())]).to_csv(args.export_content, index=False)
        print(f"[+] {args.export_content} ({len(ev)} domains with a readable capture)")
        return 0

    ipmap: dict[str, frozenset[str]] = {}
    if args.live:
        df = pd.read_csv(os.path.join("data", "raw", "host_infra", "host_infra.csv"),
                         low_memory=False)
        df["fd"] = pd.to_datetime(df["first_detected"], errors="coerce")
        ph = df[(df["label"] == "phish") & (df["fd"] >= WATCHER_START)]
        cond = (ph["a_records"].fillna("").astype(str).str.strip().astype(bool)
                & (pd.to_numeric(ph["tls_present"], errors="coerce") == 1))
        domains = [registrable(h) for h in ph[cond]["domain"].dropna()]
        # Capture-time addresses for the wildcard guard, unioned across attempts so a domain that
        # ever resolved beyond the registry's answer is never mistaken for the wildcard.
        for _, r in ph[cond].iterrows():
            reg = registrable(r["domain"])
            ips = frozenset(x.strip() for x in str(r["a_records"]).split(";") if x.strip())
            ipmap[reg] = ipmap.get(reg, frozenset()) | ips
        scope = "live-stratum conditioned phishing arm, no TLD restriction"
    elif args.all:
        df = pd.read_csv(DETECTIONS, low_memory=False)
        domains = [registrable(h) for h in df["domain"].dropna()]
        scope = f"all urlscan_brands detections ({df['domain'].nunique()} hostnames)"
    else:
        df = pd.read_csv(P4_DATASET)
        domains = list(df[df["arm"] == "phish"]["registered_domain"])
        scope = "P4 conditioned phishing arm"

    cmap = load_content_map(args.content_map) if args.content_map else None
    # BEFORE audit(), not after: write_wildcard_probe() runs inside audit() and writes into this same
    # directory. On a host carrying only data/raw -- the collector, where `--all` is natural -- the
    # directory does not exist and the run dies after every DNS probe it just spent.
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    res = audit([d for d in domains if d], use_content=args.content, content_map=cmap,
                ipmap=ipmap)
    res.to_csv(OUT, index=False)

    order = ("corroborated", "credential_form", "content_confirmed", "vn_lexical",
             "uncorroborated", "no_capture",
             "excluded_legitimate", "hosted_subdomain", "registry_wildcard")
    n = len(res)
    print(f"[i] scope: {scope} -> {n} registrable domains\n")
    for verdict in order:
        sub = res[res["verdict"] == verdict]
        if len(sub):
            print(f"  {verdict:<22} {len(sub):>4}  ({100 * len(sub) / n:.0f}%)")
    print()
    for verdict in order:
        sub = res[res["verdict"] == verdict]
        if len(sub):
            print(f"[{verdict}] {', '.join(sub['registered_domain'].head(40))}")
    wild = {s: sorted(ips) for s, ips in _WILDCARD_CACHE.items() if ips}
    if wild:
        print("[i] wildcarding suffixes (probe resolved): "
              + "; ".join(f".{s} -> {','.join(ips)}" for s, ips in sorted(wild.items())))
    print(f"\n[+] {OUT}")
    print("[!] 'uncorroborated' is not a phishing label. Any P4 fit that treats it as one is "
          "measuring brand-token co-occurrence, not phishing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
