#!/usr/bin/env python3
"""
compphish_features.py — Extract the CompPhish (Goenka 2026, Mendeley 10.17632/fmbs4kp9wz.2)
26-column lexical URL feature schema, so our VN data is cross-dataset compatible with CompPhish.

Schema (exact order):
  url,url_len,dom,dom_len,is_ip,tld,tld_len,subdom_cnt,letter_cnt,digit_cnt,special_cnt,
  eq_cnt,qm_cnt,amp_cnt,dot_cnt,dash_cnt,under_cnt,letter_ratio,digit_ratio,spec_ratio,
  is_https,slash_cnt,entropy,path_len,query_len,label

Requires: tldextract (for correct multi-part TLDs like edu.au, com.vn). pip install tldextract
Use via align_compphish.py, or import extract().
"""
from __future__ import annotations
import re
from collections import Counter
from math import log2
from urllib.parse import urlparse

try:
    import tldextract
    _EXT = tldextract.TLDExtract(suffix_list_urls=())  # offline snapshot
except Exception:  # pragma: no cover
    _EXT = None

COLUMNS = ["url", "url_len", "dom", "dom_len", "is_ip", "tld", "tld_len", "subdom_cnt",
           "letter_cnt", "digit_cnt", "special_cnt", "eq_cnt", "qm_cnt", "amp_cnt",
           "dot_cnt", "dash_cnt", "under_cnt", "letter_ratio", "digit_ratio", "spec_ratio",
           "is_https", "slash_cnt", "entropy", "path_len", "query_len"]

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in Counter(s).values())


def extract(url: str) -> dict:
    """Return the 25 feature columns (label added by caller).

    NOTE: all length/count/ratio/entropy features are computed on the *scheme-stripped*
    URL (``core``) so the stored http:// vs https:// prefix cannot leak into them. In our
    collection benign URLs were stored with https and phishing with http, which made the
    scheme a perfect (spurious) label predictor; ``is_https`` is kept for CompPhish schema
    compatibility but is a known collection artifact — exclude it from modelling.
    """
    url = str(url).strip()
    p = urlparse(url if re.match(r"^[a-z]+://", url, re.I) else "http://" + url)
    host = (p.hostname or "").lower()
    # scheme-stripped URL used for ALL lexical features (scheme-independent)
    core = re.sub(r"^[a-z]+://", "", url, flags=re.I)

    if _EXT is not None:
        ext = _EXT(url if re.match(r"^[a-z]+://", url, re.I) else "http://" + url)
        suffix = ext.suffix
        dom = ext.registered_domain or host
        subdom = ext.subdomain
    else:  # fallback (less accurate for multi-part TLDs)
        parts = host.split(".")
        suffix = parts[-1] if parts else ""
        dom = ".".join(parts[-2:]) if len(parts) >= 2 else host
        subdom = ".".join(parts[:-2]) if len(parts) > 2 else ""

    url_len = len(core)
    letter_cnt = sum(c.isalpha() for c in core)
    digit_cnt = sum(c.isdigit() for c in core)
    special_cnt = url_len - letter_cnt - digit_cnt
    is_ip = 1 if _IP_RE.match(host) else 0
    path_len = len(p.path.strip("/"))
    return {
        "url": url,
        "url_len": url_len,
        "dom": dom,
        "dom_len": len(dom),
        "is_ip": is_ip,
        "tld": suffix,
        "tld_len": len(suffix),
        "subdom_cnt": len([s for s in subdom.split(".") if s]) if subdom else 0,
        "letter_cnt": letter_cnt,
        "digit_cnt": digit_cnt,
        "special_cnt": special_cnt,
        "eq_cnt": core.count("="),
        "qm_cnt": core.count("?"),
        "amp_cnt": core.count("&"),
        "dot_cnt": core.count("."),
        "dash_cnt": core.count("-"),
        "under_cnt": core.count("_"),
        "letter_ratio": letter_cnt / url_len if url_len else 0.0,
        "digit_ratio": digit_cnt / url_len if url_len else 0.0,
        "spec_ratio": special_cnt / url_len if url_len else 0.0,
        "is_https": 1 if url.lower().startswith("https") else 0,
        "slash_cnt": core.count("/"),
        "entropy": _entropy(core),
        "path_len": path_len,
        "query_len": len(p.query),
    }


if __name__ == "__main__":
    import sys
    for u in sys.argv[1:]:
        print(extract(u))
