#!/usr/bin/env python3
"""psl.py — Public-Suffix-List domain folding for collectors and evaluation.

Extracts the registrable domain (including private suffixes like pages.dev) to ensure
consistent units of observation across collection, deduplication, and testing.
"""
from __future__ import annotations

try:
    import tldextract
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
except Exception:
    _EXTRACT = None

# Fallback multi-part suffixes (ICANN + popular platform domains)
_TWO_LEVEL = {"com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "ac.vn", "info.vn", "pro.vn",
              "health.vn", "int.vn", "name.vn", "biz.vn", "co.uk", "com.br", "com.au", "co.jp",
              "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app", "web.app",
              "firebaseapp.com", "amplifyapp.com", "webflow.io", "weebly.com", "wixsite.com",
              "blogspot.com", "github.io", "duckdns.org", "ddns.net", "glitch.me", "repl.co"}


def apex(result) -> str:
    """Return the registrable domain under the public suffix, compatible across tldextract versions."""
    new = getattr(result, "top_domain_under_public_suffix", None)
    return result.registered_domain if new is None else new



def registered_domain(host: str) -> str:
    if _EXTRACT is not None:
        try:
            return apex(_EXTRACT(host)).lower() or host
        except Exception:
            pass
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host
