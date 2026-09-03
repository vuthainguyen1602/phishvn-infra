#!/usr/bin/env python3
"""
psl.py — Public-Suffix-List domain folding, shared by the collectors and the evaluation code.

registered_domain(host) folds a full hostname to the unit somebody actually registered. It lives
here rather than inside a collector because two very different callers must agree on that unit:
the infrastructure collector groups its observations by it, and the phishing-temporal evaluation
drops same-registrable-domain re-detections from the test side. If the two ever disagreed, the
evaluation would leak re-detections the collector had already counted as one site.

include_psl_private_domains=True is what makes the unit right: under the default, free-subdomain
names collapse to the PROVIDER's registration (login-bidv.pages.dev, mbbank.pages.dev, +20 more
all became one pages.dev row carrying Cloudflare's DNS/TLS, which then ranked in Tranco and was
excluded as legitimate — the origin of the excluded-host list pages.dev/blogspot.com/duckdns.org/
netlify.app/vercel.app/webflow.io/weebly.com). ICANN suffixes are unaffected. The extractor is
built once at import (per-call construction reloads the suffix snapshot); suffix_list_urls=()
keeps it offline.

CHANGED 2026-08-03; the infrastructure log is append-only and spans both conventions, so the
~7,900 rows written before that date keep collapsed values: split on captured_at when reading a
registered domain back out of it. The `domain` column was always the full host, so older rows can
be re-derived.
"""
from __future__ import annotations

try:
    import tldextract
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
except Exception:
    _EXTRACT = None

# Fallback if tldextract is absent: multi-part suffixes met in this corpus, from BOTH PSL sections
# so the fallback reaches the same unit (ICANN delegations + free-subdomain hosts).
_TWO_LEVEL = {"com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "ac.vn", "info.vn", "pro.vn",
              "health.vn", "int.vn", "name.vn", "biz.vn", "co.uk", "com.br", "com.au", "co.jp",
              "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app", "web.app",
              "firebaseapp.com", "amplifyapp.com", "webflow.io", "weebly.com", "wixsite.com",
              "blogspot.com", "github.io", "duckdns.org", "ddns.net", "glitch.me", "repl.co"}


def apex(result) -> str:
    """The registration under the public suffix, whichever tldextract is installed.

    5.3 renamed `registered_domain` to `top_domain_under_public_suffix` and deprecated the old
    name; both return the same string. Worth an accessor rather than a rename at each call site
    because this library decides the UNIT OF OBSERVATION and its version is pinned in the
    environment record for exactly that reason (the 3.2.0-vs-5.3.1 split that folded io.vn and
    id.vn differently on two hosts, 2026-08-24). Every caller must fold identically on both.
    """
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
