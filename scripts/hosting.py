"""Did the operator of this name register a domain, or take a subdomain on someone's platform?

WHY IT CHANGES WHAT A FIELD MEANS. `agribank-gdv-rating.pages.dev` and `agribank-verify.com` are
the same kind of lure and completely different registrations. Nobody registered the first: they
signed up on a platform that owns the apex, so its A record is Cloudflare's, its WHOIS age is
Cloudflare's, its registrar is Cloudflare's and its certificate is Cloudflare's. A table that reads
registration- and transport-level fields across both rows is reading a property of the provider on
one and a property of the actor on the next, and a model trained on it learns "is this on Cloudflare
Pages", which separates the classes here for reasons that have nothing to do with deception.

THE FIX IS SCOPE, NOT DELETION. Nothing is blanked. Each row gets the stratum it belongs to and a
flag saying whether its infrastructure fields describe the operator or the platform, so an analysis
can compare within a stratum instead of across one. Page-level evidence (HTML, screenshot, URL
string, redirects, security headers) belongs to the tenant either way and is never scoped out.

THE RULE IS A UNION, because each source catches what the other misses:
  psl      the Public Suffix List's PRIVATE section, contributed by the platforms themselves. A
           name is platform-hosted when its registrable domain computed WITH private suffixes
           differs from the one computed under ICANN rules alone.
  curated  the list below, for platforms that have never submitted themselves to that section.

`rule` records which source fired, so a disagreement between them stays auditable.

THREE CLASSES, AND THE THIRD IS NOT A HEDGE. `uncertain` is a subdomain of an ordinary registrable
domain: an unlisted platform, a compromised legitimate site, or an internal subdomain of a large
organisation. Those are not separable from DNS and TLS alone, and pretending otherwise would put a
guess in a data paper.
"""
import tldextract

# Kept identical to audit_capture_labels.HOSTED_SUFFIXES; tests/test_hosting_scope.py fails if the
# two drift, because two copies of a judgement call silently disagreeing is worse than one copy in
# the wrong module.
HOSTED_SUFFIXES = ("pages.dev", "netlify.app", "vercel.app", "web.app", "firebaseapp.com",
                   "webflow.io", "weebly.com", "wixsite.com", "blogspot.com", "github.io",
                   "duckdns.org", "ddns.net", "r2.dev", "workers.dev", "glitch.me", "repl.co",
                   "translate.goog")

# The fields that describe whoever owns the apex rather than whoever put the page there. Page-level
# evidence is deliberately absent from this list.
PROVIDER_OWNED = ('a_records', 'a_ttl', 'cname', 'ns_count', 'ns_hosts', 'mx_count',
                  'whois_created', 'whois_expires', 'whois_updated', 'registrar', 'whois_age_days',
                  'tls_issuer', 'tls_subject_cn', 'tls_not_before', 'tls_not_after', 'tls_san_count')

# suffix_list_urls=() pins both extractors to the bundled snapshot, so a classification does not
# change under us when the live list does.
_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_ICANN = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)


def curated_apex(host):
    for suffix in HOSTED_SUFFIXES:
        if host.endswith("." + suffix):
            return suffix
    return ""


def classify(host):
    """Returns (class, rule that decided it, the apex the name sits under)."""
    name = str(host or "").strip().lower().removeprefix("www.")
    if not name:
        return "unclassified", "", ""
    private, icann = _PRIVATE(name), _ICANN(name)
    if not private.suffix or not private.domain:
        return "unclassified", "", ""
    private_rd = f"{private.domain}.{private.suffix}"
    icann_rd = f"{icann.domain}.{icann.suffix}"
    by_psl = private_rd != icann_rd
    by_curated = any(name.endswith("." + s) for s in HOSTED_SUFFIXES)
    if by_psl or by_curated:
        rule = "+".join((["psl"] if by_psl else []) + (["curated"] if by_curated else []))
        return "platform_hosted", rule, icann_rd if by_psl else curated_apex(name)
    if name == private_rd:
        return "attacker_registered", "self", private_rd
    return "uncertain", "subdomain", private_rd


def infra_scope(hosting_class):
    """Whose properties the infrastructure fields on this row describe.

    `uncertain` resolves to operator: the name sits under an ordinary registrable domain, so the
    registration really is someone's rather than a platform's, even when we cannot say whose.
    A name that could not be parsed gets `unknown` rather than being quietly filed as operator,
    which would be a claim about it.
    """
    if hosting_class == 'platform_hosted':
        return 'provider'
    if hosting_class == 'unclassified':
        return 'unknown'
    return 'operator'
