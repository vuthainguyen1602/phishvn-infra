# watch_ct_brands.py — Certificate Transparency feed of Vietnamese brand-impersonation domains.

Applies to: `scripts/watch_ct_brands.py`

WHY: urlscan only sees a domain after someone submits it; CT publishes the hostname the moment a
cert is issued — which VN phishing kits do before the page has content — so CT catches the same
brand-in-hostname domains hours to days earlier, plus ones never submitted to urlscan.

WHY crt.sh POLLING, NOT CERTSTREAM: certstream.calidog.io died in 2023, and tailing raw CT logs
means millions of certs/day for a handful of matches — wrong trade for a Jetson running four other
collectors. 27 substring queries every couple of hours replace the firehose, at the price of
crt.sh's ingestion lag (minutes to hours) — still earlier than a urlscan submission.

THE QUERY IS A PREFIX, `token%`, since 2026-09-18. It was `%token%` until then, and crt.sh does not
match a pattern with a wildcard at both ends against hostnames: it answers an empty 200, at once,
which for eight weeks read as "no certificates" and then as "crt.sh is degraded". Same minute,
healthy service: `%techcombank%` 0 rows, `techcombank%` 866. The price is coverage of names that
begin with the token only. `%token%` is still asked of the tokens it has answered, because what it
returns there (organizationName matches) is a different set of certificates. Measurements:
scripts/ct_brands_note.md.

THE WINDOW protects against that lag, so it is far wider than the cadence: certs are filtered on
entry_timestamp, which may be hours old by the time crt.sh can serve them, and anything outside
the window is lost silently (`seen` de-duplicates, it does not rescue). 168h is from measurement:
a token accrues ~1 non-official candidate a MONTH (bidv: 26 unexpired certs, 5 within 30 days, 1
surviving filters); crt.sh answers ~half the time and the deadline defers tokens, so a token may
be queried successfully only every day or so — a 48h window gave it barely one chance (newest
bidv cert observed was 51h old, just outside). Seven days costs nothing client-side.

A HIT is a CANDIDATE, not a labelled phish — weaker than a urlscan hit (cert proves setup, not a
live lure) but can predate the page. Capture (urlscan_submit.py / safe_crawl.py) is deliberately
not done here: this script's one job is to notice, cheaply and early.

Brand tokens, official-domain whitelist and token boundary rule are imported from
watch_urlscan_brands.py so the two feeds cannot drift apart.
Three filters are this feed's own, all consequences of asking by prefix and all dated 2026-09-19: a
set of registered domains confirmed as the brand's own, a drop of cloud-internal hostnames, and a
closing boundary for tokens of four characters or fewer. What they are, what they cost and how a
reader applies them to rows collected earlier: docs/decisions/ct-brands-brand-owned.md.

RUN:
  python scripts/watch_ct_brands.py --hours 6            # normal cron tick
  python scripts/watch_ct_brands.py --hours 168          # one-off backfill of the past week
