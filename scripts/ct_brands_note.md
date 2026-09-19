# Why the CT lookalike arm stays dry, measured 13 September 2026

> **Superseded in part, 18 September 2026.** Route 1 below was diagnosed as "crt.sh drops expensive
> substring queries". The measurement was right and the conclusion stopped one step short: nobody
> had tried a different pattern. With crt.sh healthy (8 of 8 requests 200), `%techcombank%` returned
> an empty 200 in 0.9 s, `techcombank.com.vn` 121 certificates, and **`techcombank%` 866
> certificates naming 396 hosts that carry the token** -- 3 the bank's own, 342 under the `.ph`
> registry wildcard, 51 lookalikes (`techcombanks.com`, `techcombank.icu`). `vnpay%` returned 656,
> `dichvucong%` 435, `tpbank%` 61. crt.sh does not match a pattern with a wildcard at both ends
> against hostnames at all; what the few answering tokens returned were organizationName matches.
> The collector now asks `token%` for every token and keeps `%token%` only for the tokens that
> form has answered (`patterns()` in `watch_ct_brands.py`). A six-token smoke run produced 9
> candidates in one tick, as many as the arm had produced in its first eight weeks. The prefix
> form sees only names that BEGIN with the token, so `login-techcombank.com` is still invisible:
> the last section's point about an indexed substring search stands for that remainder. Routes 2
> and 3 are unchanged.

`ct_brands` has produced 9 detections and has been dry for 307 hours. Before anyone rebuilds it,
here is what was tried and what each attempt actually returns, so the next attempt starts from the
measurements instead of the idea.

## The three routes, and why none of them works today

**1. Query crt.sh by brand token — the current implementation.** Of the 179 tokens asked for on
the last tick, 152 came back as an empty 200 and have never returned a row in up to 16 ticks, and
11 failed outright. crt.sh drops expensive substring queries rather than answering them slowly, and
`%token%` against a 6-billion-row identity index is expensive. 16 tokens do answer (vietcombank 8
certs, viettel 222, mobifone 155), which is why the arm looks alive in the log and produces almost
nothing. The 2026-09-11 fix stopped this being recorded as "no certs"; it is recorded as
UNRESOLVED, which is honest but is not data.

**2. Sample raw CT logs, the way `watch_ct_benign.py` does.** That collector works because it is
SAMPLING: any few hundred certificates are a fair draw from everything being issued, and the benign
arm needs a few hundred names. Brand matching is the opposite problem. It needs COVERAGE: a
lookalike is a needle, and a tick that reads a few hundred entries out of roughly 200 million
issued per day will find one essentially never. Full coverage is ~30 GB/day of `get-entries` on a
device behind a home connection. The arithmetic, not the engineering, is what rules this out.

**3. The CertStream firehose (`wss://certstream.calidog.io/`).** Reachable -- TCP 443 open, the
site returns 200 -- and it delivered ZERO certificate messages in a 60-second listen on
2026-09-13. The public feed is not carrying traffic. A local CertStream server is the same
bandwidth problem as route 2 wearing a different hat.

## What was done instead

The detection budget went where it measurably converts: the urlscan brand watcher, which produced
858 of the 949 new phishing domains seen in the last fourteen days. Its token list gained eight
banks and four service brands on 2026-09-13, each admitted only after measuring how much
legitimate traffic the token drags in -- the same test that had already excluded `momo` (4,679
scans in 30 days) and `shopee` (1,305). `acb` (5,049), `ninjavan` (3,374), `jtexpress` (2,265) and
`zalo` (672) were measured and REJECTED; they are listed in the code so they are not re-added.

## What would actually change this

An indexed CT search that serves substring queries at scale, or a CT feed that pushes names rather
than whole certificates. Censys and SecurityTrails both sell one; neither is free, and this
repository has never paid for a data source. That is a budget decision, not an engineering one,
and it belongs to whoever makes it rather than in a collector that quietly returns nothing.
