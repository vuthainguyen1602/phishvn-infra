# CT brand watcher: ten brand-owned names and two noise rules, 2026-09-19

**Applies to:** `scripts/watch_ct_brands.py` (`CT_BRAND_OWNED`, `CLOUD_INTERNAL_SUFFIXES`, `short_token_closed()`), source
`ct_brands` in `data/raw/ct_brands/` and wherever that source name is carried downstream.

## What changed, and when

On 2026-09-19 the author read all 103 rows the source had produced (8 from the both-ends query
before 2026-09-18, 95 from the prefix query's first night, see `ct-brands-prefix-query.md`) and
confirmed eight registered domains as belonging to the brand they name:

`viettel.io`, `viettelcloud.vn`, `viettelstore.vn`, `viettelmedia.vn`, `vnptcloud.vn`,
`ahamove.com`, `bidv.com.mm`, `ebanking-vietinbank.de` (and every host under them).

From the deploy of this change the watcher no longer reports a host on or under those domains.

## Why here and not in the shared whitelist

`load_official()` in `watch_urlscan_brands.py` also filters `urlscan_brands`, a source whose filter
is fixed by a registration made before this finding. A finding made on the CT side should not move
it, so the set is local to this feed. It is a `frozenset` that readers import; nothing copies it.
The label gate (`audit_capture_labels.py`, `load_allowlists()`) imports it from 2026-09-19: before
that, `ahamove.com` stood in the gate's output as content-corroborated phishing, because the
operator's own site renders Vietnamese. The gate matches registered domains, so the one tenant
host in the set (`vinpearltravel.cloudhms.io`) is not screened there.

## What this does to the data

- **Nothing collected is rewritten.** Nine rows in `detections.csv` sit on or under these domains
  (`xs2apsd2.ebanking-vietinbank.de` is the ninth). Six predate the query change. They stay, and
  whatever reads the file applies `CT_BRAND_OWNED` at read time.
- A reseller's subdomain that carries a brand name on somebody else's domain
  (`viettelmedia.dangkymang.vn`, `viettelmedia.4g5g.vn`) is not brand-owned and stays a candidate.

## Two more, the same day, on measured evidence

Of the seven hosts first left open, the author settled two after a check of DNS, registration
records, certificate history and landing pages (2026-09-19, about 09:30 +07):

- `viettelcloud.com.vn`: the same two addresses as `viettelcloud.vn` (171.244.232.16/17, netname
  VIETTEL-VN), the same name servers (`ns7/ns8.viettelidc.com.vn`), certificates since 2017.
- `vinpearltravel.cloudhms.io`: the registrant of `cloudhms.io` is VINHMS SOFTWARE PRODUCTION AND
  TRADING JOINT STOCK COMPANY (VN, registered 2019). Only this host is listed. `cloudhms.io` is a
  multi-tenant platform, and another tenant's name there is not the brand's.

Both rows stay in `detections.csv` like the other nine.

## Left open on purpose

Five hosts the check did not settle remain candidates and are not filtered by this set. What was
measured about each is kept in the development repository, not here: it describes third parties'
infrastructure, and a candidate is not a finding.

## Two noise rules, decided the same day

Both are consequences of asking by prefix, so both live in `watch_ct_brands.py` and neither
touches `token_at_boundary()`, which `urlscan_brands` shares. Deployed 2026-09-19, after the
brand-owned set, the same morning.

- **(a) Cloud-internal hostnames.** A host under `amazonaws.com` is dropped. Managed cache and
  database endpoints get machine-made names, and some begin with four characters that spell a
  token (`bidvqipiy....cache.amazonaws.com`). 3 of the first 103 rows.
- **(b) A token of four characters or fewer must end at a boundary** (`short_token_closed()`):
  followed by a non-letter, or ending its label. Five tokens are that short: `bidv`, `ghtk`,
  `gplx`, `utc2`, `vnpt`. Replayed over the first 103 rows it drops 22: 17 English names under
  `bidv` (`bidvest*` x7, `bidverse*` x3, `bidvault`, `bidverity`, `bidvesting`, `bidvets`,
  `bidvex`, `bidvia`, `bidvincer`), one machine-made `gplx...crosspaysolutions.app`, and four
  under `vnpt`: `vnptcloud.vn` (brand-owned anyway), `vnptplatform.vn` (unsettled, above), and
  `vnptmytv.com` and `vnptwifi24h.com`, which read like resellers. Those last two are the stated
  cost. It keeps 12, among them `bidv-kiemtra.pages.dev`, `bidv2026.ato.vn`,
  `bidv.herokaupp.com`, `vnpt365.workers.dev`, `gplx-gialai.workers.dev`.
- **Not filtered: `chatgpt.site` / `chatgpt-team.site`** (12 rows). It is a hosted-subdomain
  platform like `pages.dev`; dropping it by name would be a judgement about content made without
  looking at content. A hit is a candidate and the capture decides.

As with the brand-owned set, the 25 rows these rules would have stopped stay in
`detections.csv`; a reader that wants the source as it is now collected applies
`CLOUD_INTERNAL_SUFFIXES` and `short_token_closed()` to the `domain` and `brand` columns. So the
source has a third regime boundary on 2026-09-19 for the five short tokens only. Longer tokens
that collide with English (`payoodle.com`, `abbankingsley98.workers.dev`,
`homecreditlenders.com`) are not covered by either rule and remain in the yield.
