# What the label gate reads besides the capture log

`audit_capture_labels.audit()` decides which phishing candidates are admitted, and it consults
five inputs that are not part of the capture. Only some of them can be redistributed, so this file
records what each one was, precisely enough that a reader can obtain the same input rather than
take our word for the result.

It exists because the reproduction does not otherwise land on the published number. Placing the
deposited `host_infra.csv` and `content_map.csv` and running `make population` admits 224
candidates; the published figure is 215. Every one of the remaining nine is an exclusion the gate
could not make because one of the inputs below was absent. Measured, not inferred: with the Tranco
sample restored the same build admits 210, and the feed allowlists move it back up.

## Tranco ranking

Used to exclude established sites: a registrable domain that ranks is a real site with traffic,
and phishing domains are days old and unranked.

- Downloaded 2026-07-16 from `https://tranco-list.eu/top-1m.csv.zip`, which serves that day's
  list.
- The list that day is **GQ4LK**, permanently available at
  `https://tranco-list.eu/download/GQ4LK/1000000` (created 2026-07-16T22:00Z; providers crux,
  farsight, majestic, radar, umbrella; daily list, PLD filter on).
- Our stored copy overlaps GQ4LK on 79,766 of its 79,999 domains (99.7%), with a median rank
  difference of 387, which is the drift of an adjacent daily list. The identification is therefore
  strong but not exact: the fetcher recorded no list ID at the time, which it should have, since
  Tranco publishes permanent list IDs for this purpose and its own documentation asks callers to
  cite the one they used.

**Not redistributed, and not by oversight.** Tranco is composed from five providers under
different terms, including the Chrome UX Report under CC BY-SA 4.0. A share-alike component cannot
be relicensed into this deposit's CC BY 4.0, so the list is cited rather than shipped. Fetch it
from the permanent link above.

**`data/external/tranco_top100k.csv` is misnamed.** It holds 79,999 rows whose ranks run to
999,996: a stratified sample across rank bands drawn by `fetch_tranco.stratified_sample` with
seed 42, not the top 100,000. The gate therefore excludes ranked domains only where the sample
happens to cover them, which is a property of the exclusion worth stating and is why restoring the
file moves the admitted count by more than a handful.

## Tin Nhiem Mang trusted-org registry

`data/raw/tinnhiem_org/*.csv`, and `data/processed/brand_tokens.json` derived from it by
`build_brand_tokens.py` (1,798 tokens). Used only to exclude, never to confirm.

Not redistributed: it is a Vietnamese national registry's own publication, and republishing a
government certification list inside a research deposit is a permission question we have not
asked. The collector that fetches it ships, so the list can be rebuilt at its source.

## Feed allowlists and seen-domain sets

`watch_urlscan_brands.load_official()` and `data/raw/chongluadao_live/seen_domains.txt`. Derived
from the feeds the corpus already names and rebuilt by the collectors that ship with it.

## What this means for a reader

The deposited files reproduce the capture log, the conditioned population's schema, the funnel and
the audit verdicts exactly. They reproduce the admitted count to within the exclusions above.
A reader who wants the published 215 needs the Tranco list from its permanent link and the
registry the collectors rebuild; a reader who only wants to re-derive the infrastructure features
needs neither.
