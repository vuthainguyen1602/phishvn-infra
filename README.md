# PhishVN-Infra: detection-time infrastructure of Vietnamese-targeting phishing domains

Collection, audit and population-build code for **PhishVN-Infra**, a corpus of the DNS, TLS and
(where a registry publishes it) WHOIS state of Vietnamese-targeting phishing domains **at
detection time**, together with a benign arm sampled from raw Certificate Transparency (CT) logs
and matched on TLD and certificate age.

## What the corpus is

Retrospective URL corpora ship strings and labels; by the time anyone reads the infrastructure
behind those strings, most of the hosts are parked or taken down, so the infrastructure describes
the aftermath rather than the attacker. This corpus is the opposite object. For every
Vietnamese-targeting domain the live collectors admit, an edge collector records the A records,
CNAME, NS and MX state, the TLS certificate presented on port 443 and the WHOIS dates and
registrar, within minutes to hours of the domain first appearing on a feed. A benign arm is drawn
from raw CT logs at a rotated target certificate age so that the two arms can be matched on TLD
and age at analysis time, and a `.vn` supplement of that arm fills the one registry group the
matched arm's allow-list cannot reach. The admission funnel is part of the data: a large share of
the raw feed turns out to be registry-wildcard resolutions (a registry that answers every
unregistered name) or hosted subdomains, and only candidates with positive evidence survive the
label gate. The audit instruments that produce that funnel (the wildcard probe, the label gate,
the content map) ship with the data so that a consumer can see exactly what was removed and why.

The corpus is described in a data article (in preparation). The pre-registration that fixes the
population, the freeze rule and the analysis trigger is published with that article, not here.

## Two things to read before using `label`

`host_infra.csv` is the largest file here and carries a `label` column. It is the label the
**source assigned on admission**, and it has two properties a reuser has to know.

**It is perfectly confounded with `source`.** Every feed contributes to exactly one class, so a
model trained on `label` in this file can score well by learning which feed a row came from. Use
`infra_dataset.csv`, which carries the gate `verdict` and the `arm` the study models, or join
`label_audit.csv`. If you use the raw table anyway, hold out a whole source rather than a random
split.

**`phish` means "Vietnamese-targeting abuse the gate admitted", not "credential phishing".** The
phishing feeds are anti-fraud lists — ChongLuaDao is a *chống lừa đảo* project — so gambling,
betting-stream, investment and adult sites sit in the positive class beside credential phishing.
Only the `credential_form` verdict is direct evidence that a page asks for a credential. **There
is no `scam` label in this corpus and the gate cannot produce one**; separating the two needs
page-level adjudication this collection does not perform.

## What is here

```
scripts/                     flat layout: every module imports its siblings by bare name
  watch_host_infra.py        the infrastructure watcher (DNS / WHOIS / TLS at detection time)
  watch_ct_benign.py         CT-sampled, age-matched benign arm; --stratum vn for the .vn supplement
  watch_urlscan_brands.py    the live phishing channel (brand-token urlscan search + capture)
  watch_chongluadao.py       capture helpers the urlscan channel imports
  audit_capture_labels.py         the label gate and the registry-wildcard probe
  make_infra_assets.py          build_population(): strata, wildcard screen, gate, dedup, conditioning
  make_capture_funnel.py          funnel and accrual tables and figure
  make_infra_data_assets.py         the data article's generated tables and figures
  make_perishability.py   capture perishability: live vs backfill resolvability, retry outcomes
  audit_infra_capture.py     the WHOIS-by-policy artefact, measured before the benign arm was built
  psl.py, vn_filter.py       vendored from the URL corpus repository (see below)
  genfile.py, figstyle.py, axguard.py, paired_eval.py, compphish_features.py   shared helpers
  ops/                       the five cron wrappers, as installed on the collector
docs/collection_protocol.md  sources, cadences, age rotation, exclusions, the gate, the funnel
docs/schema.md               the 25 columns of host_infra.csv and their timestamp conventions
data/README.md               where the data lives (not in this repository)
```

## Collector layout and cron lines

All collectors run on one edge device from the repository root; every path is relative to it
(`data/raw/<source>/`). The wrappers under `scripts/ops/` take a lock so a slow tick defers the
next one instead of overlapping it, and they write their own `watch.log` beside the data.

```
# infrastructure watcher: every two hours, tails every data/raw/*/detections.csv
0 */2 * * *   /path/to/phishvn-infra/scripts/ops/host_infra_run.sh
# matched benign arm: HOURLY (the age rotation reads hour mod 4 and needs every hour)
25 * * * *    /path/to/phishvn-infra/scripts/ops/ct_benign_run.sh
# .vn supplement of the benign arm: hourly at :45, twenty minutes after the matched arm
45 * * * *    /path/to/phishvn-infra/scripts/ops/ct_benign_vn_run.sh
# live phishing channel (urlscan brand-token search + capture): six-hourly, needs URLSCAN_API_KEY
50 */6 * * *  /path/to/phishvn-infra/scripts/ops/urlscan_brands_run.sh
# hourly row-count snapshot of every feed (the CT arm back-dates first_detected, so per-day
# accrual is only recoverable from deltas of this file)
35 * * * *    /path/to/phishvn-infra/scripts/ops/rowcount_snapshot.sh
```

The urlscan channel (`watch_urlscan_brands.py --days 2 --max-captures 60`) runs six-hourly and
needs `URLSCAN_API_KEY` in the environment; the wrappers source `scripts/.env` if that file
exists. No `.env` ships with this repository and none is needed by the CT samplers or the
infrastructure watcher (CT logs and DNS are public; WHOIS is port 43).

`watch_host_infra.py` refuses to run without `dnspython`: an empty DNS field must mean a real
answer (NXDOMAIN, SERVFAIL, timeout), never a missing library.

## Running one tick by hand

```bash
pip install -r requirements.txt
python scripts/watch_ct_benign.py --dry-run                         # sample, print, write nothing
python scripts/watch_ct_benign.py --age-days 3 --batches 4          # one matched-arm tick
python scripts/watch_ct_benign.py --stratum vn --age-days 3 --target 10 --max-entries 20000
python scripts/watch_host_infra.py --max-domains 10 --delay 0.2     # gentle watcher tick
URLSCAN_API_KEY=... python scripts/watch_urlscan_brands.py --days 2 --no-capture
```

The Makefile wraps the same commands (`make benign`, `make benign-vn`, `make infra`).

## Audit, gate and population build

```bash
python scripts/audit_capture_labels.py --live      # one verdict per live-stratum phishing domain
python scripts/make_infra_assets.py              # funnel + conditioned population
python scripts/make_capture_funnel.py              # funnel/accrual tables and figure
python scripts/make_infra_data_assets.py             # the data article's tables and figures
```

`audit_capture_labels.py` uses only evidence independent of the DNS/TLS fields: exclusion verdicts
first (`hosted_subdomain`, `excluded_legitimate`, `registry_wildcard`), then the positive
verdicts in order of strength (`corroborated`, `credential_form`, `content_confirmed`,
`vn_lexical`); the rest are `no_capture` or `uncorroborated` and are counted and excluded, never
relabelled. The exclusion lists it reads (Tranco, the trusted-org registry, the blocklists) are
not in this repository (Tranco is redistribution-restricted; the others are fetched by the
collectors). If the Tranco lists are absent the script warns on stderr that every exclusion is
disabled and that its results are not valid; the deposited `label_audit.csv` is the run with the
lists present.

`make_infra_assets.py` builds the population per arm (hosted-subdomain stratum, wildcard screen,
gate, reduction of repeated attempts to the most complete record, conditioning on a non-empty A
record and `tls_present=1`) and writes the funnel. **It refuses to fit any model while the
phishing arm is below the registered trigger** (`TRIGGER = 500` conditioned registrable domains):
the protocol, not the operator, decides when results exist. Below the trigger it only regenerates
the monitoring assets; `--smoke` fits on the current data into a scratch directory that is never
read by a manuscript.

`vn_filter.py` reads `data/processed/brand_tokens.json`, which is built from the public
trusted-org registry by `build_brand_tokens.py` in the URL corpus repository; without it the
filter falls back to its built-in token set and says so.

## A note on the asset generators

`make_infra_assets.py`, `make_infra_data_assets.py`, `make_capture_funnel.py`,
`make_perishability.py`, `make_capture_lag.py` and `validate_infra_dataset.py` write LaTeX tables
and figures into a `papers/` tree that is **not** part of this repository: it is the manuscript
source the corpus was built for. Running them here produces the CSVs under `data/processed/` as
normal and creates that directory for the `.tex` output, which you can read or delete. They ship
because the path from a stored result to a printed number should be inspectable, not because a
clone is expected to typeset the papers.

## Deposit

The data are **not in this repository**. Version 1.0.0 will be archived on Mendeley Data under
CC BY 4.0 (DOI pending). The freeze rule: v1.0.0 is frozen on the day the registered analysis
trigger fires (500 conditioned phishing registrable domains), or on 2026-11-15 at the achieved
count if the trigger has not fired by then, so that the deposit is exactly the population the
detection study analyses and that study cites a DOI rather than a moving file. Later versions
extend the window under the same schema. Page captures (HTML, screenshots) are not deposited;
they are available on request for research use.

## Citation

See `CITATION.cff` (dataset DOI pending; code version `infra-v0.1.0-draft`). Please also credit
the upstream sources: urlscan.io, the Certificate Transparency logs listed by Google, the Public
Suffix List, and the Vietnamese trust registry (NCSC "Tin Nhiem Mang").

## Licence

Code: MIT (`LICENSE-CODE`). Data: CC BY 4.0 (`LICENSE`).

## Relation to github.com/vuthainguyen1602/phishvn

That repository is the code release of the PhishVN **URL** corpus. Three modules are shared by
both projects and are vendored here at the tagged commit rather than imported across
repositories: `psl.py` (registrable-domain folding with the PSL private section), `vn_filter.py`
(the Vietnamese-targeting test and brand tokens) and the blocklist/allow-list loaders inside
`audit_capture_labels.py` and `watch_urlscan_brands.py`. The URL corpus repository is the source of
truth for those modules; fixes land there first and are re-vendored here by re-running the
exporter, which lives in that repository and is not part of this one. This repository adds nothing to the URL corpus
and the URL corpus repository does not contain the infrastructure collectors.
