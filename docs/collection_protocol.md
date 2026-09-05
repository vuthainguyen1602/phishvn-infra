# Collection protocol

This document describes how every row of `host_infra.csv` came to exist: the sources that admit a
domain, the watcher that enriches it, the benign arm's sampling recipe, the exclusions, the label
gate and the funnel that turns the raw table into the conditioned population. The constants quoted
are the scripts' defaults; the scripts are the authority where the two disagree.

## 1. Sources and admission

Every row descends from a per-source `data/raw/<source>/detections.csv` written by one live
collector; the `source` column names that collector. Three lanes feed the watcher:

| `source` | `label` | collector | what admits a domain |
|---|---|---|---|
| `urlscan_brands` | phish | `watch_urlscan_brands.py` | urlscan search hits for hostnames carrying a curated Vietnamese brand token (banks, carriers, public services, logistics) plus a few Vietnamese page-content queries; official domains of the real operators are dropped before recording; a per-source seen-set prevents re-admission |
| `ct_brands` | phish | CT polling for the same tokens | certificate log entries whose names carry a brand token |
| `chongluadao_live`, `vn_phishing_live` | phish | historical feed importers | backfill only; they emitted no live detection in the window |
| `ct_benign` | benign | `watch_ct_benign.py` | the matched arm, section 3 |
| `ct_benign_vn` | benign | `watch_ct_benign.py --stratum vn` | the `.vn` supplement, section 4 |
| `tinnhiem_benign` | benign | trusted-org registry importer | certified Vietnamese sites; 100% `.vn`, years old; a comparator, never pooled with the matched arm |

Because urlscan's free tier exposes no maliciousness verdict, `label=phish` on admission means
only "brand-token hit". The label gate (section 6) is what turns it into evidence.

`first_detected` is the value the feed itself assigned: the moment the collector first recorded
the hostname (urlscan channel, local clock), or the certificate's log-entry timestamp (CT
channels, UTC). See `schema.md` for the timestamp conventions.

## 2. The infrastructure watcher

`watch_host_infra.py` runs every two hours on the same edge device as the collectors
(`scripts/ops/host_infra_run.sh`; cron `0 */2 * * *`). One tick:

1. tails every `detections.csv` in its source map and collects domains it has not observed, or
   whose last observation had no A record and is eligible for a retry;
2. orders the queue by perishability: phishing detected within the last 24 h first, then benign,
   then the stale backlog;
3. enriches at most `--max-domains 150` domains, pausing `--delay 0.8` s between them;
4. appends one row per observation to `data/raw/host_infra/host_infra.csv`; `captured_at` is the
   enrichment moment.

A domain whose capture shows no A record is re-attempted up to `--max-attempts 3` times while the
detection is at most `--max-age-days 7` old; `attempt` counts these and the append-only file is
the retry state. Every attempt row is deposited; the population build keeps the most complete one.

What is measured, and on what:

- DNS on the full host: A records (sorted, semicolon-joined), TTL, CNAME target.
- DNS on the registrable domain: NS count and hosts, MX count.
- WHOIS on the registrable domain: created, expires, updated, registrar, age in days.
- TLS on the full host, port 443: a verified handshake first; if verification fails
  (self-signed, expired, name mismatch) an unverified retry records `tls_present=1,
  tls_verified=0` with the certificate fields blank.

The watcher sends no HTTP request to a measured host: its contact is the DNS and WHOIS lookups
above plus one TLS handshake that reads the served certificate and closes. Requests to the
third-party services the collectors poll — crt.sh and urlscan.io — do carry a research
User-Agent naming a contact address, so an operator who wants to ask about the traffic can. That
string changed from `nvthai@utc2.edu.vn` to `thaivn_ph@utc.edu.vn` on 2026-08-28 when the
author's institutional address moved; nothing else about the requests changed, and no row is
affected either way.

Raw values are stored, never derived booleans. NXDOMAIN, SERVFAIL and timeout are all recorded as
an empty field; the watcher refuses to start if `dnspython` is missing, so an empty field is always
a real answer. The registrable domain is folded with the Public Suffix List **including its
private section** (`psl.py`), so a tenant of a free-hosting provider keeps its own name; such a
name has no registration of its own, and its blank WHOIS and zero NS count are the honest
observation. Rows written before 2026-08-03 used the ICANN-only fold; `domain` was always the full
host, so older rows can be re-derived.

VNNIC publishes no public WHOIS for `.vn` (port 43 refused, no RDAP, absent from the IANA
bootstrap; verified 2026-07-30), so `whois_*` is empty for every `.vn` row by registry policy. The
intended age proxy there is `tls_not_before`.

## 3. The matched benign arm

`watch_ct_benign.py` (`source=ct_benign`) samples from the raw CT logs listed as usable in
Google's published log list, so that its certificates are as young as the phishing arm's. Reading
the head of a log would fix certificate age at zero by construction; instead each tick names a
target age (`--age-days`), binary-searches the leaf timestamps of a randomly chosen log for the
offset where that age lives, and draws `--batches 4` short batches of `--batch-size 32` entries
from there.

The target age is rotated by the hour of the day in `scripts/ops/ct_benign_run.sh`: hour mod 4
gives 1, 3, 7 or 14 days. This requires an **hourly** cron line (`25 * * * *`); on a two-hourly
line only two of the four strata are ever visited. Until 2026-08-16 the wrapper ran on a
`*/4` line, which pinned the target at one day: rows before that date are younger than the
design intends. Split on the date.

Kept names: apex names (or their `www.` form), one per registrable domain, from the 20 TLDs on
an allow-list measured from the phishing arm's non-`.vn` mix on 2026-08-03 (`com`, `net`, `cc`,
`info`, `online`, `vip`, `website`, `bet`, `site`, `co`, `org`, `id`, `me`, `top`, `su`, `store`,
`xyz`, `click`, `link`, `life`). Collection is deliberately broader than the phishing mix so that
matching can be done at analysis time.

Exclusions (`is_excluded`): a name is dropped if it sits under a PSL private-section suffix or a
hand-listed hosting suffix, if it contains a Vietnamese brand token or a Vietnamese word from the
lexical list, if it is on the official-domain list, or if any of the project's blocklists names
its registrable domain. These guarantee that the arm is *not* Vietnamese-targeting while the
phishing arm is by construction; the asymmetry is safe only as long as no analysis reads the name
itself as a feature. The arm's seen-set (`seen_domains.txt`) is deposited.

## 4. The `.vn` supplement

Two of the rules above bar `.vn` outright (the TLD allow-list and a suffix test inside the
exclusion function), so for three weeks the matched arm held no `.vn` name at all.
`--stratum vn` (`source=ct_benign_vn`; `scripts/ops/ct_benign_vn_run.sh`, cron `45 * * * *`,
first tick 2026-08-21 13:45) is the same sampler, age search and exclusions with exactly those two
rules lifted, writing to `data/raw/ct_benign_vn/` with its own seen-set. Because `.vn` is rare in
the logs (about one apex name in 2,000 entries), a tick walks a few logs sequentially from the
age offset until `--target 10` names are kept or `--max-entries 20000` entries are read. The
stratum fills `.vn` matching cells only and is never pooled into the off-`.vn` arm.

## 5. The certified comparator

`tinnhiem_benign` rows are the trust registry's certified Vietnamese sites, enriched by the same
watcher. They are 100% `.vn` and years older than either sampled arm, so pooling them with the
matched arm would make TLD and certificate age label markers. They are deposited as their own
source for users who want a deployment-realistic benign population beside the matched one.

## 6. The label gate

`audit_capture_labels.py` assigns every live-stratum phishing registrable domain one verdict, using
only evidence independent of the DNS/TLS fields. Exclusion is tested before corroboration:

| verdict | meaning |
|---|---|
| `hosted_subdomain` | the name sits under a listed hosting suffix (no registration of its own) |
| `excluded_legitimate` | a Tranco rank or an allow-list hit |
| `registry_wildcard` | the registry answers every unregistered name and the candidate's capture-time addresses lie inside that answer: there is no registration at all |
| `corroborated` | an independent blocklist names the registrable domain |
| `credential_form` | the stored DOM contains a password input |
| `content_confirmed` | the capture's visible text is Vietnamese |
| `vn_lexical` | a Vietnamese word in the name |
| `no_capture`, `uncorroborated` | no positive evidence; counted and excluded, never relabelled |

The wildcard probe resolves, once per public suffix, a fixed name that cannot have been
registered; if the registry answers, the suffix is wildcarded and candidates resolving into that
answer are removed. Its per-suffix answers are deposited (`wildcard_probe.csv`). Content evidence
is computed where the captures live (`--export-content`) and read where the exclusion lists live
(`--content-map`), because running the audit without the lists disables every exclusion; the
script warns on stderr when that happens.

## 7. The population build and the funnel

`build_population` in `make_infra_assets.py` applies, per arm: the hosted-subdomain stratum, the
wildcard screen (every arm, though only the phishing feed is affected), the gate (phishing arm
only), reduction of repeated attempts to the most complete record (the one with the most of
`a_records`, `tls_not_before` and `ns_hosts` populated), and conditioning on a non-empty A record
and `tls_present=1`. The live stratum is defined by `first_detected` (phishing) or `captured_at`
(benign) on or after 2026-07-30, the watcher's first tick; domains detected earlier were enriched
from a backlog, days late, and are a different population. Each stage's count is written to
`funnel.csv`; `make_capture_funnel.py` draws it together with the per-day accrual.

The script fits no model below the registered trigger of 500 conditioned phishing registrable
domains; see the README.
