# Schema: `host_infra.csv`

One row per enrichment attempt of one hostname. 25 columns, written in this order by
`watch_host_infra.py`. Empty means "queried, no answer" (NXDOMAIN, SERVFAIL, timeout, no
listener, registry publishes nothing); the watcher refuses to run without its resolver library,
so a missing library can never masquerade as an empty answer.

## Timestamp conventions (read this first)

The table mixes three conventions because its columns come from three clocks:

| columns | written by | convention | example |
|---|---|---|---|
| `captured_at`; `first_detected` for `urlscan_brands`, `chongluadao_live`, `vn_phishing_live`, `tinnhiem_benign` | the collector's own clock on the edge device | **naive local time, Asia/Ho_Chi_Minh (UTC+07:00), no offset written** | `2026-08-21T13:45:02` |
| `first_detected` for `ct_benign`, `ct_benign_vn`, `ct_brands` | the CT log entry's leaf timestamp | **naive UTC, no offset written** | `2026-08-18T06:12:40` |
| `tls_not_before`, `tls_not_after` | the certificate presented on port 443 | **UTC with an explicit `+00:00` offset** | `2026-08-17T00:00:00+00:00` |
| `whois_created`, `whois_expires`, `whois_updated` | the registrar's WHOIS answer | as returned; ISO 8601, with or without an offset depending on the registry | `2026-08-10T09:31:00` |

Consequences: a CT-sourced `first_detected` is seven hours behind a collector-stamped one for the
same instant; capture lag (`captured_at - first_detected`) must be computed after putting both on
one clock, by source; and certificate age at capture (`captured_at - tls_not_before`) must
localise `captured_at` to Asia/Ho_Chi_Minh before subtracting. `whois_age_days` is computed by the
watcher at capture time against UTC and is safe to use as is.

## Columns

### Identity (7)

| # | column | type | notes |
|---|---|---|---|
| 1 | `domain` | string | the full hostname as detected (lower case, no scheme, no path) |
| 2 | `registered_domain` | string | the registrable domain under the Public Suffix List **with its private section** (`psl.py`); a free-hosting tenant keeps its own name. Rows captured before 2026-08-03 used the ICANN-only fold; re-derive from `domain` if needed |
| 3 | `source` | enum | the collector: `urlscan_brands`, `ct_brands`, `chongluadao_live`, `vn_phishing_live`, `ct_benign`, `ct_benign_vn`, `tinnhiem_benign` |
| 4 | `label` | enum | `phish` or `benign`, as assigned by the source on admission. For the phishing arm this means "admitted by the feed", not "confirmed phishing"; the gate verdict lives in `label_audit.csv` |
| 5 | `first_detected` | timestamp | when the feed first saw the name; convention depends on `source` (table above) |
| 6 | `captured_at` | timestamp | when this enrichment ran; naive local time |
| 7 | `attempt` | int | 1 for the first capture; a no-A-record domain is retried up to 3 times while at most 7 days old. All attempts are kept; the population build reduces to the most complete record |

### DNS on the full host (3)

| # | column | type | notes |
|---|---|---|---|
| 8 | `a_records` | string | IPv4 addresses after following CNAMEs, sorted, `;`-joined; empty if none |
| 9 | `a_ttl` | int | TTL of the A answer |
| 10 | `cname` | string | CNAME target without trailing dot, if one exists |

### DNS on the registrable domain (3)

| # | column | type | notes |
|---|---|---|---|
| 11 | `ns_count` | int | number of NS records; 0 when the query fails or the name has no delegation of its own (hosted subdomains) |
| 12 | `ns_hosts` | string | NS hostnames, sorted, `;`-joined |
| 13 | `mx_count` | int | number of MX records; 0 on failure |

### WHOIS on the registrable domain (5)

| # | column | type | notes |
|---|---|---|---|
| 14 | `whois_created` | timestamp | registration date as returned |
| 15 | `whois_expires` | timestamp | expiry date as returned |
| 16 | `whois_updated` | timestamp | last-updated date as returned |
| 17 | `registrar` | string | registrar name as returned |
| 18 | `whois_age_days` | int | `captured_at` (UTC) minus `whois_created`, in whole days |

All five are empty for every `.vn` row: VNNIC publishes no public WHOIS (verified 2026-07-30).
They are also empty for hosted subdomains, which have no registration. No registrant fields are
collected; the columns hold dates and registrar names only.

### TLS on the full host, port 443 (7)

| # | column | type | notes |
|---|---|---|---|
| 19 | `tls_present` | 0/1 | a TLS listener presented a certificate |
| 20 | `tls_verified` | 0/1 | the handshake verified against the system trust store with hostname check; if 0 while `tls_present=1`, the five fields below are blank (the standard library returns no parseable certificate from an unverified handshake) |
| 21 | `tls_issuer` | string | issuer organisation name, or issuer common name if absent |
| 22 | `tls_subject_cn` | string | subject common name |
| 23 | `tls_not_before` | timestamp | certificate validity start, UTC with offset |
| 24 | `tls_not_after` | timestamp | certificate validity end, UTC with offset |
| 25 | `tls_san_count` | int | number of subjectAltName entries |

`tls_not_before` is the designated domain-age proxy for `.vn`, where WHOIS is absent.

## Derived files

- `p4_infra_dataset.csv`: the conditioned population, one row per registrable domain per arm,
  with `arm` and the gate `verdict`; produced by `make_p4_assets.py`.
- `funnel.csv`: `stage, surviving, removed, note`; `accrual.csv`: `date, cumulative` admitted phishing
  registrable domains by detection day; both produced by `make_p4_funnel.py`.
- `label_audit.csv`: `registered_domain, source, first_detected, verdict, stage_removed` and the evidence columns `in_tranco, in_allowlist, blocklists, renders_vietnamese, credential_form, vn_lexical` (no page content).
- `content_map.csv`: `registered_domain, renders_vietnamese, credential_form`.
- `wildcard_probe.csv`: `suffix, probe_name, probed_on, resolver_host, answers, wildcards`.
- `ct_benign_seen.txt`, `ct_benign_vn_seen.txt`: the samplers' seen-sets.
