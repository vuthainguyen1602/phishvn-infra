# Independent live collection — active scope, 9 September 2026

This dataset is separate from the published URL corpus. Its labelling job does not
read, copy, merge or depend on that corpus or its manual annotation sheets.
Source-tier conventions describe the provenance of this collection alone.
The discarded cross-corpus labelling experiment is not part of this pipeline.

Inputs: `data/raw/host_infra/host_infra.csv` plus the same collection's
`chongluadao_live`, `vn_phishing_live` and `tinnhiem_benign` detection ledgers.
The inherited live community/mixed-feed labels are phishing/bronze; the certified
registry cohort is benign/gold. These are source-derived labels, not independent
verification. Unknown CT/brand-query candidates may acquire a source label only
from an exact-host report within these own ledgers. Conflicts remain unknown.
No parent/sibling or URL-to-whole-host expansion is performed.

Outputs live under `data/processed/live_labels/`: all `observations.csv`, binary
source-labelled `labelled.csv`, unresolved `review_queue.csv`, risk-ranked
`review_candidates.csv`, source `evidence.csv` and `summary.json` with counts and
input hashes. Original capture labels remain in `legacy_label`; source tier and
basis are explicit. Report-time labels are not claims that every later page on
the host is malicious. No data is overwritten in `data/raw/` and no human review
is invented.

Unresolved observations also carry `candidate_risk_score`, `candidate_risk_level`,
`candidate_review_priority`, `candidate_risk_reasons`, `impersonation_sector` and
`brand_token_hits`. These fields rank review work only. Brand, government, bank,
e-commerce, payment, telecom and delivery tokens on unconfirmed hosts remain
`label=unknown` until exact-source evidence or human review promotes them.

Run `make live-labels` locally. On Jetson, `scripts/ops/live_labels_run.sh`
replaces the discontinued paper's monitoring job, with an independent lock and log.
The collectors remain active; discontinuing the paper does not delete its data.

## Content inspection (independent live collection)

`data/processed/live_content/` contains current-root-page evidence and suggestions,
not verified labels. `observations.csv` now includes `content_status`,
`content_review_priority`, `content_checked_at`, and `content_evidence_path`.
These fields never modify `label`, `tier`, or `binary_label_usable`.

Run on Jetson:

```sh
sudo -n docker build -t phishvn-content:v1 scripts/content
python3 scripts/inspect_live_content.py --sudo-docker --self-test
CONTENT_LIMIT=10 bash scripts/ops/live_content_run.sh
```

The browser runs in a disposable container with no network, dropped capabilities,
a read-only root, and limits of 1 CPU / 1 GiB RAM. Only its capture directory is
writable. The supervisor supplies bounded GET responses over stdin/stdout; it rejects
private/reserved addresses and pins the checked public IP for each request, including
redirects. No credentials, host browser profile or Docker socket enter the container.
Service workers, downloads and non-GET requests are blocked. TLS errors are recorded;
HTTP fallback is a separate attempt. Root-page failures remain unavailable, not benign.

The reference registry comes solely from this collection's
`tinnhiem_benign/detections.csv`; its exact snapshot hash is recorded. Identity
matching uses title, headings and visible image alt text. Screenshot pixels are for
human review, not an implemented vision-model verdict. An unmatched brand identity
plus a sensitive field on that frame or payment language creates a high-priority
suggestion. Registry gaps, third-party authorization, news, demonstrations and
legitimate resellers still require a reviewer to establish context.

Open `data/processed/live_content/review.html` locally with its `captures/` directory.
Do not open captured `page.html` in a normal browser: inspect the PNG and evidence JSON.
Copy `review_queue.csv` to a separately named review file before entering reviewer,
reviewed_at, verdict and rationale; the generated queue is overwritten each run.
A review must cite the exact capture and resolve claimed identity, authorization,
and deceptive credential/payment intent. Suggestions and even current-page reviews
must not automatically relabel every historical observation of a hostname.

Default batches inspect up to 50 unique unknown hosts. Unseen CT/brand candidates
come first; previously checked hosts are eligible after 7 days, after unseen hosts.
The initial pass uses the existing data, with no P1 corpus import. The root-only,
GET-only capture may miss path-specific or interaction-gated phishing; missing
signals never establish that a site is benign. HTML, screenshot, request/redirect
records, registry/code hashes and container image ID are retained per attempt.
