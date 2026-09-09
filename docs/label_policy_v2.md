> **Superseded 2026-09-09 for active dataset work:** use the source-tier policy in the main research repository. This document describes the archived strict v2 experiment.

# Label policy v2 — 8 September 2026

`label` is an outcome; `label_status` records the available evidence. The legacy
`arm` in infrastructure monitoring is an acquisition cohort, never ground truth.

| Status | Meaning | Automatic training label |
|---|---|---|
| candidate | Collection, language, brand or form signal only | unknown |
| feed_reported | Exact-scope historical feed report | unknown |
| conflict | Feed report and exact-host reputation signal coexist | unknown |
| unknown | No supported outcome, including unreviewed CT controls | unknown |
| confirmed_phishing | Reviewed positive with scoped, hashed evidence | phishing |
| verified_benign | Reviewed negative with scoped, hashed evidence | benign |

The automatic migration emits only the first four statuses. It does not claim
that all historical labels are false. In particular, older URL-corpus human reviews are
preserved under `data/docs/verify/`; they are not extrapolated across times or URL
paths. Reviewers must align their evidence to the new observation before training.

## Reproduce locally

Run from the repository root in the project's Python environment:

```bash
python scripts/relabel_existing_data.py
python scripts/make_infra_assets.py --monitor-only
python scripts/make_capture_funnel.py
python scripts/make_infra_data_assets.py
```

`data/processed/labels_v2/host_infra.csv` and `dataset_url.csv` contain every
original row, preserve `legacy_label`, and use `label=unknown` with
`training_eligible=0` unless a separate validated review supplies an outcome.
`feed_evidence.csv` links each source row and file hash to its exact observable
and original report timestamp. `summary.json` records input hashes and transition
counts. `review_queue.csv` has blank reviewer fields intentionally; it includes
both acquisition arms. It is a triage inventory, not the final infrastructure outcome schema.

Original raw files and the published URL benchmark are retained for historical
reproduction. They must not be described as the v2 verified training set. Existing
benchmark metrics apply to their historical label protocol and are not revalidated
by this migration. Regenerating confirmed-outcome metrics requires actual review.
The previous infrastructure tables are backed up under
`data/interim/label_policy_v1_backup/` with hashes.

## Evidence boundaries

Normalize IDNA, hostname case and trailing DNS dots. Keep `www`, ports, paths and
query strings distinct. A URL report cannot label its entire host; a hostname
report cannot label its parent, siblings or hosting provider. Multiple feeds are
not presumed independent. A deduplication `seen_domains.txt` is not a report.
Only explicit schema columns are parsed, never arbitrary CSV strings containing dots.

A report at one instant remains a historical report. No validity interval or
capture-time confirmation is invented. Tranco, allowlist membership, language,
password fields, certificate age and DNS availability never certify an outcome.
Missing cached DNS probes are unmeasured; live probing requires explicit `--reprobe`.

Infrastructure review input additionally requires `annotator_a_id`, `annotator_b_id`,
`evidence_url`, `evidence_path`, `evidence_sha256`, `observed_from`, `observed_until`
and `benign_evidence`, alongside the prior annotation/adjudication/blinding fields.
Both arms require review. An evidence artifact must exist locally and match its
hash, and its exact hostname and declared observation interval must cover the
retained capture. These mechanical checks cannot verify that a reviewer is honest
or that the supplied evidence actually supports the rationale; that remains a
substantive annotation task.

The URL baseline retains its original `data/processed/dataset_url.csv` default.
Its input validation rejects unknown labels and explicit training exclusions.
The independent live collection uses `make live-labels` and its own source-tier
policy; this archived experiment does not govern either active dataset.
