# Label policy v3 — source tiers, 15 September 2026

`label` is the **source's assertion**, carried with a `label_status` that says what evidence
backs it. `arm` stays the acquisition cohort. Label correctness is **measured** on a blinded,
stratified, two-annotator sample (`label_validation.csv`), not asserted row by row. This
replaces the 8 September 2026 policy ([v2](label_policy_v2.md)), whose two-reviewer requirement
for every row had left every deposited row `label=unknown`; v2 stays archived for the record.

| `label_status` | Rows | Meaning | `label` | `training_eligible` |
|---|---|---|---|---|
| `feed_reported` | phishing arm, verdict `historical_feed_match` | an exact-host record in a second, independent list | `phishing` | 1 |
| `content_corroborated` | phishing arm, verdicts `credential_form`, `vietnamese_content` | capture-time page evidence (a password input, Vietnamese rendered text) | `phishing` | 1 |
| `source_reported` | phishing arm, verdict `vn_lexical`; every benign row | the feed or brand-query assertion alone; for benign rows the sampler's or the registry's assertion | `phishing` / `benign` | 1 |
| `reviewed` | rows adjudicated in the validation sample | two blinded annotators + adjudication; the verdict replaces the source's | adjudicated, or `unknown` when `unsure` | 1, or 0 when `unsure` |
| `conflict` | `label_audit.csv` only | a feed report coexists with a Tranco/allow-list hit; never admitted | `unknown` | 0 |
| (empty) | `label_audit.csv` only | a removed class (`registry_wildcard`, `hosted_subdomain`, `reputation_screened`, `no_capture`, `uncorroborated`, `vn_registry_gated`, `list_only_source`) | `unknown` | 0 |

**Gate amendment, 2026-09-19: a certificate-only report needs a list.** The status table above
is unchanged; what changed is which verdicts the gate will give a domain that ONLY
`ct_brands` reported. A certificate-transparency hit proves that a name carrying a brand token
was set up, not that a lure was served, and every other phishing source here is a report about a
page or a listing of one. So for such a domain the page's language, a password input and the
words in its name no longer corroborate anything: it is admitted on `historical_feed_match` and
otherwise leaves as the named removal `list_only_source` (`label=unknown`,
`training_eligible=0`). The three evidence columns are still written for it, so a reader who
prefers the older rule can apply it. A domain that another source also reported keeps the
ordinary rules. At the amendment the rule removed eight domains, none with a list behind it:
admitted until then on `vietnamese_content` (3), `vn_lexical` (4) and `credential_form` (1),
among them a contractor's house-building site and a reseller's login page. The blinded
validation sample was drawn on 2026-09-15, when this source had contributed one domain, so its
strata are not affected. The version string stays `3.0.0`: the mapping from verdict to label is
the same, and no deposit has been released under either rule.

`policy_version` is `3.0.0` on every row. The ordering weakest → strongest is
`source_reported < content_corroborated < feed_reported < reviewed`; filter on it for a stricter
positive class, and quote the measured mislabel interval of the matching stratum with any
supervised result.

## What stays true from v2

- Feed matches use explicit hostname columns. A URL report does not label its host, a hostname
  report does not label its parent, siblings or hosting provider, and a report at one time is
  not a confirmation at another.
- Tranco and allow-list membership **remove** candidates (`reputation_screened`); they never
  certify a page benign. Hosted-service and wildcard screening concern study eligibility.
- Language and password-input flags are the weakest positive tiers; they corroborate the
  source, they do not verify deception.
- Missing DNS probe records stay unmeasured in offline regeneration.

## Validation (`make_label_validation.py`)

1. `--draw`: a fixed-seed sample from `infra_dataset.csv`, stratified by (arm, verdict): the
   feed-matched tier whole, the three heuristic tiers and the two benign arms sampled without
   replacement. Writes `annotator_A.csv`, `annotator_B.csv` (blinded, differently shuffled),
   `strata_key_KEEP_BLINDED.csv` (stratum, size, inclusion probability; **never given to an
   annotator**), `adjudication.csv` and `sample_manifest.json`.
2. `--bundle`: one blinded evidence bundle per item under `evidence/<item_id>/`: the urlscan
   artefact taken at discovery when one exists, else this collection's own isolated-browser
   capture, with the feed name, the screen verdict and the pipeline's suggestion withheld.
   Items with no evidence are listed in `evidence_coverage.csv`; they are marked `unsure`
   with the limitation stated, never inferred benign.
3. Reviewers follow `pilot_protocol.md` (identity, authorisation, deceptive intent, exact
   evidence URL, observation time, artefact hash, rationale) and fill their own sheet only.
   Disagreements and `unsure` verdicts go to `adjudication.csv`.
4. `--analyze` (run by `make p4b` before the deposit is rebuilt): agreement, Cohen's kappa, the
   mislabel rate per stratum with a Wilson 95% interval, and the inclusion-probability-weighted
   rate per arm → `label_validation.csv`; adjudicated verdicts → `label_review.csv`, which
   `make_infra_assets.build_population` applies as `label_status=reviewed`. While any item lacks
   both reviews the outputs are in the `pending` state and no row is overridden.
