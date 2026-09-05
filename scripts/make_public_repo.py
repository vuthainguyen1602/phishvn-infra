#!/usr/bin/env python3
"""
make_public_repo.py — Assemble a CLEAN, public-safe code repo for PhishVN into ./public/.

Whitelist-only: copies exactly the files a public code release needs and NOTHING else. It never
copies papers/, proposal/, data/raw, data/interim, data/processed or data/private, so manuscripts,
the roadmap, raw data and the id<->PII mapping cannot leak. The dataset itself lives on
Mendeley/Zenodo; the public repo only points at it.

RUN:
  python scripts/make_public_repo.py            # build ./public/  (profile: default)
  python scripts/make_public_repo.py --out /tmp/phishvn-public
  python scripts/make_public_repo.py --profile infra   # build ./public_infra/ (see INFRA_*)

PROFILES. `default` is the URL-corpus mirror; `infra` is a second, independent mirror for the
detection-time infrastructure corpus, with its own whitelist, docs and README. Same flat layout,
and the profiles share the three gates below -- closure, prose, dead link -- so neither can drift
to a weaker check than the other.
"""
from __future__ import annotations
import argparse
import ast
import os
import re
import shutil
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)

COPY_DIRS = ["configs"]                                # safe: config only
# The loop below refuses an entry that does not exist, rather than skipping it. A silent skip
# left the mirror serving dvc.yaml on every refresh after 8944c8a deleted it here: a file the
# published repo had and this one did not.
# CITATION.cff is NOT here: it is version-bound and handled below.
COPY_FILES = ["requirements.txt", "LICENSE", "LICENSE-CODE"]
DOCS_FROM = "data/docs"

# Whitelist test and doc files for public release.
INCLUDE_TESTS = ["test_pipeline.py"]                   # the only suite whose imports are exported
INCLUDE_DOCS = ["datasheet.md", "schema.md", "data_sources.md"]

# Shipped decision documents linked by exported scripts.
DECISION_DOCS = [
    os.path.join("docs", "decisions", "novelty-probe-two-sided.md"),
    os.path.join("docs", "decisions", "guard-control-rank-test.md"),
    os.path.join("docs", "decisions", "vn-filter-aligned-min-token.md"),
]

# Label-audit instruments released with code (key.csv withheld for blinding).
INCLUDE_VERIFY = ["CODEBOOK.md", "annotator_A.csv", "annotator_B.csv", "MACHINE_PASS.csv", "adjudicated.csv"]
VERIFY_FROM = "data/docs/verify"
# Audit artefacts the revised manuscript declares released, as (source, exported name);
# they land in docs/verify/ beside the label-audit instruments.
INCLUDE_AUDITS = [
    ("data/reports/token_audit_sample.csv", "token_audit_sample.csv"),
    ("data/processed/first_seen_validation.csv", "first_seen_validation.csv"),
    ("data/processed/first_seen_validation_summary.json", "first_seen_validation_summary.json"),
    # Fixed snapshot for token audit reproducibility.
    ("data/interim/vn_phishing_candidates_20260812.csv", "feed_snapshot_20260812.csv"),
    # 386 paraphrased attack lures (verified inert, simulated links only, no prompt leak).
    ("data/processed/p3/p3_paraphrase.csv", "p3_paraphrase_lures.csv"),
]

# CITATION.cff tracks the published DOI version.
PUBLISHED_DOI = "10.17632/b97hxbxtpd.4"

# Exported code that names a docs/ path belonging to a DIFFERENT artefact -- not a pointer this
# mirror's reader is meant to follow. Shared by both profiles: see _link_gate, which waives by
# FILE, so a new dead link in one of these still has to be argued for here.
DOC_LINK_WAIVERS = {
    "make_p4b_assets.py": "its file table is the deposit's manifest, listing files that ship there",
    "make_release.py": "same -- it builds the deposits, so its paths are theirs, not this mirror's",
    "make_public_repo.py": "the export policy has to name what each profile ships -- the other"
                           " mirror's README, and the notes both profiles carry",
    "export_p1_results.py": "names the version ledger the deposit carries; neither ships here",
    "make_verification_sample.py": "names docs/verify/key.csv, which is withheld ON PURPOSE (it"
                                   " maps blinded id -> source label); the protocol has to say so",
    "run_p2_temporal_strict.py": "attributes the guard asymmetry to the private audit that"
                                 " measured it -- provenance a reader should see",
    "make_p2_bench_assets.py": "attributes numbers to the private scripts that produced them --"
                               " provenance a reader should see, not a path to follow",
    "analyze_qr_dfr.py": "its error message says where the sweep rows come from, naming the"
                         " collection host's sync wrapper -- provenance for someone holding an"
                         " empty input, not a path this mirror is expected to carry",
}

# Gate regex: catches unintended mentions of unreleased paper numbers/labels in comments/docstrings.
PAPER_LABEL = re.compile(r"\bP[2-8][ab]?\b(?!\w)|papers/P[2-8]|P[2-8]_[a-z]+")

# file -> why its labels are legitimate. A reason is required, and waived labels are still printed
# on every export, so a NEW one appearing in a waived file cannot hide behind the old decision.
PROSE_WAIVERS = {
    "make_public_repo.py": "the export policy has to name which papers are held back",
    "normalize_merge.py": "\"P2 corpus\" is the external benchmark corpus, not the manuscript",
    # make_release.py builds two deposits, and only the infrastructure half carries labels: that
    # article's file table IS the deposit's contract, so build_p4b refuses to run when the two
    # disagree on a row count. It cannot run in the mirror anyway -- it reads papers/
    "make_release.py": "the P4b deposit guard names the article whose file table it checks against",
    # P2 URL-benchmark study scripts.
    "run_p2_benchmark.py": "this IS that study's benchmark driver; the label names what it runs",
    "run_p2_temporal_strict.py": "this IS that study's phishing-temporal protocol",
    "run_p2_stacking_baseline.py": "this IS that study's stacking arm",
    "make_p2_bench_assets.py": "generates that study's tables; the paths it writes name them",
    "audit_label_noise.py": "the label-noise audit that study's decomposition rests on",
    "hpo_gwo.py": "the corrected GWO search; released for reuse, not compared in the paper",
    "run_gwo_temporal.py": "the HPO arm on the temporal window, named by its output path",
    "run_cross_dataset.py": "the transfer matrix of that study; the leakage note points at its "
                            "sibling temporal protocol, which carries the same domain guard",
    "run_p2_charcnn.py": "this IS that study's CharCNN arm",
    "run_p2_hpo.py": "this IS that study's tuning arm; the label names what it tunes",
    "p2_dup_leakage.py": "that study's memorisation check on its own random split",
    "p2_xdata_bootstrap.py": "the bootstrap CIs for that study's transfer matrix",
    "make_p2_shiftmatrix_figure.py": "draws that study's shift matrix; the path it writes names it",
    "audit_xdata_leakage.py": "the domain-disjoint guard that study's transfer diagonal carries",
    "run_combined_training.py": "the pooling baseline of that study; OUT_TEX writes into it",
    "run_ml_label_sensitivity.py": "one script serves the tier-sensitivity table of every ML"
                                   " study, so its docstring has to say which arm is which",
    "p2_generate_corpus.py": "builds that study's simulated corpus; the label names the corpus",
    "p2_corpus_ext.py": "the pre-committed extension of that same corpus",
    # P6 XAI / suffix blind spot study scripts.
    "run_p6_suffix_blindspot.py": "this IS that study's blind-spot measurement",
    "run_p6_vn_deficit.py": "this IS that study's pooled-versus-split deficit",
    "run_p6_vn_reading.py": "this IS that study's off-manifold diagnostic",
    "run_p6_group_threshold.py": "this IS that study's per-group threshold remedy",
    "run_p6_prospective_ablation.py": "this IS that study's locked forward holdout",
    "run_p6_protocol_shap.py": "this IS that study's attribution contrast across protocols",
    "run_p6_attribution_drift.py": "this IS that study's re-seeding band",
    "run_p6_charcnn_strata.py": "this IS that study's representation-change replication",
    "run_p6_budget_frontier.py": "this IS that study's reweighting frontier",
    "run_p6_case_studies.py": "this IS that study's worked cases",
    "make_p6_xai_assets.py": "generates that study's tables; the paths it writes name them",
    # P3 multimodal study scripts.
    "make_p3_assets.py": "this IS that study's asset generator",
    "make_p3_band_assets.py": "this IS that study's paraphrase-strength band",
    "make_p3_cross_generator_eval.py": "this IS that study's cross-generator evaluation",
    "make_p3_dose_response.py": "this IS that study's dose-response curve",
    "make_p3_llm_assets.py": "this IS that study's LLM arm",
    "make_p3_llm_detector_assets.py": "this IS that study's LLM-detector comparison",
    "make_p3_paraphrase_assets.py": "this IS that study's paraphrase tables",
    "make_p3_scenario_ood.py": "this IS that study's out-of-scenario split",
    "p3_paraphrase_band.py": "band construction shared by that study's generators",
    "p3_jaccard_check.py": "that study's lexical-overlap audit of its own paraphrases",
    "p3_nuisance_floor.py": "that study's nuisance floor",
    "p3_xdata_bootstrap.py": "that study's cluster bootstrap; it also names the benchmark whose "
                             "transfer matrix it resamples, which is already exported",
    "p3_gemini_generator.py": "this IS that study's paraphrase generator, which is the protocol",
    "p3_paraphrase_corpus.py": "this IS that study's corpus builder",
    "p3_paraphrase_ext.py": "this IS that study's extension round",
    "p3_paired_test.py": "the paired test behind that study's contrasts",
}

# Only scripts that build/reproduce the RELEASED P1a URL dataset and baselines; those for
# unreleased channels and papers stay private until those are released. Entries are
# role-subfolder paths in THIS repo -- the mirror stays FLAT, and the uniform bootstrap
# headers fall back via ImportError in that layout
INCLUDE_SCRIPTS = [
    "core/collect/scrape_vn_phishing.py",     # collect phishing URLs (NCSC blacklist + feeds)
    "core/collect/scrape_trusted_orgs.py",    # collect benign trusted-org URLs
    "core/collect/fetch_tranco.py",           # hard benign negatives (Tranco)
    "core/collect/fetch_urlscan.py",          # preliminary HTML/screenshot subset
    "core/collect/whois_dns_enrich.py",       # optional URL/host enrichment
    "core/dataset/normalize_merge.py",        # build the unified URL dataset + group-aware temporal split
    "core/lib/compphish_features.py",         # CompPhish-aligned URL feature schema
    "core/dataset/align_compphish.py",        # re-featurise URLs into the CompPhish schema
    "core/baselines/train_url_baseline.py",       # URL baselines (multi-seed + bootstrap CI)
    "studies/p1_dataset/make_verification_sample.py", # label-quality audit (Cohen's kappa)
    "core/collect/watch_chongluadao.py",      # the live ChongLuaDao watcher feeding the corpus
    "core/collect/fetch_phishing_feeds.py",   # the feed importer test_pipeline.py exercises
    "core/lib/psl.py",                        # PSL domain folding shared by collection and evaluation
    "core/lib/vn_filter.py",                  # is-this-VN-targeting test used across collection
    "core/dataset/build_brand_tokens.py",     # registry-derived brand tokens the filter matches on
    "studies/p1_dataset/make_p1_assets.py",         # regenerate the paper's figure + tables from data
    "core/collect/fetch_chongluadao.py",      # import the ChongLuaDao mirror snapshot (named in the paper)
    "core/dataset/chongluadao_first_seen.py", # reconstruct per-domain first-seen dates (named in the paper)
    "studies/p1_dataset/validate_first_seen.py",      # accuracy estimate for the reconstructed dates (rev. #1)
    "studies/p1_dataset/audit_token_filter.py",       # sampled audit of the VN-targeting token filter (rev. #1)
    "studies/p1_dataset/export_p1_results.py",      # the deposited benchmark-evidence bundle's generator
    "core/dataset/derive_abuse_type.py",      # types the positive class; its output ships in the open tier
    "studies/p1_dataset/collect_audit_evidence.py",   # gathers the lookup evidence the released audit sheets need
    "studies/p1_dataset/machine_pass_composition.py", # the archive-content pass, and the control showing it fails
    "core/release/make_release.py",           # package the citable open/gated release
    "core/release/make_public_repo.py",       # this exporter
    "core/lib/genfile.py",                    # atomic writer every asset generator goes through
    "core/lib/figstyle.py",                   # house palette + rcParams (and it installs the axis guard)
    "core/lib/axguard.py",                    # refuses to write a figure that clips its own data
    # P2 (URL benchmark) — the conclusion promises the code behind every table
    "studies/p2_url_benchmark/run_p2_benchmark.py",         # 7-family benchmark under the bundled protocols
    "studies/p2_url_benchmark/run_p2_temporal_strict.py",   # the phishing-temporal protocol (+ rolling origins)
    "studies/p2_url_benchmark/run_p2_stacking_baseline.py", # stacked ensembles / base-learner combos
    "studies/p2_url_benchmark/run_p2_drift_forecastability.py",  # the three forecastability diagnostics
    "studies/p3_multimodal/run_cross_dataset.py",        # 4-corpus transfer matrix
    "studies/p2_url_benchmark/hpo_gwo.py",                  # corrected GWO; no comparison is reported
    "studies/p3_multimodal/run_gwo_temporal.py",         # the HPO arm on the temporal window
    "studies/p2_url_benchmark/audit_label_noise.py",        # confident-learning label-noise audit
    "core/lib/paired_eval.py",                # NB-corrected paired t-test + BH (all significance)
    "studies/p2_url_benchmark/run_p2_charcnn.py",           # CharCNN arm
    "studies/p2_url_benchmark/make_p2_bench_assets.py",    # regenerates every P2 table/figure/verdict macro
    "studies/p2_url_benchmark/make_p2_shiftmatrix_figure.py",  # the shift matrix drawn against time (its figure)
    "studies/p2_url_benchmark/run_p2_hpo.py",               # the tuning arm behind the HPO table
    "studies/p2_url_benchmark/run_p2_fcts.py",              # E5/D4: forward-chained meta-learning control
    "studies/p2_url_benchmark/run_p2_residual_lambda.py",   # E4: residual-backbone sensitivity (prereg arm)
    "studies/p2_url_benchmark/run_p2_source_probe.py",      # the benign-source swap the CharCNN margin is checked against
    "studies/p2_url_benchmark/p2_dup_leakage.py",           # how much of the random split is memorisable (the 81% twins)
    "studies/p2_url_benchmark/p2_xdata_bootstrap.py",       # bootstrap CIs for the transfer-matrix cells
    "studies/p2_url_benchmark/audit_xdata_leakage.py",      # the domain-disjoint guard on the transfer diagonal
    "studies/p3_multimodal/run_combined_training.py",       # pooling three corpora: the "just add corpora" baseline
    "studies/p3_multimodal/run_ml_label_sensitivity.py",   # the tier/noise sensitivity tables three papers print
    "studies/p3_multimodal/p2_generate_corpus.py",         # the simulated lure corpus the evasion numbers were measured on
    "studies/p3_multimodal/p2_corpus_ext.py",              # its pre-committed extension
    # P6 (XAI / suffix blind spot)
    "studies/p6_xai/run_p6_suffix_blindspot.py",  # the blind-spot measurement the abstract opens with
    "studies/p6_xai/run_p6_vn_deficit.py",        # the pooled-vs-split .vn deficit
    "studies/p6_xai/run_p6_vn_reading.py",        # the off-manifold diagnostic on tld_len
    "studies/p6_xai/run_p6_group_threshold.py",   # the per-group threshold remedy (0.906 -> 0.177)
    "studies/p6_xai/run_p6_prospective_ablation.py",  # locked forward holdout + the no-tld_len refit
    "studies/p6_xai/run_p6_protocol_shap.py",     # SHAP under both protocols (the rho = 0.968 claim)
    "studies/p6_xai/run_p6_attribution_drift.py", # the re-seeding band that rho is compared against
    "studies/p6_xai/run_p6_charcnn_strata.py",    # the deployment-stack replication
    "studies/p6_xai/run_p6_budget_frontier.py",   # eight-cell reweighting / budget frontier
    "studies/p6_xai/run_p6_case_studies.py",      # the worked cases behind the .id finding
    "studies/p6_xai/make_p6_xai_assets.py",      # regenerates every P6 table, figure and verdict macro
    # QR / quishing benchmark
    "studies/future_quishing/gen_synthetic_qr.py",       # the controlled render generator the benchmark runs on
    "studies/future_quishing/analyze_qr_dfr.py",           # the decode-failure-rate analysis and its two registered tests
    "studies/future_quishing/qr_prevalence.py",            # the landing-page prevalence audit
    "studies/future_quishing/qr_scan.py",                # the scanner behind the landing-page audit
    "studies/future_quishing/qr_submit.py",              # the submission side of that audit
    "studies/future_quishing/backfill_qr_examined.py",     # reconciles the pages-examined denominator
    "studies/future_quishing/make_qr_visual_assets.py",   # regenerates the paper's QR figures and tables
    "studies/future_quishing/benchmark_qr.py",             # the sweep itself; the generator drives it
    "core/lib/qr_decode.py",                  # the three-decoder wrapper every arm reads through
    "core/lib/emvco.py",                      # EMVCo payment-QR parsing used by the landing-page audit
    # P3 (content + URL fusion)
    "studies/p3_multimodal/make_p3_assets.py",          # regenerates the paper's tables and figures
    "studies/p3_multimodal/make_p3_band_assets.py",     # the paraphrase-strength band
    "studies/p3_multimodal/make_p3_cross_generator_eval.py",  # the cross-generator transfer evaluation
    "studies/p3_multimodal/make_p3_dose_response.py",   # the dose-response curve and its notes
    "studies/p3_multimodal/make_p3_llm_assets.py",      # the LLM arm's tables
    "studies/p3_multimodal/make_p3_llm_detector_assets.py",   # the LLM-detector comparison
    "studies/p3_multimodal/make_p3_paraphrase_assets.py",     # the paraphrase attack's tables
    "studies/p3_multimodal/make_p3_scenario_ood.py",    # the out-of-scenario split
    "studies/p3_multimodal/p3_paraphrase_band.py",      # band construction shared by those generators
    "studies/p3_multimodal/p3_jaccard_check.py",         # lexical-overlap audit of the paraphrases
    "studies/p3_multimodal/p3_nuisance_floor.py",        # the nuisance floor the effect is measured against
    "studies/p3_multimodal/p3_xdata_bootstrap.py",       # cluster bootstrap for the cross-dataset arm
    "studies/p3_multimodal/p3_gemini_generator.py",    # the paraphrase generator (the protocol itself)
    "studies/p3_multimodal/p3_paraphrase_corpus.py",   # builds the paraphrase corpus and its lure sets
    "studies/p3_multimodal/p3_paraphrase_ext.py",      # the extension round
    "studies/p3_multimodal/p3_paired_test.py",           # the paired test behind every reported contrast
    "studies/p3_multimodal/train_content_fusion.py",     # the training code the availability sentence names
    "studies/p3_multimodal/train_fusion.py",             # the fusion head every asset generator imports
    "core/baselines/train_html_baseline.py",      # the HTML channel
    "core/baselines/train_image_baseline.py",     # the screenshot channel
    "core/lib/extract_js_features.py",        # the JS features the content model reads
    "studies/p3_multimodal/llm_content_baseline.py",     # the LLM baseline that study reports beside the encoders
    "core/baselines/convert_phobert_safetensors.py",  # the checkpoint conversion the training code needs
]

# ----------------------------------------------------------------------------------------
# PROFILE `infra`: the detection-time infrastructure corpus (phishvn-infra). Whitelist-only,
# flat, same gates. Read ONLY under --profile infra; the constants above are untouched
INFRA_OUT = "public_infra"
INFRA_COPY_FILES = ["requirements.txt", "LICENSE", "LICENSE-CODE"]
INFRA_DOCS_FROM = "data/docs/infra"
# (source name, exported path). README and CITATION take the repo-root names on export.
INFRA_DOCS = [
    ("README_infra.md", "README.md"),
    ("CITATION_infra.cff", "CITATION.cff"),
    ("collection_protocol.md", os.path.join("docs", "collection_protocol.md")),
    ("schema_infra.md", os.path.join("docs", "schema.md")),
]
# Rationale that used to sit inline in the collectors. Moving it to docs/decisions/ left the
# exported wrappers pointing at files the mirror did not carry -- a cloner following one out
# of ct_benign_run.sh found nothing. Sourced from the repo root, and held to the same
# no-waiver rule as the hand-written docs, which is why neither names a paper any more
INFRA_DECISION_DOCS = [
    os.path.join("docs", "decisions", "ct-benign-age-rotation.md"),
    os.path.join("docs", "decisions", "vn-filter-aligned-min-token.md"),
]

# The scripts the data article names, plus their import closure (the closure gate is the
# arbiter: add here only what it reports dangling). Flat on export, like the default profile.
INFRA_SCRIPTS = [
    "studies/p4_infra/watch_host_infra.py",      # the infrastructure watcher (DNS/WHOIS/TLS at detection time)
    "studies/p4_infra/watch_ct_benign.py",       # CT-sampled, age-matched benign arm (+ --stratum vn)
    "core/collect/watch_urlscan_brands.py",  # brand-token urlscan feed (the live phishing channel)
    "core/collect/watch_chongluadao.py",     # capture helpers watch_urlscan_brands imports
    "studies/p4_infra/audit_p4_labels.py",         # the label gate + registry-wildcard probe
    "studies/p4_infra/make_p4_assets.py",         # candidate population + T1, behind the trusted-label lock
    "studies/p4_infra/make_p4_funnel.py",         # funnel + accrual tables/figure
    "studies/p4_infra/make_p4b_assets.py",        # the data article's generated tables/figures
    "core/lib/psl.py",                       # vendored from the URL-corpus repo (source of truth there)
    "core/lib/vn_filter.py",                 # vendored: VN-targeting test + brand tokens
    "core/lib/genfile.py",                   # atomic writer
    "core/lib/figstyle.py",                  # house palette (installs the axis guard)
    "core/lib/axguard.py",                   # refuses to write a figure that clips its data
    "core/lib/paired_eval.py",               # wilson() used by build_population's tables
    "core/lib/compphish_features.py",        # lexical channel make_p4_assets imports at module load
    "core/lib/p4_outcome_gate.py",           # shared fail-closed unlock for every P4 outcome path
    "studies/p4_infra/make_p4_perishability.py", # capture perishability (live vs backfill resolvability)
    "studies/p4_infra/audit_infra_capture.py",     # its helper: the WHOIS-by-policy artefact, measured
    "core/release/make_public_repo.py",      # this exporter
]
# Cron wrappers shipped under scripts/ops/ with paths rewritten for the flat layout.
INFRA_OPS = ["host_infra_run.sh", "ct_benign_run.sh", "ct_benign_vn_run.sh",
             "urlscan_brands_run.sh", "rowcount_snapshot.sh",
             # Health monitor
             "jetson_health.sh"]
INFRA_TESTS: list[str] = []
# Whitelist reasons for unreleased study mentions in infra profile code.
INFRA_PROSE_WAIVERS = {
    "watch_host_infra.py": "one comment names the study whose benign arm the source map serves",
    "watch_ct_benign.py": "this IS that study's matched benign arm; its docstring names the design",
    "audit_p4_labels.py": "this IS that study's label gate; the label names what it audits",
    "make_p4_assets.py": "this IS that study's population builder; paths it writes name it",
    "make_p4_funnel.py": "names the paper folder its figure is written into",
    "make_p4b_assets.py": "names the data article's own paper folder (its output path)",
    "make_public_repo.py": "the export policy has to name which papers are held back",
    "ct_benign_run.sh": "the cadence clause names the data article whose 'four-hourly' the claims suite matches this comment against",
    "audit_infra_capture.py": "this IS that study's capture audit; it names the design it constrains",
    "make_p4_perishability.py": "names the paper folder its table is written into",
    "urlscan_brands_run.sh": "the wrapper comment names the study its feed serves",
    "rowcount_snapshot.sh": "the comment names the arm whose back-dated stamps it exists for",
    "ct_benign_vn_run.sh": "names the pre-specification amendment that created the stratum",
}
INFRA_DOC_FORBIDDEN = re.compile(r"\bcompanion\b", re.I)

INFRA_MAKEFILE = """.PHONY: install infra benign benign-vn audit population assets clean
install:      ## install python deps
\tpip install -r requirements.txt
infra:        ## one tick of the infrastructure watcher (tails data/raw/*/detections.csv)
\tpython scripts/watch_host_infra.py
benign:       ## one tick of the CT-sampled benign arm (3-day target age)
\tpython scripts/watch_ct_benign.py --age-days 3 --batches 4
benign-vn:    ## one tick of the .vn supplement
\tpython scripts/watch_ct_benign.py --stratum vn --age-days 3 --target 10 --max-entries 20000
audit:        ## label gate over the live-stratum phishing arm
\tpython scripts/audit_p4_labels.py --live
population:   ## funnel + conditioned population (refuses to fit models below the registered trigger)
\tpython scripts/make_p4_assets.py
assets:       ## the data article's tables and figures
\tpython scripts/make_p4_funnel.py && python scripts/make_p4b_assets.py
clean:
\trm -rf data/processed/p4/p4_*.csv
"""

INFRA_DATA_README = """# Data

The corpus is **not stored in this Git repository**. Version 1.0.0 will be archived on Mendeley
Data under CC BY 4.0 (DOI pending; see `README.md`, "Deposit").

The collectors write to `data/raw/<source>/` relative to the repository root; the population
build reads `data/raw/host_infra/host_infra.csv` and writes `data/processed/`. To reproduce the
deposit's derived tables, place the deposited `host_infra.csv` at `data/raw/host_infra/` and run
`make population`.
"""

PUBLIC_GITIGNORE = """# never commit data or private material to the public repo
data/raw/
data/interim/
data/processed/
data/private/
!data/**/.gitkeep
# models / tracking / build artefacts
models/
mlruns/
release/
__pycache__/
*.pyc
.pytest_cache/
.DS_Store
.idea/
"""

DATA_README = """# Data

The PhishVN **dataset is not stored in this Git repository**. It is archived with a DOI:

- Open tier (URL table, features, labels, splits, docs) — CC BY 4.0 — Mendeley Data,
  DOI: [`{doi}`](https://doi.org/{doi}).
- Captured phishing HTML/screenshots — research-only **gated** tier, on request.

To reproduce the baselines, download the open tier and place `dataset_url.csv` (and the `splits/`)
under `data/processed/`, then run `make url`.
"""

README = """# PhishVN — Vietnamese URL Phishing Dataset & Baselines

Code and documentation for **PhishVN**, an open, time-stamped Vietnamese URL phishing dataset
(53,116 URLs: an 18,997-record verified core of 2,587 phishing / 16,410 legitimate, plus a
34,119-record community/feed bronze expansion) with a CompPhish-aligned 21-feature lexical
schema, impersonation-scenario labels, gold/silver/bronze confidence tiers, and a group-aware
temporal split.

> **Dataset (with DOI):** Mendeley Data [`{doi}`](https://doi.org/{doi}) — CC BY 4.0.
> This repository holds the **code** (MIT); the **data** is archived separately at the DOI above.

## What's here
- `scripts/` — URL data collection, normalisation, CompPhish features, baselines, audit, release tools.
- `docs/` — datasheet, column schema, data-source notes.
- `docs/verify/` — the completed human label audit: time-stamped pre-specified codebook (with its amendment
  log), both annotators' independent sheets, the machine pass, and the arbitration record.
- `tests/`, `configs/`, `Makefile` — reproducibility.

## Label audit (completed 2026-08-15)
Two annotators independently re-checked a blinded, stratified 200-row sample against a four-way
codebook (credential *phishing* / other *scam* / *legitimate* / *unsure*) that forbids consulting
any blocklist and treats plausibility as non-evidence. Independent-round agreement: 0.710
(Cohen's κ 0.609) four-way; 0.820 (κ 0.725) collapsed to the abuse-vs-legitimate distinction the
released binary label makes. After documented arbitration of the 58 disagreements, 149/200 rows
resolve; against the source labels the positive arm shows **12.1% label noise** (95% CI
7.1–20.0%, concentrated in the explicitly-tagged bronze stratum) and the benign arm 4.0%.
Every number is recomputable from `docs/verify/` via `make_verification_sample.py score`; the
full record is in `docs/datasheet.md`.

## Quickstart
```bash
pip install -r requirements.txt
# download the dataset from the Mendeley DOI into data/processed/ , then:
make url          # train the URL baseline (LogReg/RF, multi-seed + bootstrap CI)
make test         # unit tests
```

## Key scripts
- `normalize_merge.py` — merge raw sources -> common schema, scheme-independent URL features,
  scenario inference, group-aware temporal split.
- `compphish_features.py` / `align_compphish.py` — CompPhish 21-feature schema (cross-dataset).
- `train_url_baseline.py` — URL baseline; `--seeds` (mean±std) and `--bootstrap` (95% CI).
- `fetch_tranco.py` — hard benign negatives from the Tranco top-list.
- `make_verification_sample.py` — two-annotator label audit + Cohen's kappa.
- `machine_pass_composition.py` — rule-based pass over the archived page behind each sampled
  domain. It reports a negative result and `docs/verify/MACHINE_PASS.csv` is that result: the
  sample's known-legitimate stratum acts as a control, the credential rule fires on it as often as
  on listed domains (13.9% vs 12.5%, Fisher p = 1.00), and only 17% of listed rows resolve at all.
  Read it as evidence that this corpus cannot be adjudicated from web archives — not as a
  composition estimate, and never as a substitute for the human audit.
- `make_release.py` — build the citable open / gated release bundles.

## Multi-protocol URL benchmark
Seven tabular families plus a character-CNN, evaluated under a full-corpus random split, a
phishing-temporal split on dated detections, and a four-corpus transfer matrix. `make benchmark`
runs the three drivers; the remaining arms take their own flags.
- `run_p2_benchmark.py` / `run_p2_temporal_strict.py` — the random and phishing-temporal
  protocols; the temporal one carries the registrable-domain guard and the rolling origins.
- `run_cross_dataset.py` — the four-corpus transfer matrix; `--drop` prunes the SHAP-named
  artefact features and `--adapt coral` aligns second-order statistics to the unlabelled target.
- `run_combined_training.py` — pooling three corpora against the held-out fourth.
- `run_p2_stacking_baseline.py`, `run_p2_hpo.py`, `run_p2_charcnn.py`, `run_p2_fcts.py`,
  `run_p2_residual_lambda.py`, `run_p2_drift_forecastability.py` — the ensemble, tuning,
  string-reading, meta-learning and forecastability arms.
- `audit_label_noise.py`, `audit_xdata_leakage.py`, `p2_dup_leakage.py`,
  `p2_xdata_bootstrap.py`, `run_p2_source_probe.py` — the audits: confident-learning label
  noise, the domain-disjoint guard on the transfer diagonal, how much of the random split is
  memorisable, bootstrap CIs, and the benign-source swap.
- `run_ml_label_sensitivity.py` — recall by provenance tier, the sensitivity analysis that
  answers the corpus audit's 12.1% positive-label error rate. One script serves several
  studies; run `--papers p2` for this one.
- `make_p2_bench_assets.py`, `make_p2_shiftmatrix_figure.py` — the table and figure generators.
  They write LaTeX into a manuscript tree that is not part of this repository; they ship so the
  path from a stored result to a printed number is inspectable.

## Citation
See `CITATION.cff`. Please cite the dataset DOI and credit the upstream sources
(NCSC "Tin Nhiem Mang" and the Tranco list).

## Licence
Code: MIT (`LICENSE-CODE`). Dataset: CC BY 4.0 (`LICENSE`).
"""

MAKEFILE = """.PHONY: install data url benchmark assets release verify clean
install:      ## install python deps
\tpip install -r requirements.txt
data:         ## build the URL dataset from data/raw
\tpython scripts/normalize_merge.py --raw data/raw --out data/processed
url:          ## train URL baselines (multi-seed + bootstrap CI)
\tpython scripts/train_url_baseline.py --in data/processed/dataset_url.csv --out models/url_rf.joblib
benchmark:    ## multi-protocol URL benchmark: both protocols, then the cross-corpus matrix
\tpython scripts/run_p2_benchmark.py
\tpython scripts/run_p2_temporal_strict.py
\tpython scripts/run_cross_dataset.py
assets:       ## regenerate the paper figure + tables from data
\tpython scripts/make_p1_assets.py
release:      ## package the citable open-tier release (PAGES=1 for the gated bundle)
\tpython scripts/make_release.py --version $(or $(VERSION),1.0.0) $(if $(PAGES),--include-pages,)
verify:       ## run unit tests
\tpytest -q
clean:
\trm -rf models data/processed/*.csv data/processed/splits/*.csv
"""


def _prose(path: str) -> str:
    """Extract comments and docstrings from a Python source file."""
    src = open(path, encoding="utf-8").read()
    out = [m.group(1) for m in re.finditer(r"^\s*#\s?(.*)$", src, re.M)]
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return "\n".join(out)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node)
            if doc:
                out.append(doc)
    return "\n".join(out)


def _flatten_sh(src: str) -> str:
    """Rewrite script subfolder paths to the flattened mirror layout."""
    src = re.sub(r"scripts/ops/", "scripts/ops/", src)
    src = re.sub(r'\(dirname "\$0"\)/\.\./\.\./\.\.', r'(dirname "$0")/../..', src)
    return re.sub(r"scripts/(?:core|studies|collect|audit|assets|lib|dataset|train|release)(?:/[a-zA-Z0-9_]+)*/", "scripts/", src)


def _drop_unshipped_doc_links(src: str, shipped: set[str]) -> str:
    """Rewrite doc pointers to design notes not shipped in the public mirror."""
    def sub(m):
        return m.group(0) if os.path.basename(m.group(0)) in shipped else \
            "kept in the development repository, not shipped in this mirror"
    return re.sub(r"docs/(?:design-notes|decisions)/[\w.-]+\.md", sub, src)



def _sh_prose(path: str) -> str:
    src = open(path, encoding="utf-8").read()
    return "\n".join(m.group(1) for m in re.finditer(r"^\s*#\s?(.*)$", src, re.M))


def _closure_gate(out: str, private: set[str], files: list[tuple[str, str]]) -> None:
    """An exported file may not import a non-exported script -- otherwise the export succeeds
    but the mirror cannot run, and only a cloner (a reviewer) finds out. Nested imports count."""
    dangling = []
    for sub, fn in files:
        p = os.path.join(out, sub, fn)
        if not os.path.exists(p):
            continue
        src = open(p, encoding="utf-8").read()
        for m in re.findall(r"^\s*(?:from|import)\s+([a-z_][a-z0-9_]*)", src, re.M):
            if m in private:
                dangling.append(f"{sub}/{fn} -> {m}")
    if dangling:
        raise SystemExit("SAFETY: exported file imports a non-exported script: "
                         + ", ".join(sorted(set(dangling))))


def _row_gate(out: str, ops: list[str], protocol_rel: str) -> None:
    """An exported ops script may only name collectors the deposit's own protocol describes.

    jetson_health.sh carries one row per collector, `name|log|data|period`, and rows accumulate as
    the host gains collectors -- including collectors belonging to studies this deposit says
    nothing about. Such a row is invisible to the other gates: it is not an import, not a paper
    label, and the paths it names are data files rather than in-repo scripts, so the closure,
    prose and link gates all pass it. What a cloner sees is a collector named nowhere else in the
    mirror, pointing at a log and a CSV nothing here produces. Rows for those live in a side file
    that is not exported (see jetson_health.rows.local), which is what this gate enforces."""
    proto = os.path.join(out, protocol_rel)
    if not os.path.exists(proto):
        raise SystemExit(f"SAFETY: {protocol_rel} missing; cannot check exported collector rows")
    described = open(proto, encoding="utf-8").read()
    undocumented = []
    for fn in ops:
        p = os.path.join(out, "scripts", "ops", fn)
        if not os.path.exists(p):
            continue
        for m in re.finditer(r'^\s*"([a-z0-9_]+)\|[^"]*\|[^"]*\|\d+"',
                             open(p, encoding="utf-8").read(), re.M):
            if m.group(1) not in described:
                undocumented.append(f"scripts/ops/{fn}: {m.group(1)}")
    if undocumented:
        raise SystemExit("SAFETY: exported ops script names a collector the deposit does not "
                         f"describe in {protocol_rel}:\n  " + "\n  ".join(sorted(set(undocumented)))
                         + "\n  Move the row to scripts/ops/jetson_health.rows.local (not exported), "
                           "or document the collector in the protocol.")


def _link_gate(out: str, waivers: dict[str, str]) -> None:
    """Every in-repo path the export names must resolve inside the mirror -- code pointing at a
    document and a document pointing back at code. A reference in prose is not an import, so
    neither of the other gates sees one: the closure gate reads imports, the prose gate reads
    paper names. Both directions have broken -- code kept pointers to notes that were not
    exported, and notes named scripts/<role>/x.py, which is not where a flat mirror puts them.

    Waived BY FILE, not by path: a file whose docs/ paths belong to a different artefact (a
    deposit manifest, the other profile's README) argues its case once, and a NEW dead link in it
    still has to be argued for. Waived links print on every export, like the prose ones."""
    LINK = re.compile(r"(?:docs|scripts)/[\w./-]+\.(?:md|csv|json|py|sh)")
    dangling: list[str] = []
    waived: set[str] = set()
    for top in ("scripts", "docs"):
        for dp, _, fns in os.walk(os.path.join(out, top)):
            for fn in fns:
                fp = os.path.join(dp, fn)
                try:
                    text = open(fp, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                why = waivers.get(fn)
                for m in LINK.finditer(text):
                    if os.path.exists(os.path.join(out, m.group(0))):
                        continue
                    if why:
                        waived.add(f"{fn} names {m.group(0)} — {why}")
                    else:
                        dangling.append(f"{os.path.relpath(fp, out)} -> {m.group(0)}")
    if dangling:
        raise SystemExit("SAFETY: exported code points at docs the mirror does not carry:\n  "
                         + "\n  ".join(sorted(set(dangling)))
                         + "\n  Export the file, or stop naming it.")
    for w in sorted(waived):
        print(f"[waived] {w}")


def _prose_gate(out: str, files: list[tuple[str, str]], waivers: dict[str, str]) -> None:
    """No exported comment or docstring may attribute anything to an unreleased paper. See
    PAPER_LABEL for what this does and does not buy. .sh files contribute their comments."""
    leaks = []
    for sub, fn in files:
        p = os.path.join(out, sub, fn)
        if not os.path.exists(p):
            continue
        text = _sh_prose(p) if fn.endswith(".sh") else _prose(p)
        labels = sorted({m.group(0) for m in PAPER_LABEL.finditer(text)})
        if not labels:
            continue
        why = waivers.get(fn)
        if why:
            print(f"[waived] {sub}/{fn} names {', '.join(labels)} — {why}")
        else:
            leaks.append(f"{sub}/{fn}: {', '.join(labels)}")
    if leaks:
        raise SystemExit(
            "SAFETY: exported prose attributes something to an unreleased paper:\n  "
            + "\n  ".join(leaks)
            + "\n  Describe the mechanism without the attribution, or add a PROSE_WAIVERS entry"
              " saying why the mention is legitimate.")


def _private_scripts(exported: set[str]) -> set[str]:
    private = set()
    for dp, dns, fns in os.walk("scripts"):
        dns[:] = [d for d in dns if d not in ("__pycache__", "hooks")]
        private |= {f[:-3] for f in fns if f.endswith(".py") and f not in exported}
    return private


def _clean_out(out: str) -> None:
    """Clean existing contents but PRESERVE .git (so the repo/remote survives a re-export). Then
    `git add -A` in the export picks up removals, dropping stale files from the tracked repo."""
    if os.path.exists(out):
        for entry in os.listdir(out):
            if entry == ".git":
                continue
            p = os.path.join(out, entry)
            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    else:
        os.makedirs(out)


def _count_files(out: str) -> int:
    """Skips .git: counting the mirror's object database made the "files" figure move with every
    commit there (272 -> 282 across one commit) as if the export had grown."""
    n = 0
    for dp, dns, fs in os.walk(out):
        dns[:] = [d for d in dns if d != ".git"]
        n += len(fs)
    return n


def build_infra(out: str) -> None:
    """Assemble the phishvn-infra mirror. Same discipline as the default profile: whitelist only,
    flat scripts/, no data payloads, no papers, no pre-specification, no .env; both gates."""
    _clean_out(out)
    for f in INFRA_COPY_FILES:
        if os.path.exists(f):
            shutil.copy2(f, os.path.join(out, f))

    os.makedirs(os.path.join(out, "scripts", "ops"), exist_ok=True)
    for s in INFRA_SCRIPTS:
        src = os.path.join("scripts", s)
        if os.path.exists(src):
            # flattened like the wrappers, and for the same reason: every RUN: line in these headers reads
            # `python scripts/<role>/x.py`, a path this mirror does not have. The rewrite only touches the
            # role directory, and every occurrence here is text a person reads -- a docstring example, a
            # comment, a command to run -- never a path opened at run time
            dst = os.path.join(out, "scripts", os.path.basename(s))
            open(dst, "w", encoding="utf-8").write(
                _flatten_sh(open(src, encoding="utf-8").read()))
            shutil.copymode(src, dst)
    for sh in INFRA_OPS:
        src = os.path.join("scripts", "core", "ops", sh)
        if os.path.exists(src):
            txt = _flatten_sh(open(src, encoding="utf-8").read())
            dst = os.path.join(out, "scripts", "ops", sh)
            open(dst, "w", encoding="utf-8").write(txt)
            shutil.copymode(src, dst)
    with open(os.path.join(out, "Makefile"), "w", encoding="utf-8") as f:
        f.write(INFRA_MAKEFILE)

    os.makedirs(os.path.join(out, "docs"), exist_ok=True)
    missing = []
    for src_name, dst_rel in INFRA_DOCS:
        src = os.path.join(INFRA_DOCS_FROM, src_name)
        if os.path.exists(src):
            dst = os.path.join(out, dst_rel)
            open(dst, "w", encoding="utf-8").write(_flatten_sh(open(src, encoding="utf-8").read()))
        else:
            missing.append(src)
    if missing:
        raise SystemExit("SAFETY: infra docs missing (the README/citation are hand-written, not "
                         "generated): " + ", ".join(missing))

    os.makedirs(os.path.join(out, "docs", "decisions"), exist_ok=True)
    for rel in INFRA_DECISION_DOCS:
        if not os.path.exists(rel):
            raise SystemExit(f"SAFETY: an exported wrapper points at {rel}, which is missing here")
        # these notes open with "Applies to: scripts/<role>/x.py", and the mirror is flat
        dst = os.path.join(out, rel)
        open(dst, "w", encoding="utf-8").write(
            _flatten_sh(open(rel, encoding="utf-8").read()))
        shutil.copymode(rel, dst)

    os.makedirs(os.path.join(out, "data"), exist_ok=True)
    with open(os.path.join(out, "data", "README.md"), "w", encoding="utf-8") as f:
        f.write(INFRA_DATA_README)
    with open(os.path.join(out, ".gitignore"), "w", encoding="utf-8") as f:
        f.write(PUBLIC_GITIGNORE)

    # safety assertion: nothing forbidden slipped in -- the default profile's classes, plus the
    # secrets file, anything named like a pre-specification, and any payload under data/.
    leaked = []
    for dp, dns, fns in os.walk(out):
        dns[:] = [d for d in dns if d != ".git"]
        for fn in fns:
            p = os.path.relpath(os.path.join(dp, fn), out)
            parts = p.split(os.sep)
            if any(seg in parts for seg in ("papers", "proposal")) \
               or fn.startswith(".env") or "PREREG" in fn.upper() or fn == "key.csv" \
               or (parts[0] == "data" and len(parts) > 2):
                leaked.append(p)
    if leaked:
        raise SystemExit("SAFETY: forbidden files present: " + ", ".join(sorted(set(leaked))))

    exported = {os.path.basename(s) for s in INFRA_SCRIPTS}
    files = [("scripts", fn) for fn in sorted(exported)] + [("tests", t) for t in INFRA_TESTS]
    # _path is the layout bootstrap every header imports inside try/except ImportError; the
    # fallback IS the flat-mirror design, so that import is dangling on purpose.
    _closure_gate(out, _private_scripts(exported) - {"_path"}, files)
    _prose_gate(out, files + [(os.path.join("scripts", "ops"), sh) for sh in INFRA_OPS],
                INFRA_PROSE_WAIVERS)

    # the hand-written docs get no waiver: no paper label, no "companion"
    bad = []
    for dst_rel in [d for _, d in INFRA_DOCS] + INFRA_DECISION_DOCS:
        text = open(os.path.join(out, dst_rel), encoding="utf-8").read()
        hits = sorted({m.group(0) for m in PAPER_LABEL.finditer(text)}
                      | {m.group(0) for m in INFRA_DOC_FORBIDDEN.finditer(text)})
        if hits:
            bad.append(f"{dst_rel}: {', '.join(hits)}")
    if bad:
        raise SystemExit("SAFETY: infra docs name a paper or call it a companion:\n  "
                         + "\n  ".join(bad))

    _row_gate(out, INFRA_OPS, os.path.join("docs", "collection_protocol.md"))
    _link_gate(out, DOC_LINK_WAIVERS)

    print(f"[+] public_infra repo assembled at {out}  ({_count_files(out)} files)")
    print("    excluded: papers/, PREREG, scripts/.env*, data/ payloads")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=["default", "infra"], default="default")
    ap.add_argument("--out", default=None,
                    help="build dir (default: ./public for the default profile, ./public_infra for infra)")
    args = ap.parse_args()
    os.chdir(ROOT)
    if args.profile == "infra":
        build_infra(os.path.abspath(args.out or os.path.join(ROOT, INFRA_OUT)))
        return
    args.out = args.out or os.path.join(ROOT, "public")

    prev_cff = ""                                  # survives the clean; see PUBLISHED_DOI
    if os.path.exists(p := os.path.join(args.out, "CITATION.cff")):
        prev_cff = open(p, encoding="utf-8").read()
    _clean_out(args.out)                           # keeps .git

    def ignore(_dir, names):                       # keep dirs clean of caches
        return [n for n in names if n in ("__pycache__", ".pytest_cache") or n.endswith(".pyc")]

    for d in COPY_DIRS:
        if os.path.isdir(d):
            shutil.copytree(d, os.path.join(args.out, d), ignore=ignore)
    for f in COPY_FILES:
        if not os.path.exists(f):
            raise SystemExit(f"[!] COPY_FILES names {f}, which does not exist. Either restore it"
                             " or drop it from the list -- skipping in silence is how the mirror"
                             " kept shipping a dvc.yaml this repo had already deleted.")
        shutil.copy2(f, os.path.join(args.out, f))

    # the citation ships only when it describes the published deposit (see PUBLISHED_DOI)
    local_cff = open("CITATION.cff", encoding="utf-8").read() if os.path.exists("CITATION.cff") else ""
    cited = re.search(r"^doi:\s*(\S+)\s*$", local_cff, re.M)
    if cited and cited.group(1) == PUBLISHED_DOI:
        open(os.path.join(args.out, "CITATION.cff"), "w", encoding="utf-8").write(local_cff)
    elif prev_cff:
        open(os.path.join(args.out, "CITATION.cff"), "w", encoding="utf-8").write(prev_cff)
        print(f"[!] CITATION.cff describes {cited.group(1) if cited else 'an unknown DOI'}, not the "
              f"published {PUBLISHED_DOI} — kept the mirror's published citation instead.")

    # copy ONLY the whitelisted, P1a-relevant scripts (not the whole scripts/ dir).
    # Source paths carry the role subfolder; the mirror flattens to scripts/<basename>.
    os.makedirs(os.path.join(args.out, "scripts"), exist_ok=True)
    for s in INCLUDE_SCRIPTS:
        src = os.path.join("scripts", s)
        if os.path.exists(src):
            # flattened like the infra profile's, and for the same reason: every RUN: line in these headers
            # names a path this mirror does not have. The rewrite only touches the role directory, and
            # every occurrence here is text a person reads rather than a path opened at run time
            dst = os.path.join(args.out, "scripts", os.path.basename(s))
            open(dst, "w", encoding="utf-8").write(_drop_unshipped_doc_links(
                _flatten_sh(open(src, encoding="utf-8").read()), set(INCLUDE_DOCS)))
            shutil.copymode(src, dst)
    # a trimmed Makefile whose targets only reference the exported scripts
    with open(os.path.join(args.out, "Makefile"), "w", encoding="utf-8") as f:
        f.write(MAKEFILE)

    os.makedirs(os.path.join(args.out, "tests"), exist_ok=True)
    for t in INCLUDE_TESTS:
        src = os.path.join("tests", t)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(args.out, "tests", t))

    os.makedirs(os.path.join(args.out, "docs", "verify"), exist_ok=True)
    for fn in INCLUDE_VERIFY:
        src = os.path.join(VERIFY_FROM, fn)
        if os.path.exists(src):
            dst = os.path.join(args.out, "docs", "verify", fn)
            if fn.endswith(".md"):
                open(dst, "w", encoding="utf-8").write(_flatten_sh(open(src, encoding="utf-8").read()))
                shutil.copymode(src, dst)
            else:
                shutil.copy2(src, dst)
    for src, name in INCLUDE_AUDITS:
        if os.path.exists(src):
            dst = os.path.join(args.out, "docs", "verify", name)
            # Normalise CRLF to LF on the way out. Two of these are written by a csv.writer that
            # emits \r\n, so a byte copy made every line of feed_snapshot_20260812.csv (1,116) and
            # p3_paraphrase_lures.csv (387) differ from the published copy while the content was
            # identical -- a 3,000-line diff on a public repo that says nothing. The mirror's line
            # endings should depend on the mirror, not on how the private file happened to be
            # written. Binary-ish payloads are copied untouched.
            if name.endswith((".csv", ".json", ".md", ".txt")):
                data = open(src, "rb").read().replace(b"\r\n", b"\n")
                open(dst, "wb").write(data)
                shutil.copystat(src, dst)
            else:
                shutil.copy2(src, dst)

    os.makedirs(os.path.join(args.out, "docs"), exist_ok=True)
    for fn in INCLUDE_DOCS:
        src = os.path.join(DOCS_FROM, fn)
        if os.path.exists(src):
            dst = os.path.join(args.out, "docs", fn)
            if fn.endswith(".md"):
                open(dst, "w", encoding="utf-8").write(_flatten_sh(open(src, encoding="utf-8").read()))
                shutil.copymode(src, dst)
            else:
                shutil.copy2(src, dst)

    os.makedirs(os.path.join(args.out, "docs", "decisions"), exist_ok=True)
    for rel in DECISION_DOCS:
        if not os.path.exists(rel):
            raise SystemExit(f"SAFETY: an exported script points at {rel}, which is missing here")
        # these notes open with "Applies to: scripts/<role>/x.py", and the mirror is flat
        dst = os.path.join(args.out, rel)
        open(dst, "w", encoding="utf-8").write(
            _flatten_sh(open(rel, encoding="utf-8").read()))
        shutil.copymode(rel, dst)

    os.makedirs(os.path.join(args.out, "data"), exist_ok=True)
    with open(os.path.join(args.out, "data", "README.md"), "w", encoding="utf-8") as f:
        f.write(DATA_README.format(doi=PUBLISHED_DOI))
    with open(os.path.join(args.out, ".gitignore"), "w", encoding="utf-8") as f:
        f.write(PUBLIC_GITIGNORE)
    with open(os.path.join(args.out, "README.md"), "w", encoding="utf-8") as f:
        f.write(README.format(doi=PUBLISHED_DOI))

    # safety assertion: nothing forbidden slipped in
    forbidden = ("private", "raw", "interim", "processed")
    leaked = []
    for dp, _, fns in os.walk(args.out):
        for fn in fns:
            p = os.path.relpath(os.path.join(dp, fn), args.out)
            if any(seg in p.split(os.sep) for seg in ("papers", "proposal")) or \
               p.startswith(os.path.join("data", "") ) and any(x in p for x in forbidden):
                leaked.append(p)
    if leaked:
        raise SystemExit("SAFETY: forbidden files present: " + ", ".join(leaked))

    for dp, _, fns in os.walk(args.out):
        if "key.csv" in fns:
            raise SystemExit("SAFETY: the audit key reached the export at "
                             + os.path.relpath(os.path.join(dp, "key.csv"), args.out)
                             + " — it un-blinds the annotation sheets and must never ship.")

    # CLOSURE ASSERTION (see _closure_gate). Nested imports count: test_pipeline.py imports its
    # collection modules inside test bodies.
    exported = {os.path.basename(s) for s in INCLUDE_SCRIPTS}
    # Five exemptions, all on paths the mirror cannot reach: hpo_gwo backs an unreleased study's
    # --tune flag; p3_jaccard_check is reached only by make_release after inputs absent here, so
    # it aborts before the import; _path is the bootstrap every header imports inside
    # try/except ImportError -- falling back IS the flat-mirror design; and make_p5_assets and
    # retrain_drift are imported inside run_ml_label_sensitivity's p5() alone, so the p2, p3 and
    # p6 arms -- the three this mirror exists to reproduce -- never reach them.
    private = _private_scripts(exported) - {"hpo_gwo", "p3_jaccard_check", "_path",
                                            "make_p5_assets", "retrain_drift"}
    files = [("scripts", fn) for fn in sorted(exported)] + [("tests", t) for t in INCLUDE_TESTS]
    _closure_gate(args.out, private, files)

    # PROSE ASSERTION (see _prose_gate and PAPER_LABEL).
    _prose_gate(args.out, files, PROSE_WAIVERS)
    _link_gate(args.out, DOC_LINK_WAIVERS)

    n = _count_files(args.out)
    print(f"[+] public repo assembled at {args.out}  ({n} files)")
    print("    excluded: papers/, proposal/, data/raw, data/interim, data/processed, data/private")


if __name__ == "__main__":
    main()
