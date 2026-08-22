#!/usr/bin/env python3
"""
make_public_repo.py — Assemble a CLEAN, public-safe code repo for PhishVN into ./public/.

Whitelist-only: copies exactly the files a public code release needs (scripts, tests, configs,
build files, licences, docs) and NOTHING else. It never copies papers/, proposal/, data/raw,
data/interim, data/processed, or data/private — so manuscripts, the roadmap, raw data and the
id<->PII mapping cannot leak. The dataset itself lives on Mendeley/Zenodo (DOI); the public repo
only points at it.

RUN:
  python scripts/release/make_public_repo.py            # build ./public/  (profile: default)
  python scripts/release/make_public_repo.py --out /tmp/phishvn-public
  python scripts/release/make_public_repo.py --profile infra   # build ./public_infra/ (see INFRA_*)

PROFILES. `default` is the URL-corpus mirror (github.com/vuthainguyen1602/phishvn). `infra` is a
second, independent mirror for the detection-time infrastructure corpus (phishvn-infra): its own
whitelist, docs and README, the same flat layout and the same two gates. The profiles share the
gate code below so neither can drift to a weaker check than the other.
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
    from _path import ROOT, add_script_dirs  # noqa: E402
    add_script_dirs()
except ImportError:  # flat public-mirror layout
    ROOT = os.path.dirname(_HERE)

COPY_DIRS = ["configs"]                                # safe: config only
# dvc.yaml ships because the README lists it and both its stages (normalize, train_url) are exported.
# CITATION.cff is NOT here: it is version-bound and handled below.
COPY_FILES = ["requirements.txt", "LICENSE", "LICENSE-CODE", "dvc.yaml"]
DOCS_FROM = "data/docs"

# WHITELIST EVERYTHING THAT GROWS. tests/ and data/docs/ were copied wholesale until 2026-08-11;
# both grew private material (claims verifier, P2 paired eval, P3 Jaccard band, scenario_grounding.md)
# that a re-export would have published — and the private-suite imports broke `pytest -q` on the mirror.
INCLUDE_TESTS = ["test_pipeline.py"]                   # the only suite whose imports are exported
INCLUDE_DOCS = ["datasheet.md", "schema.md", "data_sources.md"]

# The label-audit instruments P1 states are released with the code. key.csv NEVER ships: it maps
# blinded id -> source label and would destroy the blinding. MACHINE_PASS.csv ships (its failure vs
# the benign control backs the datasheet's "not adjudicable from archives" claim); it carries no
# source labels, and the codebook forbids annotators opening it before their own sheet is done.
INCLUDE_VERIFY = ["CODEBOOK.md", "annotator_A.csv", "annotator_B.csv", "MACHINE_PASS.csv", "adjudicated.csv"]
VERIFY_FROM = "data/docs/verify"
# Audit artefacts the revised manuscript declares released, as (source, exported name);
# they land in docs/verify/ beside the label-audit instruments.
INCLUDE_AUDITS = [
    ("data/reports/token_audit_sample.csv", "token_audit_sample.csv"),
    ("data/processed/first_seen_validation.csv", "first_seen_validation.csv"),
    ("data/processed/first_seen_validation_summary.json", "first_seen_validation_summary.json"),
    # the unified-feed snapshot the token audit sampled from (836 -> 1,115 claim), archived so
    # the audited numbers are reproducible against a fixed input rather than a moving feed
    ("data/interim/vn_phishing_candidates_20260812.csv", "feed_snapshot_20260812.csv"),
]

# CITATION.cff tracks the LOCAL corpus (it hit 3.0.0 / 53,116 records / the reserved `.3` DOI while
# readers could still only fetch v2), so it is exported only when its DOI equals this constant; the
# mirror keeps its published citation until then. Bump when the next version goes live on Mendeley.
PUBLISHED_DOI = "10.17632/b97hxbxtpd.4"

# PROSE GATE. Comments/docstrings are what leaked: four exported modules named unreleased papers and
# quoted their numbers, caught only by a pre-push diff read. The paper LABEL is the tell (attribution
# turns an engineering note into a disclosure), and matching it catches all four incident files.
# Floor, not ceiling: an unattributed leak still passes. P1 is deliberately absent — it is the paper
# this mirror accompanies; including it took the flag rate from 4/19 to 12/19, all noise.
PAPER_LABEL = re.compile(r"\bP[2-8][ab]?\b(?!\w)|papers/P[2-8]|P[2-8]_[a-z]+")

# file -> why its labels are legitimate. A reason is required, and waived labels are still printed
# on every export, so a NEW one appearing in a waived file cannot hide behind the old decision.
PROSE_WAIVERS = {
    "make_public_repo.py": "the export policy has to name which papers are held back",
    "normalize_merge.py": "\"P2 corpus\" is the external benchmark corpus, not the manuscript",
    # Seven scripts ARE the URL-benchmark study's own code, exported because its conclusion
    # promises the code behind every table (see INCLUDE_SCRIPTS). Stripping the label from a
    # docstring that opens "the P2 benchmark" would leave the file describing an experiment it
    # cannot name, which is worse for a cloner than the label costs. Decided 2026-08-18.
    "run_p2_benchmark.py": "this IS that study's benchmark driver; the label names what it runs",
    "run_p2_temporal_strict.py": "this IS that study's strict-temporal protocol",
    "run_p2_stacking_baseline.py": "this IS that study's stacking arm",
    "make_p2_bench_assets.py": "generates that study's tables; the paths it writes name them",
    "audit_label_noise.py": "the label-noise audit that study's decomposition rests on",
    "hpo_gwo.py": "the HPO method that study benchmarks against random search",
    "run_gwo_temporal.py": "the HPO arm on the temporal window, named by its output path",
}

# Only scripts that build/reproduce the RELEASED P1a URL dataset and baselines. Scripts for
# unreleased channels/papers (SMS, email, images, PhoBERT, fusion, LLM red-team, drift, edge —
# P1b/P2/P6/P7) stay private until those papers and their data are released.
# Entries are role-subfolder paths in THIS repo; the mirror stays FLAT (basename only) — the
# exported files' uniform bootstrap headers fall back via ImportError in the flat layout.
INCLUDE_SCRIPTS = [
    "collect/scrape_vn_phishing.py",     # collect phishing URLs (NCSC blacklist + feeds)
    "collect/scrape_trusted_orgs.py",    # collect benign trusted-org URLs
    "collect/fetch_tranco.py",           # hard benign negatives (Tranco)
    "collect/fetch_urlscan.py",          # preliminary HTML/screenshot subset
    "collect/whois_dns_enrich.py",       # optional URL/host enrichment
    "dataset/normalize_merge.py",        # build the unified URL dataset + group-aware temporal split
    "lib/compphish_features.py",         # CompPhish-aligned URL feature schema
    "dataset/align_compphish.py",        # re-featurise URLs into the CompPhish schema
    "train/train_url_baseline.py",       # URL baselines (multi-seed + bootstrap CI)
    "audit/make_verification_sample.py", # label-quality audit (Cohen's kappa)
    "collect/watch_chongluadao.py",      # the live ChongLuaDao watcher feeding the corpus
    "collect/fetch_phishing_feeds.py",   # the feed importer test_pipeline.py exercises
    "lib/psl.py",                        # PSL domain folding shared by collection and evaluation
    "lib/vn_filter.py",                  # is-this-VN-targeting test used across collection
    "dataset/build_brand_tokens.py",     # registry-derived brand tokens the filter matches on
    "assets/make_p1_assets.py",         # regenerate the paper's figure + tables from data
    "collect/fetch_chongluadao.py",      # import the ChongLuaDao mirror snapshot (named in the paper)
    "dataset/chongluadao_first_seen.py", # reconstruct per-domain first-seen dates (named in the paper)
    "audit/validate_first_seen.py",      # accuracy estimate for the reconstructed dates (rev. #1)
    "audit/audit_token_filter.py",       # sampled audit of the VN-targeting token filter (rev. #1)
    "assets/export_p1_results.py",      # the deposited benchmark-evidence bundle's generator
    "dataset/derive_abuse_type.py",      # types the positive class; its output ships in the open tier
    "audit/collect_audit_evidence.py",   # gathers the lookup evidence the released audit sheets need
    "audit/machine_pass_composition.py", # the archive-content pass, and the control showing it fails
    "release/make_release.py",           # package the citable open/gated release
    "release/make_public_repo.py",       # this exporter
    "lib/genfile.py",                    # atomic writer every asset generator goes through
    "lib/figstyle.py",                   # house palette + rcParams (and it installs the axis guard)
    "lib/axguard.py",                    # refuses to write a figure that clips its own data
    # P2 (URL benchmark) — the conclusion promises the code behind every table
    "train/run_p2_benchmark.py",         # 7-family benchmark under the bundled protocols
    "train/run_p2_temporal_strict.py",   # the strict-temporal protocol (+ rolling origins)
    "train/run_p2_stacking_baseline.py", # stacked ensembles / base-learner combos
    "train/run_p2_drift_forecastability.py",  # the three forecastability diagnostics
    "train/run_cross_dataset.py",        # 4-corpus transfer matrix
    "train/hpo_gwo.py",                  # GWO vs equal-budget random search
    "train/run_gwo_temporal.py",         # the HPO arm on the temporal window
    "audit/audit_label_noise.py",        # confident-learning label-noise audit
    "lib/paired_eval.py",                # NB-corrected paired t-test + BH (all significance)
    "assets/make_p2_bench_assets.py",    # regenerates every P2 table/figure/verdict macro
]

# ----------------------------------------------------------------------------------------------
# PROFILE `infra`: the detection-time infrastructure corpus (phishvn-infra). Whitelist-only, flat,
# same gates. Everything below is read ONLY when --profile infra is given; the default profile's
# constants above are untouched.
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
# The scripts the data article names, plus their import closure (the closure gate is the
# arbiter: add here only what it reports dangling). Flat on export, like the default profile.
INFRA_SCRIPTS = [
    "collect/watch_host_infra.py",      # the infrastructure watcher (DNS/WHOIS/TLS at detection time)
    "collect/watch_ct_benign.py",       # CT-sampled, age-matched benign arm (+ --stratum vn)
    "collect/watch_urlscan_brands.py",  # brand-token urlscan feed (the live phishing channel)
    "collect/watch_chongluadao.py",     # capture helpers watch_urlscan_brands imports
    "audit/audit_p4_labels.py",         # the label gate + registry-wildcard probe
    "assets/make_p4_assets.py",         # build_population (funnel stages); refuses to fit below trigger
    "assets/make_p4_funnel.py",         # funnel + accrual tables/figure
    "assets/make_p4b_assets.py",        # the data article's generated tables/figures
    "lib/psl.py",                       # vendored from the URL-corpus repo (source of truth there)
    "lib/vn_filter.py",                 # vendored: VN-targeting test + brand tokens
    "lib/genfile.py",                   # atomic writer
    "lib/figstyle.py",                  # house palette (installs the axis guard)
    "lib/axguard.py",                   # refuses to write a figure that clips its data
    "lib/paired_eval.py",               # wilson() used by build_population's tables
    "lib/compphish_features.py",        # lexical channel make_p4_assets imports at module load
    "assets/make_p4_perishability.py", # capture perishability (live vs backfill resolvability)
    "audit/audit_infra_capture.py",     # its helper: the WHOIS-by-policy artefact, measured
    "release/make_public_repo.py",      # this exporter
]
# The cron wrappers ship under scripts/ops/ with their `scripts/<role>/x.py` calls rewritten to
# the flat `scripts/x.py` (the only edit made to any exported file; see _flatten_sh).
INFRA_OPS = ["host_infra_run.sh", "ct_benign_run.sh", "ct_benign_vn_run.sh",
             "urlscan_brands_run.sh", "rowcount_snapshot.sh",
             # Ships with the wrappers because it is what tells a silent collector from a quiet
             # day, and it checks that every module the wrappers import exists on the device --
             # the failure that cost this collection 28 hours on 2026-08-21.
             "jetson_health.sh"]
# No test suite ships: the only candidates either import a non-exported module
# (test_p4_cascade -> run_p4_cascade_eval) or hard-code the role-folder path scripts/assets/
# that the flat mirror does not have (test_p4_funnel, test_p4_perishability).
INFRA_TESTS: list[str] = []
# The collector's own code and wrappers name the detection study they were built for, exactly as
# the URL-benchmark scripts name theirs (see PROSE_WAIVERS). Same rule: a reason per file, printed
# on every export. The hand-written docs under data/docs/infra/ get NO waiver: they must not name
# any paper (and not "companion" either) -- phrase as "the data article" / "the detection study".
INFRA_PROSE_WAIVERS = {
    "watch_host_infra.py": "one comment names the study whose benign arm the source map serves",
    "watch_ct_benign.py": "this IS that study's matched benign arm; its docstring names the design",
    "audit_p4_labels.py": "this IS that study's label gate; the label names what it audits",
    "make_p4_assets.py": "this IS that study's population builder; paths it writes name it",
    "make_p4_funnel.py": "names the paper folder its figure is written into",
    "make_p4b_assets.py": "names the data article's own paper folder (its output path)",
    "make_public_repo.py": "the export policy has to name which papers are held back",
    "ct_benign_run.sh": "the rotation comment names the study the age match exists for",
    "audit_infra_capture.py": "this IS that study's capture audit; it names the design it constrains",
    "make_p4_perishability.py": "names the paper folder its table is written into",
    "urlscan_brands_run.sh": "the wrapper comment names the study its feed serves",
    "rowcount_snapshot.sh": "the comment names the arm whose back-dated stamps it exists for",
    "ct_benign_vn_run.sh": "names the pre-registration amendment that created the stratum",
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
- `docs/verify/` — the completed human label audit: pre-registered codebook (with its amendment
  log), both annotators' independent sheets, the machine pass, and the arbitration record.
- `tests/`, `configs/`, `Makefile`, `dvc.yaml` — reproducibility.

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

## Citation
See `CITATION.cff`. Please cite the dataset DOI and credit the upstream sources
(NCSC "Tin Nhiem Mang" and the Tranco list).

## Licence
Code: MIT (`LICENSE-CODE`). Dataset: CC BY 4.0 (`LICENSE`).
"""

MAKEFILE = """.PHONY: install data url assets release verify clean
install:      ## install python deps
\tpip install -r requirements.txt
data:         ## build the URL dataset from data/raw
\tpython scripts/normalize_merge.py --raw data/raw --out data/processed
url:          ## train URL baselines (multi-seed + bootstrap CI)
\tpython scripts/train_url_baseline.py --in data/processed/dataset_url.csv --out models/url_rf.joblib
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
    """Comments and docstrings only. The code is not what leaks -- a function named
    make_p5_assets says nothing a reader could not infer from the repository layout."""
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
    """The wrappers call `scripts/<role>/x.py`; the mirror is flat. Nothing else is rewritten."""
    return re.sub(r"scripts/(collect|audit|assets|lib|dataset|train|release)/", "scripts/", src)


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
    flat scripts/, no data payloads, no papers, no pre-registration, no .env; both gates."""
    _clean_out(out)
    for f in INFRA_COPY_FILES:
        if os.path.exists(f):
            shutil.copy2(f, os.path.join(out, f))

    os.makedirs(os.path.join(out, "scripts", "ops"), exist_ok=True)
    for s in INFRA_SCRIPTS:
        src = os.path.join("scripts", s)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(out, "scripts", os.path.basename(s)))
    for sh in INFRA_OPS:
        src = os.path.join("scripts", "ops", sh)
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
            shutil.copy2(src, os.path.join(out, dst_rel))
        else:
            missing.append(src)
    if missing:
        raise SystemExit("SAFETY: infra docs missing (the README/citation are hand-written, not "
                         "generated): " + ", ".join(missing))

    os.makedirs(os.path.join(out, "data"), exist_ok=True)
    with open(os.path.join(out, "data", "README.md"), "w", encoding="utf-8") as f:
        f.write(INFRA_DATA_README)
    with open(os.path.join(out, ".gitignore"), "w", encoding="utf-8") as f:
        f.write(PUBLIC_GITIGNORE)

    # safety assertion: nothing forbidden slipped in -- the default profile's classes, plus the
    # secrets file, anything named like a pre-registration, and any payload under data/.
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
    for _, dst_rel in INFRA_DOCS:
        text = open(os.path.join(out, dst_rel), encoding="utf-8").read()
        hits = sorted({m.group(0) for m in PAPER_LABEL.finditer(text)}
                      | {m.group(0) for m in INFRA_DOC_FORBIDDEN.finditer(text)})
        if hits:
            bad.append(f"{dst_rel}: {', '.join(hits)}")
    if bad:
        raise SystemExit("SAFETY: infra docs name a paper or call it a companion:\n  "
                         + "\n  ".join(bad))

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
        if os.path.exists(f):
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
            shutil.copy2(src, os.path.join(args.out, "scripts", os.path.basename(s)))
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
            shutil.copy2(src, os.path.join(args.out, "docs", "verify", fn))
    for src, name in INCLUDE_AUDITS:
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(args.out, "docs", "verify", name))

    os.makedirs(os.path.join(args.out, "docs"), exist_ok=True)
    for fn in INCLUDE_DOCS:
        src = os.path.join(DOCS_FROM, fn)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(args.out, "docs", fn))

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
    # Three exemptions, all on paths the mirror cannot reach: hpo_gwo backs `--tune --tune-method
    # gwo` (unreleased study); p3_jaccard_check is only reached by make_release after inputs that
    # are absent here, so it aborts before the import; _path is the layout bootstrap every
    # exported header imports inside try/except ImportError — falling back IS the flat-mirror
    # design, so the import is dangling on purpose.
    private = _private_scripts(exported) - {"hpo_gwo", "p3_jaccard_check", "_path"}
    files = [("scripts", fn) for fn in sorted(exported)] + [("tests", t) for t in INCLUDE_TESTS]
    _closure_gate(args.out, private, files)

    # PROSE ASSERTION (see _prose_gate and PAPER_LABEL).
    _prose_gate(args.out, files, PROSE_WAIVERS)

    n = _count_files(args.out)
    print(f"[+] public repo assembled at {args.out}  ({n} files)")
    print("    excluded: papers/, proposal/, data/raw, data/interim, data/processed, data/private")


if __name__ == "__main__":
    main()
