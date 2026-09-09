"""Hard outcome-label gate shared by both confirmatory paths of the detection study.

The collection funnel admits *candidates*.  It is not an outcome label.  T1, T2, and imported
score tables remain locked until a separate blinded, two-annotator file supplies enough
adjudicated positives with positive evidence that is stronger than language, lexical form, or
the mere presence of a password field.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import hashlib
from pathlib import Path

from label_policy import observable

import pandas as pd


OUTCOME_LABELS = "data/processed/infra/p4_outcome_labels.csv"
REQUIRED_COLUMNS = (
    "registered_domain", "annotator_a", "annotator_b", "adjudicated_label",
    "positive_evidence", "blinded_to_infrastructure", "blinded_to_model",
    "annotator_a_id", "annotator_b_id", "evidence_url", "evidence_path", "evidence_sha256",
    "observed_from", "observed_until", "benign_evidence",
)
ANNOTATIONS = {"phishing", "benign", "unsure"}
FINAL_LABELS = {"phishing", "benign"}
# Candidate-only signals (language, lexical construction, credential_form) are deliberately absent.
TRUSTED_POSITIVE_EVIDENCE = {
    "independent_blocklist",
    "credential_exfiltration",
    "phishing_kit",
    "operator_confirmation",
}


@dataclass(frozen=True)
class OutcomeGate:
    unlocked: bool
    reason: str
    n_candidates: int
    n_reviewed: int = 0
    n_resolved: int = 0
    n_positive: int = 0
    n_positive_vn: int = 0
    agreement_rate: float | None = None


def _truthy(series: pd.Series) -> pd.Series:
    return series.astype(str).str.strip().str.lower().isin({"1", "true", "yes"})


def trusted_positive_population(
        pop: pd.DataFrame,
        minimum_positives: int,
        labels_path: str = OUTCOME_LABELS,
) -> tuple[pd.DataFrame, OutcomeGate]:
    """Return a copy whose phishing arm contains only trusted adjudicated positives.

    Invalid label files fail closed with a reason.  A missing/incomplete file is ordinary
    pre-outcome state, not an exception.  Smoke and design analyses must bypass this function
    explicitly because they do not read the accrued outcome.
    """
    candidates = pop[pop["arm"] == "phish"].copy()
    n_candidates = candidates["registered_domain"].nunique()
    locked = lambda reason, **kw: (
        pop.iloc[0:0].copy(),
        OutcomeGate(False, reason, n_candidates, **kw),
    )
    if not os.path.exists(labels_path):
        return locked(f"trusted-label file absent: {labels_path}")
    try:
        labels = pd.read_csv(labels_path, dtype=str).fillna("")
    except Exception as exc:
        return locked(f"trusted-label file unreadable: {exc}")
    missing = [c for c in REQUIRED_COLUMNS if c not in labels.columns]
    if missing:
        return locked("trusted-label schema missing: " + ", ".join(missing))
    labels = labels[list(REQUIRED_COLUMNS)].copy()
    for c in REQUIRED_COLUMNS:
        labels[c] = labels[c].astype(str).str.strip()
    labels["registered_domain"] = labels["registered_domain"].str.lower().str.strip(".")
    if labels["registered_domain"].eq("").any():
        return locked("trusted-label file contains an empty registered_domain")
    if labels["registered_domain"].duplicated().any():
        return locked("trusted-label file contains duplicate registered_domain rows")
    if not labels["annotator_a"].isin(ANNOTATIONS).all() or not labels["annotator_b"].isin(
            ANNOTATIONS).all():
        return locked("annotator labels must be phishing, benign, or unsure")
    if not (_truthy(labels["blinded_to_infrastructure"]).all()
            and _truthy(labels["blinded_to_model"]).all()):
        return locked("every review must certify infrastructure/model-score blinding")

    same_resolved = ((labels["annotator_a"] == labels["annotator_b"])
                     & labels["annotator_a"].isin(FINAL_LABELS))
    needs_adjudication = ~same_resolved
    if not labels.loc[needs_adjudication, "adjudicated_label"].isin(FINAL_LABELS).all():
        return locked("every disagreement or unsure verdict requires final adjudication",
                      n_reviewed=len(labels))
    labels["final_label"] = labels["annotator_a"].where(
        same_resolved, labels["adjudicated_label"])
    positive = labels["final_label"].eq("phishing")
    if not labels.loc[positive, "positive_evidence"].isin(TRUSTED_POSITIVE_EVIDENCE).all():
        return locked("every positive requires trusted positive evidence",
                      n_reviewed=len(labels), n_resolved=len(labels))

    # Version 2: an evidence enum alone is not an auditable review. Validate the
    # artifact, exact captured hostname and time interval; controls require review too.
    if (labels["annotator_a_id"].eq("").any() or labels["annotator_b_id"].eq("").any()
            or labels["annotator_a_id"].eq(labels["annotator_b_id"]).any()):
        return locked("two distinct identified reviewers are required")
    if not {"domain", "captured_at"}.issubset(pop.columns):
        return locked("population lacks exact hostname/capture time for evidence matching")
    pop_keys = pop.assign(_key=pop["registered_domain"].astype(str).str.lower().str.strip("."))
    for row in labels.itertuples(index=False):
        artifact = Path(row.evidence_path)
        if (not artifact.is_file() or not row.evidence_sha256
                or hashlib.sha256(artifact.read_bytes()).hexdigest() != row.evidence_sha256):
            return locked("review evidence artifact absent or hash mismatch")
        host, url = observable(row.evidence_url)
        if not url:
            return locked("review requires an exact evidence URL")
        start = pd.to_datetime(row.observed_from, errors="coerce", utc=True)
        end = pd.to_datetime(row.observed_until, errors="coerce", utc=True)
        if pd.isna(start) or pd.isna(end) or end < start:
            return locked("review requires a valid observed time interval")
        selected = pop_keys[pop_keys["_key"] == row.registered_domain]
        for captured in selected.itertuples(index=False):
            if observable(captured.domain)[0] != host:
                return locked("review host differs from captured host; no parent/sibling propagation")
            stamp = pd.Timestamp(captured.captured_at)
            if stamp.tzinfo is None:
                stamp = stamp.tz_localize("Asia/Ho_Chi_Minh")
            if not start <= stamp.tz_convert("UTC") <= end:
                return locked("capture falls outside reviewed observation interval")
        if row.final_label == "benign" and not row.benign_evidence.strip():
            return locked("negative outcomes require reviewed benign evidence")

    candidate_domains = set(candidates["registered_domain"].astype(str).str.lower().str.strip("."))
    current = labels[labels["registered_domain"].isin(candidate_domains)].copy()
    pos_domains = set(current.loc[current["final_label"].eq("phishing"), "registered_domain"])
    n_pos = len(pos_domains)
    n_vn = sum(d.endswith(".vn") for d in pos_domains)
    agree = float((current["annotator_a"] == current["annotator_b"]).mean()) if len(current) else None
    common = dict(n_reviewed=len(current), n_resolved=len(current), n_positive=n_pos,
                  n_positive_vn=n_vn, agreement_rate=agree)
    if n_pos < minimum_positives:
        return locked(f"trusted positives below unlock ({n_pos} < {minimum_positives})", **common)

    keep_phish = candidates[
        candidates["registered_domain"].astype(str).str.lower().str.strip(".").isin(pos_domains)]
    negatives = set(labels.loc[labels["final_label"].eq("benign"), "registered_domain"])
    controls = pop[(pop["arm"] == "benign") &
                   pop["registered_domain"].astype(str).str.lower().str.strip(".").isin(negatives)]
    if controls.empty:
        return locked("no independently reviewed benign controls", **common)
    trusted = pd.concat([keep_phish, controls], ignore_index=True)
    trusted["label"] = trusted["arm"].map({"phish": "phishing", "benign": "benign"})
    trusted["label_status"] = trusted["arm"].map({"phish": "confirmed_phishing", "benign": "verified_benign"})
    trusted["training_eligible"] = 1
    return trusted, OutcomeGate(True, "trusted-positive unlock satisfied", n_candidates, **common)
