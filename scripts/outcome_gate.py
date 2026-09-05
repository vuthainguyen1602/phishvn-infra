"""Hard outcome-label gate shared by both confirmatory paths of the detection study.

The collection funnel admits *candidates*.  It is not an outcome label.  T1, T2, and imported
score tables remain locked until a separate blinded, two-annotator file supplies enough
adjudicated positives with positive evidence that is stronger than language, lexical form, or
the mere presence of a password field.
"""
from __future__ import annotations

from dataclasses import dataclass
import os

import pandas as pd


OUTCOME_LABELS = "data/processed/p4/p4_outcome_labels.csv"
REQUIRED_COLUMNS = (
    "registered_domain", "annotator_a", "annotator_b", "adjudicated_label",
    "positive_evidence", "blinded_to_infrastructure", "blinded_to_model",
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
    trusted = pd.concat([keep_phish, pop[pop["arm"] != "phish"]], ignore_index=True)
    return trusted, OutcomeGate(True, "trusted-positive unlock satisfied", n_candidates, **common)
