#!/usr/bin/env python3
"""Build a reproducible human-review batch from live unknown candidates.

The input is the generated risk-ranked live label output. This script does not
promote labels; it only creates rows for reviewers to inspect and fill.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import random
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_IN = ROOT / "data/processed/live_labels/review_candidates.csv"
DEFAULT_OUT = ROOT / "data/processed/live_labels/audit_sample.csv"

REVIEW_FIELDS = [
    "audit_id", "sample_stratum", "review_rank", "domain", "registered_domain", "source",
    "candidate_risk_score", "candidate_risk_level", "candidate_review_priority",
    "candidate_risk_reasons", "impersonation_sector", "brand_token_hits",
    "content_status", "content_review_priority", "content_checked_at", "content_evidence_path",
    "captured_at", "first_detected", "whois_created", "registrar", "tls_present", "tls_verified",
    "reviewer", "reviewed_at", "verdict", "evidence_url", "evidence_path", "rationale",
]


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def stable_id(domain: str, seed: int) -> str:
    return "L" + hashlib.sha256(f"live-audit:{seed}:{domain}".encode()).hexdigest()[:10].upper()


def take(rows: list[dict[str, str]], n: int, *, rng: random.Random, ordered: bool) -> list[dict[str, str]]:
    if n <= 0 or not rows:
        return []
    if ordered:
        return rows[:n]
    return sorted(rng.sample(rows, min(n, len(rows))), key=lambda r: (r.get("registered_domain", ""), r.get("domain", "")))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="input", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--high", type=int, default=100, help="Top high-risk rows, rank ordered")
    parser.add_argument("--medium", type=int, default=150, help="Random medium-risk rows")
    parser.add_argument("--low", type=int, default=25, help="Random low-risk rows")
    parser.add_argument("--background", type=int, default=25, help="Random background control rows")
    args = parser.parse_args()

    rows = read_rows(args.input)
    by_level = {level: [r for r in rows if r.get("candidate_risk_level") == level]
                for level in ["high", "medium", "low", "background"]}
    rng = random.Random(args.seed)
    picked = []
    picked.extend(("high", r) for r in take(by_level["high"], args.high, rng=rng, ordered=True))
    picked.extend(("medium", r) for r in take(by_level["medium"], args.medium, rng=rng, ordered=False))
    picked.extend(("low", r) for r in take(by_level["low"], args.low, rng=rng, ordered=False))
    picked.extend(("background", r) for r in take(by_level["background"], args.background, rng=rng, ordered=False))

    out_rows = []
    seen = set()
    for stratum, row in picked:
        domain = row.get("domain", "")
        if domain in seen:
            continue
        seen.add(domain)
        out = {field: row.get(field, "") for field in REVIEW_FIELDS}
        out.update({
            "audit_id": stable_id(domain, args.seed),
            "sample_stratum": stratum,
            "reviewer": "",
            "reviewed_at": "",
            "verdict": "",      # phishing | benign | scam_non_phishing | inactive | unsure
            "evidence_url": "",
            "evidence_path": "",
            "rationale": "",
        })
        out_rows.append(out)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    temp = args.out.with_suffix(args.out.suffix + ".tmp")
    with temp.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=REVIEW_FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)
    temp.replace(args.out)

    print({
        "input": str(args.input.relative_to(ROOT) if args.input.is_relative_to(ROOT) else args.input),
        "output": str(args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out),
        "seed": args.seed,
        "rows": len(out_rows),
        "sample_strata": dict(Counter(r["sample_stratum"] for r in out_rows)),
        "available_levels": {k: len(v) for k, v in by_level.items()},
    })


if __name__ == "__main__":
    main()
