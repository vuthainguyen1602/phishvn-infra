#!/usr/bin/env python3
"""Build a human-review batch from content-triage findings, with controls mixed in.

The triage flags a handful of hosts as suspected_phishing. Handing a reviewer those and only
those produces a batch where every row is a machine positive, and a reviewer who notices that
will agree more often than the evidence warrants, even without being shown the flag. So the
batch carries an equal number of hosts the triage captured and found nothing in, shuffled
together, and which arm a host came from is written to a key that does not travel with the sheet.

This selects. It does not decide: no verdict column is filled, and nothing here promotes a label.

USAGE:
  python3 scripts/make_content_review_batch.py --out /tmp/batch
  python3 scripts/export_blinded_evidence.py --hosts /tmp/batch/hosts.txt --out /tmp/batch/evidence
"""
import argparse
import csv
import hashlib
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
QUEUE = ROOT / 'data/processed/live_content/review_queue.csv'
# Filled by the reviewer, never by this script. Same shape as the pilot's annotator sheets so
# one adjudication procedure covers both.
SHEET_FIELDS = ['item_id', 'hostname', 'reviewer_id', 'reviewed_at', 'verdict', 'claimed_brand',
                'authorization_basis', 'deceptive_intent', 'evidence_url', 'evidence_observed_at',
                'evidence_file', 'evidence_sha256', 'rationale']


def item_id(hostname):
    return hashlib.sha256(hostname.encode()).hexdigest()[:20]


def select(rows, flagged_status, control_status, controls, seed):
    """Return (batch, key). `batch` is shuffled; `key` records the arm each host came from."""
    flagged = [r for r in rows if r['content_status'] == flagged_status]
    pool = [r for r in rows if r['content_status'] == control_status]
    wanted = len(flagged) if controls is None else controls
    rng = random.Random(seed)
    chosen = pool if wanted >= len(pool) else rng.sample(pool, wanted)
    batch = [(r['hostname'], 'flagged') for r in flagged] + [(r['hostname'], 'control') for r in chosen]
    rng.shuffle(batch)
    key = [{'item_id': item_id(h), 'hostname': h, 'arm': arm,
            'triage_status': flagged_status if arm == 'flagged' else control_status}
           for h, arm in batch]
    return batch, key


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--queue', type=Path, default=QUEUE)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--flagged-status', default='suspected_phishing')
    parser.add_argument('--control-status', default='captured_no_strong_signal')
    parser.add_argument('--controls', type=int, default=None,
                        help='how many control hosts; defaults to one per flagged host')
    parser.add_argument('--seed', type=int, default=20260911)
    args = parser.parse_args()
    rows = list(csv.DictReader(args.queue.open(encoding='utf-8', newline='')))
    batch, key = select(rows, args.flagged_status, args.control_status, args.controls, args.seed)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'hosts.txt').write_text('\n'.join(h for h, _ in batch) + '\n', encoding='utf-8')
    with (args.out / 'review_sheet.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=SHEET_FIELDS)
        writer.writeheader()
        for hostname, _ in batch:
            writer.writerow({'item_id': item_id(hostname), 'hostname': hostname})
    with (args.out / 'KEEP_BLINDED_key.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['item_id', 'hostname', 'arm', 'triage_status'])
        writer.writeheader()
        writer.writerows(key)
    flagged = sum(1 for _, arm in batch if arm == 'flagged')
    print(f'[i] {len(batch)} host(s): {flagged} flagged, {len(batch) - flagged} control, seed {args.seed}')
    print(f'[i] sheet and hosts.txt in {args.out}; KEEP_BLINDED_key.csv stays with you, not the reviewer')
    print(f'[i] next: python3 scripts/export_blinded_evidence.py '
          f'--hosts {args.out}/hosts.txt --out {args.out}/evidence')


if __name__ == '__main__':
    main()
