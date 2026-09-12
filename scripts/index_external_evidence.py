#!/usr/bin/env python3
"""Index the time-matched artifacts urlscan already captured, which the pipeline does not see.

The collection records `content_status = not_checked` and an empty `content_evidence_path` for
every observation, and the review protocol refuses a verdict without evidence taken near the
observation. Both statements are true and both miss the same fact: the urlscan channel stores a
DOM and a screenshot for each host it finds, captured at scan time, and those files are on disk.
This walks the two ledgers that reference them, confirms each file exists, hashes it, and writes
one row per host so the rest of the pipeline can find them.

WHY THIS IS A DIFFERENT KIND OF EVIDENCE. Our own triage visits a host now and can only speak to
what it serves now. A urlscan artifact was taken when the host was found, and its `scan_uuid`
resolves publicly, so a referee opens the same scan rather than taking this repository's word.
That is an observation of a third party acting, not an opinion, which is why it outranks any
verdict a model or a heuristic produces.

WHAT IT DOES NOT DO. It changes no label. These hosts carry `label=unknown`, so an artifact makes
them ANNOTATABLE; it does not annotate them, and it does not validate the phishing or benign
labels of the other strata, which have no such artifact.

RUN:
  python3 scripts/index_external_evidence.py
"""
import argparse
import csv
import hashlib
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
# Both ledgers carry artifact columns. detections.csv is the live feed; captures.csv is the retry
# store, and it holds over a thousand hosts the feed ledger never recorded, so neither alone is
# the index.
LEDGERS = [('detections', ROOT / 'data/raw/urlscan_brands/detections.csv'),
           ('captures', ROOT / 'data/raw/urlscan_brands/captures.csv')]
OUT = ROOT / 'data/processed/live_content/external_evidence.csv'
FIELDS = ['hostname', 'evidence_source', 'scan_uuid', 'scan_url', 'scan_time', 'first_detected',
          'lag_days', 'dom_path', 'dom_sha256', 'shot_path', 'shot_sha256', 'origin_ledger']


def parse(stamp):
    try:
        return datetime.fromisoformat((stamp or '')[:19].replace(' ', 'T'))
    except ValueError:
        return None


def resolve(path, root=ROOT):
    """An artifact path that actually exists, or None. Paths are recorded relative to the repo
    root in one ledger and to the source directory in the other."""
    raw = (path or '').strip()
    if not raw:
        return None
    for candidate in (root / raw, root / 'data/raw/urlscan_brands' / raw):
        if candidate.is_file():
            return candidate
    return None


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def index(ledgers=LEDGERS, root=ROOT):
    """One row per host. Returns (rows, stats). A host seen in both ledgers keeps the record whose
    scan is closest to its detection, because that is the one the protocol can accept."""
    best, stats = {}, {'rows_read': 0, 'no_artifact': 0, 'missing_file': 0}
    for name, path in ledgers:
        if not path.exists():
            continue
        for record in csv.DictReader(path.open(encoding='utf-8', newline='')):
            stats['rows_read'] += 1
            hostname = (record.get('domain') or '').strip()
            uuid = (record.get('scan_uuid') or '').strip()
            if not hostname or not uuid:
                stats['no_artifact'] += 1
                continue
            dom = resolve(record.get('dom_file'), root)
            shot = resolve(record.get('shot_file'), root)
            if not dom and not shot:
                stats['missing_file'] += 1
                continue
            scan = parse(record.get('scan_time') or record.get('attempted_at'))
            detected = parse(record.get('first_detected'))
            lag = round((scan - detected).total_seconds() / 86400, 3) if scan and detected else ''
            row = {'hostname': hostname, 'evidence_source': 'urlscan', 'scan_uuid': uuid,
                   'scan_url': 'https://urlscan.io/result/' + uuid + '/',
                   'scan_time': scan.isoformat() if scan else '',
                   'first_detected': detected.isoformat() if detected else '',
                   'lag_days': lag,
                   'dom_path': str(dom.relative_to(root)) if dom else '',
                   'dom_sha256': digest(dom) if dom else '',
                   'shot_path': str(shot.relative_to(root)) if shot else '',
                   'shot_sha256': digest(shot) if shot else '',
                   'origin_ledger': name}
            kept = best.get(hostname)
            if kept is None or _closer(row, kept):
                best[hostname] = row
    return sorted(best.values(), key=lambda r: r['hostname']), stats


def _closer(candidate, kept):
    """Prefer a measured lag over an unmeasured one, then the smaller lag."""
    a, b = candidate['lag_days'], kept['lag_days']
    if a == '':
        return False
    if b == '':
        return True
    return abs(float(a)) < abs(float(b))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', type=Path, default=OUT)
    args = parser.parse_args()
    rows, stats = index()
    if not rows:
        sys.exit('[!] no artifacts found; the urlscan ledgers are missing or their files are gone')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    lags = sorted(float(r['lag_days']) for r in rows if r['lag_days'] != '')
    both = sum(1 for r in rows if r['dom_path'] and r['shot_path'])
    print(f"[i] {len(rows)} host(s) with a time-matched artifact -> {args.out}")
    print(f"    {both} have both DOM and screenshot; {stats['rows_read']} ledger rows read, "
          f"{stats['no_artifact']} with no scan id, {stats['missing_file']} referencing a file that is gone")
    if lags:
        print(f"    lag measurable for {len(lags)}: median {lags[len(lags)//2]:.2f} d, "
              f"{sum(1 for x in lags if x <= 1)} within 1 day")
    print(f"    {len(rows) - len(lags)} carry a scan time but no recorded detection time, so their "
          f"lag is unproven and must not be reported as zero")


if __name__ == '__main__':
    main()
