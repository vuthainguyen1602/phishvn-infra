#!/usr/bin/env python3
"""Export capture artifacts for human annotation with the machine's opinion removed.

The pilot only means something if the reviewer reaches a verdict from the artifact rather than
from this pipeline's guess, so two fields never leave with a bundle:

  analysis       content_status, review_priority, suggested_label, reasons, brand_matches
  source         the feed name, which IS the claim under test: seeing `chongluadao_live` or
                 `tinnhiem_benign` hands the reviewer the label they were asked to check
  registry_path  constant across every bundle and so carries no per-host signal, but its value
                 is `data/raw/tinnhiem_benign/detections.csv`, which puts a feed name reading
                 as a label in front of the reviewer. registry_sha256 stays and identifies the
                 registry exactly, so nothing about provenance is lost by dropping the path.

This is the same blinding the strata key already applies one layer down: the hostname is given,
the claim is not. Withholding at field level rather than excluding sampled hosts from the triage
report matters, because an excluded host is identifiable by its absence and its capture still
sits on disk carrying the analysis block.

USAGE:
  python3 scripts/export_blinded_evidence.py --hosts audit/annotator_A.csv --out /tmp/bundle_A
"""
import argparse
import csv
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'data/processed/live_content'
# Withheld from anything an annotator sees. Adding a field here is the whole fix; do not filter
# in the caller instead, or the next caller will forget.
BLINDED_FIELDS = ('analysis', 'source', 'registry_path')
ARTIFACTS = ('page.html', 'page.png', 'browser.log')


def blind(evidence):
    """Return a copy of one evidence record with the withheld fields gone.

    Non-destructive: callers hold the original, and a mutating version of this silently
    corrupted the stored capture the first time it was written.
    """
    return {k: v for k, v in evidence.items() if k not in BLINDED_FIELDS}


def read_hosts(path):
    """Hostnames from an annotator sheet (a `hostname` column) or a plain one-per-line list."""
    text = path.read_text(encoding='utf-8')
    first = text.splitlines()[0] if text.splitlines() else ''
    if 'hostname' in first.split(','):
        rows = csv.DictReader(text.splitlines())
        return [r['hostname'].strip() for r in rows if (r.get('hostname') or '').strip()]
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith('#')]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def export(hosts, latest, out, content_root=OUT):
    """Write one blinded bundle per host. Returns (exported, missing).

    A host with no capture yet is REPORTED, never quietly skipped: an annotator handed a short
    bundle would otherwise read the gap as "nothing was found here", which is a verdict.
    """
    exported, missing, manifest = [], [], []
    for hostname in hosts:
        entry = latest.get(hostname)
        if not entry or not entry.get('evidence_path'):
            missing.append(hostname)
            continue
        evidence_path = content_root / entry['evidence_path']
        if not evidence_path.exists():
            missing.append(hostname)
            continue
        source_dir = evidence_path.parent
        target = out / hostname.replace('/', '_')
        target.mkdir(parents=True, exist_ok=True)
        record = blind(json.loads(evidence_path.read_text(encoding='utf-8')))
        (target / 'evidence.json').write_text(json.dumps(record, indent=2, sort_keys=True), encoding='utf-8')
        copied = ['evidence.json']
        for name in ARTIFACTS:
            for found in sorted(source_dir.rglob(name)):
                relative = found.relative_to(source_dir)
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(found, destination)
                copied.append(str(relative))
        for name in copied:
            manifest.append({'hostname': hostname, 'checked_at': record.get('checked_at', ''),
                             'file': name, 'sha256': digest(target / name)})
        exported.append(hostname)
    if manifest:
        with (out / 'manifest.csv').open('w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['hostname', 'checked_at', 'file', 'sha256'])
            writer.writeheader()
            writer.writerows(manifest)
    return exported, missing


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--hosts', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--force', action='store_true',
                        help='write into a non-empty directory, which may overwrite completed work')
    args = parser.parse_args()
    if args.out.exists() and any(args.out.iterdir()) and not args.force:
        sys.exit(f'[!] {args.out} is not empty; pass --force only if no annotation there is finished')
    state = OUT / 'latest.json'
    if not state.exists():
        sys.exit(f'[!] {state} does not exist; nothing has been captured yet')
    latest = json.loads(state.read_text(encoding='utf-8'))
    args.out.mkdir(parents=True, exist_ok=True)
    exported, missing = export(read_hosts(args.hosts), latest, args.out)
    print(f'[i] {len(exported)} bundle(s) written to {args.out}, withholding {", ".join(BLINDED_FIELDS)}')
    if missing:
        print(f'[?] {len(missing)} host(s) have NO capture yet and were not exported; they are not '
              f'evidence of absence and must not be annotated from this bundle: ' + ', '.join(missing))


if __name__ == '__main__':
    main()
