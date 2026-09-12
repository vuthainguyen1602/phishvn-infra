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
EXTERNAL = ROOT / 'data/processed/live_content/external_evidence.csv'
# The urlscan row names the brand token that found the host. That token is a guess at the very
# identity the reviewer is asked to establish, so it is withheld exactly like `source`.
EXTERNAL_WITHHELD = ('brand',)


def blind(evidence):
    """Return a copy of one evidence record with the withheld fields gone.

    Non-destructive: callers hold the original, and a mutating version of this silently
    corrupted the stored capture the first time it was written.
    """
    return {k: v for k, v in evidence.items() if k not in BLINDED_FIELDS}


def external_index(path=EXTERNAL):
    """Time-matched urlscan artifacts by hostname, or {} when the index has not been built."""
    if not path.exists():
        return {}
    return {r['hostname']: r for r in csv.DictReader(path.open(encoding='utf-8', newline=''))}


def export_external(hostname, row, out, root=ROOT):
    """Bundle a urlscan artifact. Unlike a local capture this one was taken when the host was
    found, so it is admissible for a verdict about the observation, not only about today."""
    target = out / hostname.replace('/', '_')
    target.mkdir(parents=True, exist_ok=True)
    record = {'hostname': hostname, 'checked_at': row.get('scan_time', ''),
              'evidence_source': row.get('evidence_source', ''),
              'scan_uuid': row.get('scan_uuid', ''), 'scan_url': row.get('scan_url', ''),
              'lag_days': row.get('lag_days', ''),
              'scope': 'third_party_scan_at_discovery_time',
              'artifact_sha256': {}, 'limitations': [
                  'Captured by urlscan.io, not by this collection; re-openable at scan_url.',
                  'A blank lag_days means no detection time was recorded, so closeness to the '
                  'observation is unproven and must not be assumed.']}
    copied = []
    for key, name in (('dom_path', 'page.html'), ('shot_path', 'page.png')):
        relative = (row.get(key) or '').strip()
        if not relative:
            continue
        source = root / relative
        if not source.is_file():
            continue
        shutil.copy2(source, target / name)
        record['artifact_sha256'][name] = row.get(key.replace('_path', '_sha256'), '')
        copied.append(name)
    if not copied:
        return None
    (target / 'evidence.json').write_text(json.dumps(record, indent=2, sort_keys=True),
                                          encoding='utf-8')
    return copied + ['evidence.json']


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


def export(hosts, latest, out, content_root=OUT, external=None, prefer_external=True,
           external_root=ROOT):
    """Write one blinded bundle per host. Returns (exported, missing).

    A host with no capture yet is REPORTED, never quietly skipped: an annotator handed a short
    bundle would otherwise read the gap as "nothing was found here", which is a verdict.
    """
    exported, missing, manifest = [], [], []
    external = {} if external is None else external
    for hostname in hosts:
        # A urlscan artifact is preferred when one exists: it was taken at discovery, while a
        # local capture was taken whenever the queue reached the host.
        row = external.get(hostname)
        if prefer_external and row:
            copied = export_external(hostname, row, out, root=external_root)
            if copied:
                target = out / hostname.replace('/', '_')
                for name in copied:
                    manifest.append({'hostname': hostname, 'checked_at': row.get('scan_time', ''),
                                     'file': name, 'sha256': digest(target / name)})
                exported.append(hostname)
                continue
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
    parser.add_argument('--external', type=Path, default=EXTERNAL)
    parser.add_argument('--local-only', action='store_true',
                        help='ignore urlscan artifacts and bundle only this collection\'s captures')
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
    external = external_index(args.external)
    exported, missing = export(read_hosts(args.hosts), latest, args.out, external=external,
                               prefer_external=not args.local_only)
    withheld = ', '.join(BLINDED_FIELDS + EXTERNAL_WITHHELD)
    print(f'[i] {len(exported)} bundle(s) written to {args.out}, withholding {withheld}')
    if external:
        print(f'[i] {len(external)} host(s) have a time-matched urlscan artifact available')
    if missing:
        print(f'[?] {len(missing)} host(s) have NO capture yet and were not exported; they are not '
              f'evidence of absence and must not be annotated from this bundle: ' + ', '.join(missing))


if __name__ == '__main__':
    main()
