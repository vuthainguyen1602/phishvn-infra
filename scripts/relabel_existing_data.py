#!/usr/bin/env python3
"""Reclassify existing infrastructure captures and URL corpus offline, without deleting originals.

Outputs are observation-scoped evidence ledgers, not fabricated human adjudications.
The original labels survive as legacy_label. Only a scoped review may produce a
training outcome; today's feed/heuristic evidence cannot do so automatically.
"""
from __future__ import annotations
import csv
import hashlib
import json
import sys
import os
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
_HERE = os.path.dirname(os.path.abspath(__file__))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:
    ROOT = os.path.dirname(_HERE)
import label_policy
from label_policy import POLICY_VERSION, classify, feed_evidence, observable
from audit_capture_labels import load_allowlists, load_tranco

ROOT = Path(ROOT)
OUT = ROOT / 'data/processed/labels_v2'


def write_csv(path, fields, rows):
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(path)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    evidence, inputs = feed_evidence(ROOT)
    # Reputation is a review signal only, matched on the exact normalized host.
    reputation = load_allowlists() | load_tranco()
    evidence_rows = [r for records in evidence.values() for r in records]
    fields = ['evidence_id', 'source', 'path', 'row', 'file_sha256', 'scope', 'host', 'url',
              'reported_at', 'timestamp_field', 'source_status', 'independently_verified']
    write_csv(OUT / 'feed_evidence.csv', fields, evidence_rows)
    summary = {'policy_version': POLICY_VERSION, 'inputs': inputs, 'datasets': {},
               'interpretation': 'Reports retain their recorded scope and time; no automatic ground truth.'}
    queue = {}
    for name, relative, key, time_col in [
            ('host_infra', 'data/raw/host_infra/host_infra.csv', 'domain', 'captured_at'),
            ('dataset_url', 'data/processed/dataset_url.csv', 'url', 'collected_at')]:
        path = ROOT / relative
        if not path.exists():
            inputs[relative] = {'available': False}
            summary['datasets'][name] = {'available': False, 'reason': 'input absent'}
            continue
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        inputs[relative] = {'available': True, 'sha256': digest, 'bytes': len(raw)}
        with path.open(newline='', encoding='utf-8-sig') as stream:
            reader = csv.DictReader(stream)
            old_fields = reader.fieldnames
            output = []
            for number, row in enumerate(reader, 2):
                host, url = observable(row.get(key, ''))
                legacy = row.pop('label', '')
                candidate = legacy in {'phish', 'phishing', 'candidate'}
                decision = classify(host, url, evidence.get(host, []),
                                    candidate=candidate, reputable=host in reputation)
                rid = hashlib.sha256(f'{digest}:{number}'.encode()).hexdigest()
                row.update(legacy_label=legacy, observation_id=rid, hostname_key=host,
                           url_key=url, observed_at=row.get(time_col, ''),
                           reputation_signal=int(host in reputation), **decision)
                output.append(row)
                # Candidate and conflict review spans all collected hosts, including CT controls.
                if host:
                    item = queue.setdefault(host, {'hostname': host, 'observations': 0,
                        'legacy_labels': set(), 'statuses': set(), 'evidence_ids': set()})
                    item['observations'] += 1
                    item['legacy_labels'].add(legacy)
                    item['statuses'].add(decision['label_status'])
                    item['evidence_ids'].update(filter(None, decision['evidence_ids'].split(';')))
        extra = ['legacy_label', 'observation_id', 'hostname_key', 'url_key', 'observed_at',
                 'reputation_signal', 'label_status', 'reason', 'evidence_ids',
                 'related_url_evidence_ids', 'evidence_time_scope', 'training_eligible', 'policy_version']
        write_csv(OUT / (name + '.csv'), old_fields + extra, output)
        counts = Counter(r['label_status'] for r in output)
        transition = Counter(r['legacy_label'] + ' -> ' + r['label_status'] for r in output)
        summary['datasets'][name] = {'rows': len(output), 'hosts': len({r['hostname_key'] for r in output}),
                                    'statuses': dict(counts), 'transitions': dict(transition),
                                    'training_eligible': sum(r['training_eligible'] for r in output)}
    review = []
    for host, item in sorted(queue.items()):
        for field in ['legacy_labels', 'statuses', 'evidence_ids']:
            item[field] = ';'.join(sorted(item[field]))
        item.update(annotator_a_id='', annotator_b_id='', annotator_a='', annotator_b='',
                    adjudicated_label='', evidence_url='', observed_from='', observed_until='',
                    evidence_path='', evidence_sha256='', rationale='')
        review.append(item)
    if review:
        write_csv(OUT / 'review_queue.csv', list(review[0]), review)
    # Record reputation inputs as well: their absence affects conflict flags, not truth labels.
    summary['reputation_set_sha256'] = hashlib.sha256('\n'.join(sorted(reputation)).encode()).hexdigest()
    (OUT / 'reputation_snapshot.txt').write_text('\n'.join(sorted(reputation)) + '\n')
    summary['generator_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    summary['policy_sha256'] = hashlib.sha256(Path(label_policy.__file__).read_bytes()).hexdigest()
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps(summary['datasets'], indent=2))


if __name__ == '__main__':
    main()
