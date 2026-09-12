#!/usr/bin/env python3
"""How much of each evidence layer actually exists, reported against its own denominator.

A corpus that quotes one size and then analyses whatever subset happens to have DNS, or TLS, or a
page, is reporting a different population in every section without saying so. This writes the
table that makes the subsetting visible: one row per evidence layer, the share of scans on which
that layer was observed, split by class, and again by hosting stratum where the layer belongs to
whoever owns the apex rather than to whoever put the page there.

TWO RULES IT ENFORCES. A layer that was never fetched is missing, not negative: absence is written
as absence and never folded into a zero. And a provider-owned layer is reported for the
independently registered stratum only, because a tenant page's A record and registrar describe the
platform, so mixing the strata would measure the provider's completeness.

RUN:
  python3 scripts/evidence_coverage.py
  python3 scripts/evidence_coverage.py --latex   # also write the LaTeX table
"""
import argparse
import csv
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
ROOT = _HERE.parents[3]
sys.path.insert(0, str(ROOT / 'scripts/lib'))
OBS = ROOT / 'data/processed/live_labels/observations.csv'
EXTERNAL = ROOT / 'data/processed/live_content/external_evidence.csv'
OUT = ROOT / 'data/processed/live_labels/evidence_coverage.csv'

# (layer, scope, predicate). `scope` says which stratum the layer may be reported over:
# 'all' for evidence the tenant owns, 'operator' for registration and transport, which describe
# the platform on a tenant page and would otherwise measure the provider.
LAYERS = [
    ('DNS A record', 'operator', lambda r, e: bool((r.get('a_records') or '').strip())),
    ('Nameservers', 'operator', lambda r, e: (r.get('ns_count') or '0') not in ('', '0')),
    ('MX', 'operator', lambda r, e: (r.get('mx_count') or '0') not in ('', '0')),
    ('WHOIS creation date', 'operator', lambda r, e: bool((r.get('whois_created') or '').strip())),
    ('Registrar', 'operator', lambda r, e: bool((r.get('registrar') or '').strip())),
    ('TLS certificate', 'operator', lambda r, e: (r.get('tls_present') or '') == '1'),
    ('TLS chain verified', 'operator', lambda r, e: (r.get('tls_verified') or '') == '1'),
    ('Page captured (this collection)', 'all',
     lambda r, e: (r.get('content_status') or 'not_checked') not in ('', 'not_checked')),
    ('Page rendered a document', 'all',
     lambda r, e: (r.get('content_status') or '') in
     ('captured_no_strong_signal', 'possible_impersonation', 'suspected_phishing')),
    ('Artifact taken at discovery (urlscan)', 'all', lambda r, e: r.get('hostname_key') in e),
    ('Independently verified by a human', 'all',
     lambda r, e: (r.get('independently_verified') or '0') == '1'),
]


def load_external(path=EXTERNAL):
    if not path.exists():
        return set()
    return {r['hostname'] for r in csv.DictReader(path.open(encoding='utf-8', newline=''))}


def coverage(rows, external, layers=LAYERS):
    """One record per (layer, class). `denominator` is the population the layer may be read over,
    which is smaller than the corpus for provider-owned layers."""
    classes = ['phishing', 'benign', 'unknown']
    out = []
    for layer, scope, present in layers:
        for label in classes:
            pool = [r for r in rows if r.get('label') == label
                    and (scope == 'all' or r.get('infra_scope') == 'operator')]
            if not pool:
                out.append({'layer': layer, 'scope': scope, 'class': label, 'denominator': 0,
                            'observed': 0, 'availability': ''})
                continue
            observed = sum(1 for r in pool if present(r, external))
            out.append({'layer': layer, 'scope': scope, 'class': label,
                        'denominator': len(pool), 'observed': observed,
                        'availability': round(100 * observed / len(pool), 1)})
    return out


def render(records):
    lines, seen = [], None
    width = max(len(r['layer']) for r in records)
    lines.append('%-*s  %-9s %s' % (width, 'evidence layer', 'scope',
                                    ' '.join('%20s' % c for c in ['phishing', 'benign', 'unknown'])))
    by_layer = {}
    for r in records:
        by_layer.setdefault((r['layer'], r['scope']), {})[r['class']] = r
    for (layer, scope), cells in by_layer.items():
        row = []
        for label in ['phishing', 'benign', 'unknown']:
            c = cells.get(label)
            row.append('%20s' % ('-' if not c or not c['denominator']
                                 else f"{c['availability']}% ({c['observed']}/{c['denominator']})"))
        lines.append('%-*s  %-9s %s' % (width, layer, scope, ' '.join(row)))
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--observations', type=Path, default=OBS)
    parser.add_argument('--out', type=Path, default=OUT)
    args = parser.parse_args()
    csv.field_size_limit(10 ** 9)
    if not args.observations.exists():
        sys.exit(f'[!] {args.observations} does not exist; run the live label rebuild first')
    rows = list(csv.DictReader(args.observations.open(encoding='utf-8', newline='')))
    if rows and 'infra_scope' not in rows[0]:
        sys.exit('[!] observations.csv predates the hosting stratum; rebuild the live labels first')
    records = coverage(rows, load_external())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['layer', 'scope', 'class', 'denominator',
                                               'observed', 'availability'])
        writer.writeheader()
        writer.writerows(records)
    print(render(records))
    print()
    print(f'[i] {len(rows)} scans; table written to {args.out}')
    print('[i] scope=operator rows exclude platform-hosted names, whose registration and transport '
          'belong to the provider')


if __name__ == '__main__':
    main()
