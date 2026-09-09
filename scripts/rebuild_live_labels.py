#!/usr/bin/env python3
"""Label this live collection only. No published corpus or external audit inputs.

Sources and confidence tiers are provenance, not independent verification. Keeps
all original capture rows and never infers a binary outcome from name/CT signals.
"""
import csv
import hashlib
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    from _path import ROOT, add_script_dirs
    add_script_dirs()
except ImportError:
    ROOT = os.path.dirname(_HERE)
from label_policy import observable
from psl import registered_domain

ROOT = Path(ROOT)
VERSION = 'live-source-tiers-2026-09-09'
RAW = 'data/raw/host_infra/host_infra.csv'
# Only detection ledgers belonging to this same live collection.
SOURCES = {'chongluadao_live': ('phishing', 'bronze'),
           'vn_phishing_live': ('phishing', 'bronze'),
           'tinnhiem_benign': ('benign', 'gold')}
OUT = ROOT / 'data/processed/live_labels'

FREE_HOSTING_SUFFIXES = {
    'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app', 'web.app', 'firebaseapp.com',
    'amplifyapp.com', 'webflow.io', 'weebly.com', 'wixsite.com', 'blogspot.com', 'github.io',
    'duckdns.org', 'ddns.net', 'glitch.me', 'repl.co'
}
SUSPICIOUS_TLDS = {'site', 'shop', 'info', 'top', 'xyz', 'live', 'vip', 'click', 'online', 'icu', 'club'}
SECTOR_TOKENS = {
    'bank': {
        'vietcombank', 'techcombank', 'vietinbank', 'agribank', 'bidv', 'sacombank', 'vpbank',
        'hdbank', 'lpbank', 'lienvietpostbank', 'namabank', 'vietabank', 'pvcombank', 'shinhanbank',
        'mbbank', 'baovietbank', 'bacabank', 'kienlongbank', 'saigonbank', 'dongabank', 'coopbank',
        'seabank', 'msbbank', 'ocbbank', 'vibbank', 'shbbank', 'abbank', 'ncbbank', 'bvbank',
        'vietbank', 'scbbank', 'eximbank', 'pgbank', 'timobank', 'cakebyvpbank', 'mcredit',
        'fecredit', 'homecredit', 'vcbdigibank', 'smartbanking', 'vaynhanh', 'vaytienonline',
        'vaytinchap', 'tracuucic', 'nganhang'
    },
    'gov': {
        'vneid', 'dichvucong', 'dichvucongquocgia', 'dancuquocgia', 'dinhdanhdientu',
        'cancuoccongdan', 'cancuoc', 'bocongan', 'conganxaphuong', 'conganhanoi', 'congantphcm',
        'canhsatgiaothong', 'chinhphu', 'vienkiemsat', 'lenhbat', 'toaanhanoi', 'toaanhcm',
        'thuedientu', 'tongcucthue', 'etaxmobile', 'hoadondientu', 'tracuuthue', 'cucthue',
        'hoanthuetncn', 'gplx', 'tracuugplx'
    },
    'ecommerce': {
        'ctvshopee', 'vnshopee', 'shopeevn', 'shopeevip', 'shopeemall', 'shopeereward',
        'lazadavn', 'lazadamall', 'ctvlazada', 'tuyendunglazada', 'tikivn', 'tikivip', 'tikictv',
        'sendovn', 'ctvsendo', 'sendomall', 'tiktokshopvn', 'shopaeon', 'aeonmall', 'aeshopvn',
        'giaohangnhanh', 'ghtk', 'ghnexpress', 'ghnvn', 'dienmayxanh', 'thegioididong', 'shopee',
        'lazada', 'tiki', 'sendo', 'tiktokshop'
    },
    'payment': {'momo', 'zalopay', 'vnpay', 'viettelmoney', 'viettelpay', 'shopeepay', 'napas247'},
    'telecom': {'viettel', 'vinaphone', 'mobifone', 'vnpt', 'fptshop', 'fpttelecom', 'chuanhoathuebao', 'khoathuebao', 'nangcapsim', 'sim5g'},
    'delivery': {'viettelpost', 'vnpost', 'giaohangtietkiem', 'giaohangnhanh', 'ghtk', 'ghnexpress', 'ghnvn'},
}
OFFICIAL_DOMAINS = {
    'shopee.vn', 'lazada.vn', 'tiki.vn', 'sendo.vn', 'aeon.com.vn', 'aeon.vn', 'giaohangnhanh.vn',
    'ghn.vn', 'ghn.tech', 'giaohangtietkiem.vn', 'vietcombank.com.vn', 'techcombank.com.vn',
    'vietinbank.vn', 'agribank.com.vn', 'bidv.com.vn', 'sacombank.com.vn', 'vpbank.com.vn',
    'mbbank.com.vn', 'tpbank.vn', 'acb.com.vn', 'vneid.gov.vn', 'bocongan.gov.vn',
    'dichvucong.gov.vn', 'dancuquocgia.gov.vn', 'chinhphu.vn', 'gdt.gov.vn',
    'baohiemxahoi.gov.vn', 'viettel.vn', 'viettel.com.vn', 'vinaphone.com.vn', 'mobifone.vn',
    'vnpt.vn', 'vnpt.com.vn', 'vnpost.vn', 'viettelpost.com.vn', 'fptshop.com.vn', 'fpt.vn',
    'zalopay.vn', 'vnpay.vn', 'viettelmoney.vn', 'shopeepay.vn'
}


def compact(value):
    return re.sub(r'[^a-z0-9]+', '', str(value).lower())


def token_hits(host):
    compact_host = compact(host)
    hits = []
    sectors = []
    for sector, tokens in SECTOR_TOKENS.items():
        matched = sorted(t for t in tokens if compact(t) in compact_host)
        if matched:
            sectors.append(sector)
            hits.extend(f'{sector}:{t}' for t in matched[:5])
    return sectors, hits[:20]


def load_official_domains():
    domains = set(OFFICIAL_DOMAINS)
    token_path = ROOT / 'data/processed/brand_tokens.json'
    if token_path.exists():
        try:
            for token in json.loads(token_path.read_text()).get('tokens', []):
                domains.update(str(d).lower().removeprefix('www.') for d in token.get('domains', []) if d)
        except (OSError, ValueError, TypeError):
            pass
    trusted_path = ROOT / 'data/raw/tinnhiem_benign/detections.csv'
    if trusted_path.exists():
        try:
            for row in csv.DictReader(io.StringIO(trusted_path.read_text(encoding='utf-8-sig'), newline='')):
                host, _ = observable(row.get('domain', ''))
                if host:
                    domains.add(host.removeprefix('www.'))
        except OSError:
            pass
    return domains


def official_host(host, official_domains):
    return any(host == domain or host.endswith('.' + domain) for domain in official_domains)


def candidate_risk(row, label, host, inspection, official_domains):
    """Rank unresolved rows for review. This is triage only; it never changes `label`."""
    if label != 'unknown' or not host:
        return 0, '', '', '', '', ''
    score = 0
    reasons = []
    source = row.get('source', '')
    if source == 'urlscan_brands':
        score += 35; reasons.append('urlscan_brand_candidate')
    elif source == 'ct_brands':
        score += 30; reasons.append('ct_brand_candidate')
    elif source == 'ct_benign_vn':
        score += 5; reasons.append('vn_ct_background')
    sectors, hits = token_hits(host)
    if sectors and not official_host(host, official_domains):
        score += 25; reasons.append('brand_or_institution_token_on_unconfirmed_host')
    reg = row.get('registered_domain') or registered_domain(host)
    if any(reg == s or reg.endswith('.' + s) for s in FREE_HOSTING_SUFFIXES):
        score += 15; reasons.append('free_hosting_or_tenant_platform')
    tld = host.rsplit('.', 1)[-1] if '.' in host else ''
    if tld in SUSPICIOUS_TLDS:
        score += 8; reasons.append('abuse_prone_tld')
    signals = inspection.get('analysis', {}) if inspection else {}
    status = signals.get('content_status', '')
    if status == 'suspected_phishing':
        score += 50; reasons.append('content_suspected_phishing')
    elif status == 'possible_impersonation':
        score += 35; reasons.append('content_possible_impersonation')
    elif status == 'blocked_or_challenge':
        score += 10; reasons.append('content_blocked_or_challenge')
    elif status == 'captured_no_strong_signal':
        score += 3; reasons.append('content_captured_no_strong_signal')
    score = min(score, 100)
    level = 'high' if score >= 70 else 'medium' if score >= 40 else 'low' if score >= 15 else 'background'
    priority = 'high' if level == 'high' else 'medium' if level == 'medium' else 'normal' if level == 'low' else 'backlog'
    return score, level, priority, ';'.join(reasons), ';'.join(sectors), ';'.join(hits)


def snapshot(path):
    data = path.read_bytes()
    rows = list(csv.DictReader(io.StringIO(data.decode('utf-8-sig'), newline='')))
    return rows, {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'rows': len(rows)}


def decision(source, host, reports):
    labels = {r['label'] for r in reports}
    inherited, tier = SOURCES.get(source, ('unknown', 'unverified'))
    if inherited != 'unknown':
        labels.add(inherited)
    if not host:
        return 'unknown', 'unverified', 'invalid_observable'
    if len(labels) > 1:
        return 'unknown', 'conflict', 'conflicting_source_reports'
    if inherited != 'unknown':
        return inherited, tier, 'source_inherited'
    if labels:
        label = next(iter(labels))
        tier = 'gold' if label == 'benign' else 'bronze'
        return label, tier, 'exact_host_live_report'
    return 'unknown', 'unverified', 'candidate_only'


def write(path, rows, fields):
    temp = path.with_suffix('.tmp')
    with temp.open('w', newline='', encoding='utf-8') as stream:
        w = csv.DictWriter(stream, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    temp.replace(path)


def main():
    captures, raw_meta = snapshot(ROOT / RAW)
    if not captures:
        raise SystemExit('Live capture input is empty; existing outputs were not replaced.')
    manifest = {RAW: raw_meta}
    content_path = ROOT / 'data/processed/live_content/latest.json'
    official_domains = load_official_domains()
    content = {}
    if content_path.exists():
        content_bytes = content_path.read_bytes()
        content = json.loads(content_bytes)
        manifest[str(content_path.relative_to(ROOT))] = {
            'sha256': hashlib.sha256(content_bytes).hexdigest(),
            'purpose': 'current_content_triage_only_not_label_evidence'}
    by_host = defaultdict(list)
    evidence = []
    for source, (label, tier) in SOURCES.items():
        relative = 'data/raw/' + source + '/detections.csv'
        path = ROOT / relative
        if not path.exists():
            manifest[relative] = {'available': False}
            continue
        rows, meta = snapshot(path)
        manifest[relative] = meta
        for number, row in enumerate(rows, 2):
            host, _ = observable(row.get('domain', ''))
            if not host:
                continue
            ev = dict(evidence_id=hashlib.sha256(f"{meta['sha256']}:{number}".encode()).hexdigest(),
                      hostname=host, source=source, label=label, tier=tier,
                      reported_at=row.get('first_detected') or row.get('first_captured', ''),
                      source_path=relative, source_row=number, source_sha256=meta['sha256'])
            evidence.append(ev)
            by_host[host].append(ev)
    output = []
    for number, row in enumerate(captures, 2):
        row = row.copy()
        host, _ = observable(row.get('domain', ''))
        reports = by_host.get(host, [])
        label, tier, basis = decision(row.get('source', ''), host, reports)
        inspection = content.get(host, {})
        signals = inspection.get('analysis', {})
        risk_score, risk_level, risk_priority, risk_reasons, sectors, hits = candidate_risk(row, label, host, inspection, official_domains)
        row.update(legacy_label=row.get('label', ''), label=label, tier=tier,
                   label_basis=basis, hostname_key=host,
                   label_status='conflict' if tier == 'conflict' else
                       'candidate' if label == 'unknown' else 'source_labelled',
                   independently_verified=0,
                   evidence_ids=';'.join(r['evidence_id'] for r in reports),
                   observation_row=number, policy_version=VERSION,
                   label_time_scope='source_report_only_not_current_page_confirmation',
                   binary_label_usable=int(label in {'phishing', 'benign'}),
                   content_status=signals.get('content_status', 'not_checked'),
                   content_review_priority=signals.get('review_priority', ''),
                   content_checked_at=inspection.get('checked_at', ''),
                   content_evidence_path=inspection.get('evidence_path', ''),
                   content_scope='current_root_page_only_not_historical_label',
                   candidate_risk_score=risk_score,
                   candidate_risk_level=risk_level,
                   candidate_review_priority=risk_priority,
                   candidate_risk_reasons=risk_reasons,
                   impersonation_sector=sectors,
                   brand_token_hits=hits)
        output.append(row)
    OUT.mkdir(parents=True, exist_ok=True)
    fields = list(output[0])
    write(OUT / 'observations.csv', output, fields)
    write(OUT / 'labelled.csv', [r for r in output if r['binary_label_usable']], fields)
    unresolved = [r for r in output if not r['binary_label_usable']]
    write(OUT / 'review_queue.csv', unresolved, fields)
    review_candidates = sorted(unresolved, key=lambda r: (-int(r['candidate_risk_score']), r['source'], r['hostname_key']))
    for rank, row in enumerate(review_candidates, 1):
        row['review_rank'] = rank
    candidate_fields = fields + ['review_rank']
    write(OUT / 'review_candidates.csv', review_candidates, candidate_fields)
    if evidence:
        write(OUT / 'evidence.csv', evidence, list(evidence[0]))
    summary = dict(dataset='independent_live_collection', policy_version=VERSION,
        inputs=manifest, rows=len(output), distinct_hosts=len({r['hostname_key'] for r in output if r['hostname_key']}),
        labels=dict(Counter(r['label'] for r in output)), tiers=dict(Counter(r['tier'] for r in output)),
        labelled_rows=sum(r['binary_label_usable'] for r in output),
        content_status_observations=dict(Counter(r['content_status'] for r in output)),
        candidate_risk_levels=dict(Counter(r['candidate_risk_level'] for r in output if r['label'] == 'unknown')),
        candidate_review_priorities=dict(Counter(r['candidate_review_priority'] for r in output if r['label'] == 'unknown')),
        impersonation_sectors=dict(Counter(sector for r in output if r['label'] == 'unknown' for sector in r['impersonation_sector'].split(';') if sector)),
        note='Counts are observations, not unique domains. All binary labels are source-derived; candidate risk fields are triage signals only, not labels.',
        code_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    temp = OUT / 'summary.json.tmp'
    temp.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    temp.replace(OUT / 'summary.json')
    print(json.dumps({k: summary[k] for k in ['rows','distinct_hosts','labels','tiers','labelled_rows']}, indent=2))


if __name__ == '__main__':
    main()
