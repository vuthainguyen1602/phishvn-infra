"""Conservative, offline evidence policy. A feed report is not a verified outcome.

Evidence is matched at its recorded URL/hostname scope. Never expand it to a
registrable domain, sibling host, or an unobserved time interval.
"""
from __future__ import annotations

import csv
import io
import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

POLICY_VERSION = '2.0.0'


def observable(value: str) -> tuple[str, str]:
    """Return an exact normalized host and conservative URL key; reject malformed values."""
    value = str(value).strip()
    if not value or any(c.isspace() for c in value):
        return '', ''
    try:
        explicit = '://' in value
        parsed = urlsplit(value if explicit else '//' + value)
        if explicit and parsed.scheme.lower() not in {'http', 'https'}:
            return '', ''
        host = (parsed.hostname or '').rstrip('.').encode('idna').decode('ascii').lower()
        if not host:
            return '', ''
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or '.' not in host or not all(
                    re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                    for part in host.split('.')):
                return '', ''
        port = parsed.port  # validates malformed ports
        netloc = '[' + host + ']' if ':' in host else host
        if port is not None:
            netloc += ':' + str(port)
        # Userinfo is significant; never strip it into a different URL's identity.
        if '@' in parsed.netloc:
            netloc = parsed.netloc.rsplit('@', 1)[0] + '@' + netloc
        url = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or '/', parsed.query, '')) if explicit else ''
        return host, url
    except (ValueError, UnicodeError):
        return '', ''


# Explicit schemas only. Seen sets are deduplication state, not evidence records.
FEEDS = (
    ('openphish', 'data/raw/openphish/feed.csv', 'url', 'scraped_at', 'url'),
    ('tinnhiemmang', 'data/raw/tinnhiemmang/blacklist_hist.csv', 'domain', 'detected_date', 'hostname'),
    ('chongluadao', 'data/raw/chongluadao_live/detections.csv', 'domain', 'first_detected', 'hostname'),
    ('vn_phishing_live', 'data/raw/vn_phishing_live/detections.csv', 'domain', 'first_detected', 'hostname'),
)


def feed_evidence(root: Path):
    by_host = defaultdict(list)
    manifest = {}
    for source, relative, column, time_column, scope in FEEDS:
        path = root / relative
        if not path.exists():
            manifest[relative] = {'available': False}
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        manifest[relative] = {'available': True, 'sha256': digest, 'bytes': len(data)}
        with io.StringIO(data.decode('utf-8-sig'), newline='') as stream:
            reader = csv.DictReader(stream)
            if column not in (reader.fieldnames or []):
                raise ValueError(f'{relative}: required evidence column {column} absent')
            for number, row in enumerate(reader, 2):
                host, url = observable(row.get(column, ''))
                if not host or (scope == 'url' and not url):
                    continue
                by_host[host].append({
                    'evidence_id': hashlib.sha256(f'{digest}:{number}'.encode()).hexdigest(),
                    'source': source, 'path': relative, 'row': number, 'file_sha256': digest,
                    'scope': scope, 'host': host, 'url': url,
                    'reported_at': row.get(time_column, ''),
                    'timestamp_field': time_column, 'source_status': row.get('status', ''),
                    'independently_verified': False,
                })
    return by_host, manifest


def classify(host, url, records, *, candidate=False, reputable=False):
    exact = [r for r in records if r['host'] == host and
             (r['scope'] == 'hostname' or (url and r['url'] == url))]
    related = [r for r in records if r['host'] == host and r not in exact]
    if not host:
        status, reason = 'unknown', 'invalid_observable'
    elif exact and reputable:
        status, reason = 'conflict', 'feed_report_and_reputation_signal_require_review'
    elif exact:
        status, reason = 'feed_reported', 'historical_exact_scope_report_not_current_confirmation'
    elif candidate:
        status, reason = 'candidate', 'collection_or_content_signal_only'
    else:
        status, reason = 'unknown', 'no_verified_outcome'
    return {'label_status': status, 'label': 'unknown', 'reason': reason,
            'evidence_ids': ';'.join(r['evidence_id'] for r in exact),
            'related_url_evidence_ids': ';'.join(r['evidence_id'] for r in related),
            'evidence_time_scope': 'recorded_report_only' if exact else '',
            'training_eligible': 0, 'policy_version': POLICY_VERSION}
