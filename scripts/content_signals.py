"""Explainable content triage; never produces a ground-truth binary label."""
import csv
import io
import re
import unicodedata
from urllib.parse import urlsplit

VERSION = 'content-triage-v1'


def fold(text):
    return ''.join(c for c in unicodedata.normalize('NFKD', str(text).lower().replace('đ','d')) if not unicodedata.combining(c))


def host(url):
    try:
        return (urlsplit(url if '://' in url else 'https://' + url).hostname or '').encode('idna').decode().lower().rstrip('.')
    except ValueError:
        return ''


def same_site(value, domain):
    return bool(value and domain) and (value == domain or value.endswith('.' + domain))


def registry(path, data=None):
    """Build identity references from this collection's trusted-domain ledger only."""
    records = {}
    generic = {'www','com','net','org','gov','edu','vn','dichvucong','portal','online','shop','bank','store','congty'}
    data = path.read_bytes() if data is None else data
    for row in csv.DictReader(io.StringIO(data.decode('utf-8-sig'), newline='')):
        domain = host(row['domain'])
        if not domain:
            continue
        # www is a registry alias here, never a dataset join key.
        domain = domain.removeprefix('www.')
        name = row.get('org_name','').strip()
        aliases = {p for p in domain.split('.') if len(p) >= 4 and p not in generic and not p.isdigit()}
        if len(name) >= 8:
            aliases.add(fold(name))
        if domain == 'dichvucong.gov.vn':
            aliases.update(['dich vu cong quoc gia', 'cong dich vu cong quoc gia'])
        if domain == 'bocongan.gov.vn':
            aliases.add('bo cong an')
        records[domain] = {'name': name, 'domains': [domain], 'aliases': sorted(aliases)}
    return list(records.values())


def mentions(text, alias):
    return bool(re.search(r'(?<!\w)' + re.escape(fold(alias)) + r'(?!\w)', fold(text)))


def analyze(capture, brands):
    out = {'policy_version': VERSION, 'content_status': 'unavailable', 'review_priority': 'retry',
           'suggested_label': '', 'verified': False, 'reasons': [], 'brand_matches': [],
           'sensitive_fields': [], 'form_actions': []}
    if capture.get('capture_status') != 'captured':
        return out
    frames = capture.get('frames', [])
    text = fold(' '.join(f.get('text','') for f in frames))
    if capture.get('http_status', 0) in {401,403,429,503} or any(s in text for s in ['verify you are human','checking your browser','just a moment','access denied']):
        out['content_status'] = 'blocked_or_challenge'
        return out
    if not text.strip() or (capture.get('http_status') or 0) >= 400:
        out['content_status'] = 'empty_or_error'
        return out
    mismatches, sensitive = [], []
    for frame in frames:
        identity = frame.get('title','') + ' ' + frame.get('identity','')
        frame_host = host(frame.get('url',''))
        for brand in brands:
            matched = [a for a in brand['aliases'] if mentions(identity, a)]
            if matched:
                known = any(same_site(frame_host, d) for d in brand['domains'])
                match = {'brand': brand['name'], 'matched_aliases': matched, 'frame_url': frame.get('url'),
                         'known_domain_match': known, 'reference_domains': brand['domains']}
                out['brand_matches'].append(match)
                if not known:
                    mismatches.append(match)
        for field in frame.get('inputs',[]):
            descriptor = fold(' '.join(str(v) for v in field.values()))
            kind = None
            if field.get('type') == 'password': kind = 'password'
            elif re.search(r'\botp\b|one-time-code|ma xac (?:thuc|nhan)', descriptor): kind = 'otp'
            elif re.search(r'cc-number|cc-csc|\bcvv\b|\bcvc\b|so the|card.?number', descriptor): kind = 'payment_card'
            if kind:
                sensitive.append({'kind': kind, 'frame_url': frame.get('url'), 'field': field})
        out['form_actions'].extend({'frame_url':frame.get('url'), **f} for f in frame.get('forms', []))
    transfer = bool(re.search(r'chuyen khoan|nop (?:phi|phat)|thanh toan|transfer money', text))
    out['sensitive_fields'] = sensitive
    out['content_status'] = 'captured_no_strong_signal'
    out['review_priority'] = 'normal'
    if mismatches:
        out['reasons'].append('brand_identity_on_domain_not_in_reference_registry')
        out['content_status'] = 'possible_impersonation'
        out['review_priority'] = 'medium'
        # Link sensitive inputs to the same frame that asserts the identity.
        same_frame = any(s['frame_url'] == m['frame_url'] for s in sensitive for m in mismatches)
        if same_frame or transfer:
            out['reasons'].append('sensitive_input_on_brand_frame' if same_frame else 'payment_language_requires_context_review')
            out['content_status'] = 'suspected_phishing'
            out['review_priority'] = 'high'
            out['suggested_label'] = 'phishing'
    if sensitive and not mismatches:
        out['reasons'].append('sensitive_inputs_without_unmatched_brand_identity')
    out['reasons'].append('registry_is_incomplete_authorization_requires_human_review')
    return out
