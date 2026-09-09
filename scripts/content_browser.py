"""Networkless browser worker. GET responses arrive through the supervisor's pipe."""
import base64
import json
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright


def emit(value):
    print(json.dumps(value), flush=True)


def main():
    job = json.loads(sys.stdin.readline())
    requests = []
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path='/usr/bin/chromium', headless=True,
            args=['--disable-dev-shm-usage', '--disable-background-networking'])
        context = browser.new_context(accept_downloads=False, service_workers='block',
            viewport={'width': 1365, 'height': 900}, locale='vi-VN')
        context.set_default_timeout(5000)
        def intercept(route):
            req = route.request
            if req.method != 'GET' or req.resource_type in {'media', 'websocket', 'eventsource'}:
                requests.append({'url': req.url, 'blocked': 'method_or_resource'})
                return route.abort()
            emit({'type': 'fetch', 'url': req.url, 'resource': req.resource_type})
            response = json.loads(sys.stdin.readline())
            requests.append({k: response[k] for k in ('url','status','error','ip') if k in response})
            if response.get('error'):
                return route.abort()
            route.fulfill(status=response['status'], headers=response['headers'],
                          body=base64.b64decode(response['body']))
        context.route('**/*', intercept)
        page = context.new_page()
        page.on('download', lambda download: download.cancel())
        page.on('dialog', lambda dialog: dialog.dismiss())
        context.on('page', lambda popup: popup.close() if popup != page else None)
        result = {'url': job['url'], 'capture_status': 'error'}
        try:
            resp = page.goto(job['url'], wait_until='domcontentloaded', timeout=30000)
            page.wait_for_timeout(1500)
            result.update(final_url=page.url, http_status=resp.status if resp else None)
            # No clicks, typing, form submissions, or credential values are collected.
            frames = []
            for frame in page.frames[:10]:
                try:
                    frames.append(frame.evaluate('''() => {
                      const visible = e => !!(e.getClientRects().length) && getComputedStyle(e).visibility !== 'hidden';
                      return {url: location.href, title: document.title,
                        text: (document.body?.innerText || '').slice(0,100000),
                        identity: [...document.querySelectorAll('h1,h2,header img,img[alt]')].filter(visible).slice(0,80).map(e => e.alt || e.innerText).join(' ').slice(0,8000),
                        inputs: [...document.querySelectorAll('input')].filter(visible).slice(0,100).map(e => ({type:e.type,name:e.name,id:e.id,placeholder:e.placeholder,autocomplete:e.autocomplete,label:[...(e.labels||[])].map(l=>l.innerText).join(' ')})),
                        forms: [...document.forms].slice(0,40).map(f => ({action:f.action,method:f.method})),
                        links: [...document.querySelectorAll('a[href]')].filter(visible).slice(0,150).map(a=>({text:a.innerText.slice(0,200),url:a.href}))};
                    }'''))
                except Exception:
                    frames.append({'url': frame.url, 'error': 'frame_unavailable'})
            Path('/out/page.html').write_text(page.content(), encoding='utf-8')
            page.screenshot(path='/out/page.png', full_page=False, timeout=10000)
            result.update(capture_status='captured', frames=frames,
                          html_file='page.html', screenshot_file='page.png')
        except Exception as exc:
            result['error'] = str(exc)[:1500]
        result['requests'] = requests
        context.close()
        browser.close()
    emit({'type': 'result', 'result': result})


if __name__ == '__main__':
    main()
