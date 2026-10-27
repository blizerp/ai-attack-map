"""Durable discovery, full-report review, backfill, and public collection health.

No credentials or full article bodies are saved in the published audit files.
"""
import concurrent.futures
import hashlib
import html
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urljoin

import feedparser
import requests
import trafilatura

FEEDS = {
    'BleepingComputer': 'https://www.bleepingcomputer.com/feed/',
    'The Hacker News': 'https://feeds.feedburner.com/TheHackersNews',
    'The Record': 'https://therecord.media/feed',
    'SecurityWeek': 'https://www.securityweek.com/feed/',
    'Dark Reading': 'https://www.darkreading.com/rss.xml',
    'HIPAA Journal': 'https://www.hipaajournal.com/feed/',
    'CERT-FR': 'https://cert.cyber.gouv.fr/alerte/feed/',
    'Wiz Research': 'https://www.wiz.io/blog/rss.xml',
}
ARCHIVES = {k: FEEDS[k] for k in ['SecurityWeek', 'HIPAA Journal']}
UA = 'ai-attack-map/2.0 (+https://github.com/blizerp/ai-attack-map)'

def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def safe_error(exc):
    # SDK exception messages may contain fragments of credentials.
    code = getattr(exc, 'status_code', None)
    return f'{type(exc).__name__}' + (f' (HTTP {code})' if code else '')

def public_url(url):
    p = urlparse(url)
    if p.scheme not in {'https', 'http'} or not p.hostname or p.username or p.password:
        return False
    host = p.hostname.lower()
    if host == 'localhost' or '.' not in host or host.endswith(('.local', '.internal')):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True

def download(url):
    # Bound reads, timeouts, redirects; never send credentials to article sites.
    for _ in range(5):
        if not public_url(url):
            raise ValueError('Non-public article URL')
        with requests.get(url, headers={'User-Agent': UA}, timeout=(8, 20),
                          allow_redirects=False, stream=True) as r:
            if r.is_redirect:
                url = urljoin(url, r.headers['Location'])
                continue
            r.raise_for_status()
            body = bytearray()
            for chunk in r.iter_content(65536):
                body.extend(chunk)
                if len(body) > 4_000_000:
                    raise ValueError('Document exceeds size limit')
            return bytes(body), url
    raise ValueError('Too many redirects')

def day(entry):
    t = entry.get('published_parsed') or entry.get('updated_parsed')
    return datetime(*t[:6]).date().isoformat() if t else ''

def text_of(markup):
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html.unescape(markup or ''))).strip()

def read_feed(u, name, url, cutoff):
    raw, _ = download(url)
    feed = feedparser.parse(raw)
    if not feed.entries:
        raise ValueError('Feed returned no entries')
    result = []
    dates = []
    for e in feed.entries:
        date = day(e)
        if date:
            dates.append(date)
        if date and date < cutoff:
            continue
        title, link = text_of(e.get('title', '')), e.get('link', '')
        content = max([e.get('summary', '')] + [c.get('value', '') for c in e.get('content', [])], key=len)
        body = text_of(content)
        if not public_url(link) or not u.candidate_text(title + ' ' + body):
            continue
        result.append(dict(id=u.make_id(link, title), title=title, url=link,
                           date=date, source=name, text=body[:18000],
                           published_at=(datetime(*(e.get('updated_parsed') or e.get('published_parsed'))[:6], tzinfo=timezone.utc).isoformat()
                                         if (e.get('updated_parsed') or e.get('published_parsed')) else None)))
    return result, dates, len(feed.entries)

def read_article(item):
    body = item.get('text', '')
    if len(body) >= 1800:
        return body[:18000], 'feed_full_text', None
    try:
        raw, _ = download(item['url'])
        article = trafilatura.extract(raw, include_comments=False, include_tables=True,
                                      favor_precision=True) or ''
        if len(article) > len(body) and len(article) >= 500:
            return article[:18000], 'article', None
        return body, 'summary', 'No readable full article'
    except Exception as e:
        return body, 'summary', safe_error(e)

def discover(u, history, now):
    cutoff = (datetime.fromisoformat(now) - timedelta(days=90)).date().isoformat()
    items, health = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {pool.submit(read_feed, u, name, url, cutoff): (name, url) for name, url in FEEDS.items()}
        for job in concurrent.futures.as_completed(jobs):
            name, url = jobs[job]
            try:
                found, dates, total = job.result()
                items.extend(found)
                health.append(dict(source=name, ok=True, entries=total, candidates=len(found), newest=max(dates, default=None)))
            except Exception as e:
                health.append(dict(source=name, ok=False, error=safe_error(e)))
    # The AI tracker retains its historical role, but is no longer the only archive.
    tracked = u.fetch_tracker()
    items.extend(i for i in tracked if not i['date'] or i['date'] >= cutoff)
    health.append(dict(source='AI agent attack tracker', ok=bool(tracked), entries=len(tracked)))
    seeds = u.load_json(os.path.join(u.ROOT, 'backfill_sources.json'), [])
    items.extend(dict(i, id=u.make_id(i['url'], i['title']), priority=1)
                 for i in seeds if i.get('date', '') >= cutoff)
    # Save a cursor after each page, and retry failed pages next run.
    for name, url in ARCHIVES.items():
        progress = history.setdefault(name, {'page': 2, 'complete': False})
        if progress['complete']:
            # Weekly overlap catches reports that fell out of the short RSS window.
            if progress.get('checked', '')[:10] >= (datetime.fromisoformat(now)-timedelta(days=7)).date().isoformat():
                continue
            progress.update(page=2, complete=False)
        last_signature = None
        for _ in range(65):
            page = progress['page']
            try:
                found, dates, total = read_feed(u, name, url + f'?paged={page}', cutoff)
                signature = tuple(i['url'] for i in found)
                items.extend(found)
                progress['page'] += 1
                if not dates or min(dates) < cutoff or (signature and signature == last_signature):
                    progress.update(complete=True, checked=now)
                    break
                last_signature = signature
                time.sleep(.15)
            except Exception as e:
                health.append(dict(source=f'{name} archive page {page}', ok=False, error=safe_error(e)))
                break
        progress['cutoff'] = cutoff
    return items, health

def legal_followup(title):
    # These feeds carry many court stories about attacks from years earlier.
    # They are not a new incident or operational update for this map.
    if re.search(r'^in other news\b', title, re.I):
        return False  # Mixed roundups still need incident-by-incident review.
    return bool(re.search(r"\bsentenc(?:e|ed|es|ing)\b|pleads? guilty|pleaded guilty|gets? \d+ years|\bsettle(?:s|d|ment|ments)?\b|\blitigation\b|class.action lawsuit", title, re.I))

def due(item, previous, now, version):
    if not previous or previous.get('policy') != version:
        return True
    if previous.get('status') == 'error':
        return True
    changed = previous.get('summary_hash') != hashlib.sha256(item.get('text','').encode()).hexdigest()
    if previous.get('review_override'):
        # A reviewed exclusion is durable until fresh feed evidence changes.
        # Archive-only metadata is not evidence of an article revision.
        return 'text' in item and changed
    if changed:
        return True
    # Recheck evolving and rejected reports for 90 days, not only new URLs.
    interval = 2 if previous.get('status') == 'defer' else 7
    return previous.get('checked', '') < (datetime.fromisoformat(now)-timedelta(days=interval)).isoformat()

def merge_record(u, data, item, rec, geo, now):
    by_id = {i['id']: i for i in data['incidents']}
    source_records = [i for i in data['incidents'] if item['url'] in
                      {i['source_url']} | {s['url'] for s in i.get('more_sources', [])}]
    source_match = next((i for i in source_records if i['victim'].casefold() == rec.get('victim', i['victim']).casefold()), None)
    if source_match is None and item.get('single_incident') and len(source_records) == 1:
        # One report, one known event: a paraphrased victim name is not a new attack.
        # Multi-event roundups retain victim-level matching.
        source_match = source_records[0]
    id_match = by_id.get(item['id'])
    if id_match and id_match['victim'].casefold() != rec.get('victim', id_match['victim']).casefold():
        id_match = None
    dup = by_id.get(rec.get('duplicate_of')) or source_match or id_match
    reported = item.get('date') or now[:10]
    queries = rec.get('location_queries') or ([{'query':rec['geocode_query'], 'basis':'Reported affected area'}] if rec.get('geocode_query') else [])
    if dup:
        urls = {dup['source_url']} | {s['url'] for s in dup.get('more_sources', [])}
        if item['url'] not in urls:
            dup.setdefault('more_sources', []).append({'name':item['source'], 'url':item['url']})
        dup['last_reported'] = max(dup.get('last_reported', dup.get('reported_date', dup.get('date',''))), reported)
        dup.setdefault('reported_date', reported)
        if dup['category'] == 'major_cyber' and rec['category'] in u.AI_CATEGORIES:
            dup.update(category=rec['category'], ai_role=rec['ai_role'], ai_source_url=item['url'], ai_source_name=item['source'])
        if rec.get('evidence_status') == 'confirmed' or 'evidence_status' not in dup:
            dup['evidence_status'] = rec.get('evidence_status', 'under_investigation')
        # Keep a dated, sourced update rather than erasing earlier established facts.
        dup.setdefault('updates', [])
        update = {'date':reported,'what':rec['what'],'url':item['url'],'source':item['source']}
        dup['updates'] = [x for x in dup['updates'] if x['url'] != item['url']] + [update]
        dup['updates'] = sorted(dup['updates'], key=lambda x:x['date'])[-8:]
        u.update_severity(dup, rec.get('severity_evidence'), item['url'], now)
        if queries and not dup.get('locations'):
            u.locate_incident(dup, geo, queries)
        return 'merged', dup['id']
    inc = {k:rec[k] for k in ['title','date','category','victim','attacker','what','ai_role','why','where','major_impact','significance']}
    incident_id = item['id'] if item['id'] not in by_id else u.make_id(item['id'], rec['victim'], rec['date'])
    inc.update(id=incident_id, source_name=item['source'], source_url=item['url'], added=now,
               reported_date=reported, last_reported=reported, evidence_status=rec.get('evidence_status','under_investigation'), lat=None, lon=None)
    if inc['category'] == 'major_cyber':
        inc['ai_role'] = 'AI involvement not confirmed in the reporting.'
    u.update_severity(inc, rec.get('severity_evidence'), item['url'], now)
    u.locate_incident(inc, geo, queries)
    data['incidents'].append(inc)
    return 'added', inc['id']

def run(u):
    now = timestamp()
    started = time.monotonic()
    root = u.ROOT
    path = lambda name: os.path.join(root, name)
    data = u.load_json(u.DATA_PATH, {'updated':None, 'incidents':[]})
    audit = u.load_json(path('decisions.json'), {})
    queue = u.load_json(path('pending.json'), {})
    history = u.load_json(path('backfill_progress.json'), {})
    geo = u.load_json(u.GEO_PATH, {})
    status = {'checked_at':now,'last_success':data.get('updated'),'status':'running','added':0,'merged':0,'processed':0,'errors':0,'summary_only':0,'retrieval_warnings':0}
    items, sources = discover(u, history, now)
    # Revisit decisions even after their articles rotate out of RSS.
    fresh_urls = {i['url'] for i in items}
    for url, old in audit.items():
        if url not in fresh_urls and old.get('item') and old.get('status') in {'defer','exclude','include'}:
            interval = 2 if old['status'] == 'defer' else 7
            if old.get('checked','') < (datetime.fromisoformat(now)-timedelta(days=interval)).isoformat():
                items.append(old['item'])
    status['sources'] = sources
    for item in items:
        key = item['url']
        if due(item, audit.get(key), now, u.SELECTION_VERSION):
            # Retain a short feed excerpt for retries, never full article bodies.
            queue[key] = {k:v for k,v in item.items() if k != 'text'}
            queue[key]['text'] = item.get('text','')[:400]
    live = {i['url']: i for i in items}
    cutoff = (datetime.fromisoformat(now)-timedelta(days=90)).date().isoformat()
    queue = {k:v for k,v in queue.items() if not v.get('date') or v['date'] >= cutoff}
    # Priority leads first, then fresh reports; older unfinished work stays queued.
    candidates = sorted(queue.values(), key=lambda i:(i.get('priority',0), i.get('date',''), i['url']), reverse=True)[:u.MAX_NEW]
    print(f'{len(candidates)} candidates this run; {len(queue)} queued', flush=True)
    client = u.OpenAI(timeout=60, max_retries=1) if os.environ.get('OPENAI_API_KEY') else None
    if not client:
        status.update(status='failed', errors=1, error='OPENAI_API_KEY is not set')

    def review(item, tracked):
        original = live.get(item['url'], item)
        if legal_followup(item['title']):
            rec = dict(relevant=False, decision='exclude', decision_reason='Court or settlement follow-up, not a new incident or operational update.', title=item['title'])
            return [rec], 'title', None, hashlib.sha256(original.get('text','').encode()).hexdigest()
        body, mode, warning = read_article(original)
        enriched = dict(item, text=body)
        records = u.extract(client, enriched, tracked)
        if isinstance(records, dict):
            records = [records]
        if not records:
            raise ValueError('Empty extraction')
        if not body.strip():
            for rec in records:
                rec.update(relevant=False, decision='defer', decision_reason='No readable source evidence; retry required.')
        return records, mode, warning, hashlib.sha256(original.get('text','').encode()).hexdigest()

    def checkpoint():
        data['incidents'].sort(key=lambda i:i.get('last_reported',i['date']), reverse=True)
        u.save_json(u.DATA_PATH, data)
        u.save_json(u.GEO_PATH, geo)
        u.save_json(path('decisions.json'), audit)
        u.save_json(path('pending.json'), queue)
        u.save_json(path('backfill_progress.json'), history)
        status['pending'] = len(queue)
        status['backfill'] = history
        u.save_json(path('feed_status.json'), status)

    fatal = not client
    # Four readers keep backfill practical. Re-review collisions against newly added
    # victims before committing a batch result, to avoid same-batch duplicates.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for start in range(0, len(candidates), 4):
            if fatal or time.monotonic() - started > 35 * 60:
                break
            tracked = list(data['incidents'])
            known_ids = {i['id'] for i in tracked}
            batch = candidates[start:start+4]
            jobs = [(item, pool.submit(review, item, tracked)) for item in batch]
            for item, job in jobs:
                try:
                    records, mode, warning, fingerprint = job.result()
                    if any(rec.get('relevant') for rec in records) and any(i['id'] not in known_ids for i in data['incidents']):
                        records, mode, warning, fingerprint = review(item, list(data['incidents']))
                    outcomes = []
                    for index, rec in enumerate(records):
                        accepted = u.eligible_record(rec) and rec.get('decision') == 'include' and rec.get('evidence_status') != 'unverified'
                        outcome = 'include' if accepted else ('defer' if rec.get('decision') in {'defer','include'} else 'exclude')
                        detail = {'status':outcome, 'reason':rec['decision_reason'], 'title':rec['title']}
                        if accepted:
                            event_item = dict(item)
                            event_item['single_incident'] = len(records) == 1
                            if index:
                                event_item['id'] = u.make_id(item['id'], rec['victim'], rec['date'])
                            result, incident_id = merge_record(u, data, event_item, rec, geo, now)
                            status[result] += 1
                            detail['incident_id'] = incident_id
                            print(f'{result}: {rec["title"]}', flush=True)
                        outcomes.append(detail)
                    overall = 'defer' if any(x['status']=='defer' for x in outcomes) else ('include' if any(x['status']=='include' for x in outcomes) else 'exclude')
                    entry = dict(title=item['title'], source=item['source'], checked=now, policy=u.SELECTION_VERSION,
                                 status=overall, reason='; '.join(x['reason'] for x in outcomes), decisions=outcomes,
                                 evidence=mode, summary_hash=fingerprint, item={k:v for k,v in item.items() if k != 'text'})
                    if mode == 'summary':
                        status['summary_only'] += 1
                    if warning:
                        status['retrieval_warnings'] += 1
                        entry['retrieval_warning'] = warning
                    audit[item['url']] = entry
                    queue.pop(item['url'], None)
                    status['processed'] += 1
                except Exception as e:
                    status['errors'] += 1
                    audit[item['url']] = dict(title=item['title'], checked=now, policy=u.SELECTION_VERSION, status='error', reason=safe_error(e))
                    print(f'extract failed: {item["url"]}: {safe_error(e)}', flush=True)
                    if getattr(e, 'status_code', None) in {401,403,429}:
                        fatal = True
            checkpoint()
            print(f'reviewed {status["processed"]}/{len(candidates)} reports; {status["added"]} added, {status["merged"]} updated, {status["errors"]} errors', flush=True)
    failed_sources = [s for s in sources if not s['ok']]
    status['status'] = 'failed' if fatal or (candidates and not status['processed']) else ('partial' if status['errors'] or failed_sources else 'ok')
    if status['status'] == 'ok':
        data['updated'] = now
        status['last_success'] = now
    data['last_added'] = max((i.get('added','') for i in data['incidents']), default=None)
    checkpoint()
    summary = f'done: {status["added"]} added, {status["merged"]} merged; {status["processed"]} reviewed, {status["errors"]} errors, {len(queue)} pending; status={status["status"]}'
    print(summary, flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(summary + '\n\n' + '\n'.join(f'- {s["source"]}: {"OK" if s["ok"] else s.get("error","unavailable")}' for s in sources))
    return 1 if status['status'] == 'failed' else 0

