from __future__ import annotations
import csv
import datetime as dt
import hashlib
import http.cookiejar
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = '4.1.0'
NORMAL = 'https://192.168.10.150:1606'
LAB = 'http://172.16.30.209:1606'
SECRET = re.compile(r'password|passwd|cookie|authorization|csrf|token|secret|session', re.I)

def clean(value):
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if SECRET.search(k) else clean(v)) for k,v in value.items()}
    if isinstance(value, list): return [clean(v) for v in value]
    return value

def canonical(v): return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
def sha(v): return hashlib.sha256(v).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def fail(code, retryable=False): raise Error(code, retryable)

class Error(Exception):
    def __init__(self, code, retryable=False):
        self.code, self.retryable = code, retryable
        super().__init__(code)

def save(path, data, exclusive=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as f: f.write(canonical(clean(data)))

def timestamp(value):
    try: t = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, AttributeError): fail('INVALID_TIME')
    if t.tzinfo is None: fail('TIMEZONE_REQUIRED')
    return t

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, base=None): self.base=base
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.base and urllib.parse.urlsplit(newurl)[:2]==urllib.parse.urlsplit(self.base)[:2]:
            return super().redirect_request(req,fp,code,msg,headers,newurl)
        fail('REDIRECT_REQUIRES_PROFILE')

class PinnedHandler(urllib.request.HTTPSHandler):
    def __init__(self, fingerprint):
        super().__init__(); self.fingerprint=fingerprint.lower()
        if not re.fullmatch('[0-9a-f]{64}',self.fingerprint): fail('TLS_PIN_INVALID')
    def https_open(self, request):
        expected=self.fingerprint
        class Connection(http.client.HTTPSConnection):
            def __init__(self,host,**kwargs):
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                kwargs.pop('context',None)
                super().__init__(host,context=ctx,**kwargs)
            def connect(self):
                super().connect()
                if sha(self.sock.getpeercert(binary_form=True))!=expected:
                    self.close(); raise ssl.SSLError('Certificate pin mismatch')
        return self.do_open(Connection,request)

class Client:
    def __init__(self, profile):
        self.profile = profile
        self.base = profile['base_url'].rstrip('/')
        parsed = urllib.parse.urlsplit(self.base)
        if parsed.scheme not in ('http','https') or parsed.username or parsed.password or parsed.query or parsed.fragment:
            fail('INVALID_TARGET')
        tls = profile.get('tls', {})
        if tls.get('insecure'): fail('INSECURE_TLS_FORBIDDEN')
        try: context = ssl.create_default_context(cafile=tls.get('ca_file'))
        except Exception: fail('TLS_CONFIG')
        self.cookies = http.cookiejar.CookieJar()
        handler=PinnedHandler(tls['certificate_sha256']) if tls.get('certificate_sha256') else urllib.request.HTTPSHandler(context=context)
        redirects=NoRedirect(self.base if profile.get('auth',{}).get('allow_same_origin_redirects') else None)
        self.opener = urllib.request.build_opener(redirects, urllib.request.HTTPCookieProcessor(self.cookies), handler)
        self.token = None
        self.authenticated = False
        self.events = []
    def raw(self, path, method='GET', body=None, form=False):
        if not path.startswith('/') or path.startswith('//') or urllib.parse.urlsplit(path).netloc: fail('CROSS_TARGET_PATH')
        headers = {'Accept':'application/json'}
        if self.token: headers['Authorization'] = 'Bearer ' + self.token
        auth = self.profile.get('auth', {})
        csrf = next((c.value for c in self.cookies if c.name == auth.get('csrf_cookie')), None)
        if csrf: headers[auth.get('csrf_header','X-XSRF-TOKEN')] = urllib.parse.unquote(csrf)
        data = None
        if body is not None:
            data = urllib.parse.urlencode(body).encode() if form else canonical(body)
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        try:
            req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
            with self.opener.open(req, timeout=self.profile.get('timeout',30)) as r:
                limit = self.profile.get('max_response_bytes', 16*1024*1024)
                content = r.read(limit+1)
                if len(content)>limit: fail('RESPONSE_LIMIT')
                return content
        except urllib.error.HTTPError as e:
            if e.code in (401,403): fail('AUTH_EXPIRED')
            fail('HTTP_' + str(e.code), e.code in (429,502,503,504))
        except urllib.error.URLError as e:
            fail('TLS_FAILURE' if isinstance(e.reason, ssl.SSLError) else 'CONNECTION_FAILED', not isinstance(e.reason,ssl.SSLError))
        except (TimeoutError, OSError): fail('CONNECTION_FAILED', True)
    def authenticate(self):
        a = self.profile.get('auth',{})
        mode = a.get('mode','none')
        if mode == 'none': self.authenticated=True; return {'authenticated':True,'mode':mode}
        credentials = {}
        if a.get('secret_file'):
            p = Path(a['secret_file'])
            if p.is_symlink() or not p.is_file() or p.stat().st_mode & 0o777 != 0o600: fail('SECRET_PERMISSIONS')
            try:
                if a.get('secret_file_format')=='password_text':
                    credentials={k:os.environ.get(v) for k,v in a.get('env',{}).items()}
                    credentials['password']=p.read_text().rstrip('\r\n')
                else: credentials = json.loads(p.read_text())
            except Exception: fail('SECRET_FORMAT')
        else:
            credentials = {k:os.environ.get(v) for k,v in a.get('env',{}).items()}
        if mode == 'bearer':
            self.token = credentials.get('token')
            if not self.token: fail('CREDENTIALS_MISSING')
        elif mode in ('form','json'):
            body = {field:credentials.get(key) for field,key in a.get('fields',{}).items()}
            if not body or any(v is None for v in body.values()): fail('CREDENTIALS_MISSING')
            if a.get('csrf_page'):
                page = self.raw(a['csrf_page']).decode()
                match = re.search(a['csrf_pattern'], page)
                if not match: fail('CSRF_MISSING')
                body[a.get('csrf_field','_token')] = match.group(1)
            try: raw = self.raw(a['login'], 'POST', body, mode=='form')
            except Error as e:
                if e.code == 'AUTH_EXPIRED': fail('AUTH_FAILED')
                raise
            if a.get('success_cookie') and not any(c.name==a['success_cookie'] for c in self.cookies): fail('AUTH_FAILED')
            if a.get('failure_body_marker') and a['failure_body_marker'].encode() in raw: fail('AUTH_FAILED')
            if a.get('token_field'):
                try: self.token=json.loads(raw)[a['token_field']]
                except Exception: fail('AUTH_FAILED')
            # A configured authenticated GET is mandatory; redirects alone are not success.
            if not a.get('verify'): fail('AUTH_VERIFY_REQUIRED')
            try: self.raw(a['verify'])
            except Error: fail('AUTH_FAILED')
        else: fail('AUTH_PROFILE_UNSUPPORTED')
        self.authenticated = True
        return {'authenticated':True,'mode':mode}
    def request(self, path, method='GET', body=None):
        if not self.authenticated: self.authenticate()
        for attempt in range(2):
            try:
                raw = self.raw(path, method, body)
                try: return json.loads(raw)
                except Exception: fail('INVALID_JSON')
            except Error as e:
                # Never replay mutations after authentication errors or transport failures.
                if e.code=='AUTH_EXPIRED' and method=='GET' and attempt==0:
                    self.events.append({'event':'reauthenticate','at':now()})
                    self.cookies.clear(); self.token=None; self.authenticate(); continue
                raise
    def logout(self):
        try:
            if self.profile.get('auth',{}).get('logout'): self.raw(self.profile['auth']['logout'],'POST')
        finally: self.cookies.clear(); self.token=None; self.authenticated=False
        return {'logged_out':True}

class Logs:
    def __init__(self, client, capability): self.client,self.cap = client,capability
    def query(self, filters, limits=None, checkpoint=None):
        limits=limits or {}; cfg=self.cap['logs']; pg=cfg['pagination']
        if not filters.get('start_time') or not filters.get('end_time'): fail('TIME_WINDOW_REQUIRED')
        start,end=timestamp(filters['start_time']),timestamp(filters['end_time'])
        if end<=start: fail('INVALID_TIME_WINDOW')
        if end>dt.datetime.now(dt.timezone.utc): fail('FUTURE_WINDOW')
        supported=cfg.get('filters',{}); params=dict(cfg.get('default_parameters',{})); applied={}; client_filters=[]
        for key,value in filters.items():
            spec=supported.get(key)
            if not spec or spec.get('verified') is not True: fail('FILTER_UNVERIFIED_'+key.upper())
            if spec.get('mode','server')=='client':
                if key in ('start_time','end_time') or not spec.get('row_field'): fail('CLIENT_FILTER_INVALID')
                client_filters.append((spec['row_field'],value,spec.get('normalize')))
                applied[key]={'value':value,'mode':'client','semantics':'exact'}
                continue
            if spec.get('mode','server')!='server': fail('FILTER_MODE_UNSUPPORTED')
            if spec.get('format')=='unix_seconds': value=int(timestamp(value).timestamp())
            if spec.get('encoding')=='sentry_filter':
                existing=json.loads(params.get('filter','{}'))
                existing[spec['parameter']]={'field':spec['field'],'reverse':0,'rule':[value]}
                params['filter']=json.dumps(existing,separators=(',',':'))
            else: params[spec['parameter']]=value
            applied[key]={'value':filters[key],'mode':'server','semantics':spec.get('semantics','exact')}
        size=limits.get('page_size',pg.get('max_page_size',2500))
        if pg.get('fixed_page_size') and size!=pg['fixed_page_size']: fail('FIXED_PAGE_SIZE_REQUIRED')
        if not isinstance(size,int) or size<1 or size>pg.get('max_page_size',2500): fail('PAGE_SIZE_INVALID')
        fingerprint=sha(canonical({'target':self.client.base,'capability':self.cap,'filters':filters,'size':size}))
        position=pg.get('first',1); rows=[]; seen=set(); page_hashes=[]; pages=0; total=None; snapshot=None
        if checkpoint:
            if checkpoint.get('fingerprint')!=fingerprint: fail('CHECKPOINT_TARGET_OR_QUERY_MISMATCH')
            verified=dict(checkpoint); digest=verified.pop('checkpoint_sha256',None)
            if sha(canonical(verified))!=digest: fail('CHECKPOINT_CORRUPTED')
            position=checkpoint['position']; rows=checkpoint['rows']; seen={sha(canonical(r)) for r in rows}; page_hashes=checkpoint['page_hashes']; pages=checkpoint['pages']; total=checkpoint['total']; snapshot=checkpoint['snapshot']
            if not snapshot: fail('RESUME_REQUIRES_SNAPSHOT')
        begun=time.monotonic(); completed=False
        while True:
            if limits.get('max_pages') is not None and pages>=limits['max_pages']: break
            if limits.get('max_seconds') is not None and time.monotonic()-begun>=limits['max_seconds']: break
            q=dict(params)
            if pg.get('send_size_parameter',True): q[pg.get('size_parameter','page_size')]=size
            if position is not None: q[pg.get('parameter','page')]=position
            if snapshot is not None: q[pg['snapshot_parameter']]=snapshot
            endpoint=cfg['endpoint']
            if '{position}' in endpoint:
                endpoint=endpoint.replace('{position}',urllib.parse.quote(str(position),safe='')); q.pop(pg.get('parameter','page'),None)
            data=self.client.request(endpoint+'?'+urllib.parse.urlencode(q))
            batch=data if isinstance(data,list) else data.get(pg.get('rows_field','rows'))
            if not isinstance(batch,list) or any(not isinstance(r,dict) for r in batch): fail('LOG_SCHEMA')
            h=sha(canonical(batch))
            if batch and h in page_hashes: fail('DUPLICATE_PAGE')
            current_total=data.get(pg.get('total_field','total')) if isinstance(data,dict) else None
            current_snapshot=data.get(pg.get('snapshot_field','snapshot')) if isinstance(data,dict) else None
            if pages and (current_total!=total or current_snapshot!=snapshot): fail('PAGINATION_DRIFT')
            if current_snapshot is not None and not isinstance(current_snapshot,(str,int)): fail('SNAPSHOT_SCHEMA')
            total=current_total; snapshot=current_snapshot
            if len(batch)>size: fail('PAGE_SIZE_EXCEEDED')
            if any(sha(canonical(r)) in seen for r in batch): fail('DUPLICATE_RECORD')
            if len({sha(canonical(r)) for r in batch})!=len(batch): fail('DUPLICATE_RECORD')
            if limits.get('max_records') is not None and len(rows)+len(batch)>limits['max_records']: break
            rows.extend(batch); seen.update(sha(canonical(r)) for r in batch); page_hashes.append(h); pages+=1
            if limits.get('max_bytes') is not None and len(canonical(rows))>limits['max_bytes']: fail('BYTE_LIMIT')
            kind=pg['kind']
            if kind in ('cursor','next_token'):
                nxt=data.get(pg.get('next_field','next'))
                if nxt is not None and nxt==position: fail('DUPLICATE_CURSOR')
                position=nxt; ended=nxt is None
            elif kind in ('page','offset'):
                position+=size if kind=='offset' else 1; ended=len(batch)<size
            else: fail('PAGINATION_UNSUPPORTED')
            if ended:
                if total is not None and len(rows)!=total: fail('TOTAL_MISMATCH')
                # A short page is insufficient proof of absence of drift or gaps.
                completed=bool(pg.get('verified_snapshot') and snapshot is not None and total==len(rows))
                break
        cp={'schema_version':1,'fingerprint':fingerprint,'position':position,'rows':rows,'page_hashes':page_hashes,'pages':pages,'total':total,'snapshot':snapshot}
        cp['checkpoint_sha256']=sha(canonical(cp))
        def normalize(value,mode):
            if mode=='domain': return str(value).lower().rstrip('.')
            if mode=='upper': return str(value).upper()
            return value
        if any(field not in r for field,_,_ in client_filters for r in rows): fail('CLIENT_FILTER_SCHEMA')
        selected=[r for r in rows if all(normalize(r.get(field),mode)==normalize(value,mode) for field,value,mode in client_filters)]
        return {'rows':selected,'count':len(selected),'raw_count':len(rows),'pages':pages,'page_size':size,'complete':completed,'deduplicated':0,'applied_filters':applied,'timezone':'offsets in start_time/end_time','checkpoint':cp,'endpoint':cfg['endpoint'],'input_sha256':fingerprint,'errors':[],'retries':self.client.events}
    def export(self, result, directory, formats):
        directory=Path(directory)
        directory.mkdir(parents=True,exist_ok=False,mode=0o700)
        if shutil.disk_usage(directory).free < len(canonical(result['rows']))*4: fail('DISK_SPACE')
        files={}
        try:
            for fmt in formats:
                p=directory/('logs.'+fmt)
                with p.open('x',newline='') as f:
                    os.chmod(p,0o600)
                    if fmt=='json': json.dump(clean(result['rows']),f,ensure_ascii=False)
                    elif fmt=='jsonl':
                        for row in result['rows']: f.write(canonical(clean(row)).decode()+'\n')
                    elif fmt=='csv':
                        fields=sorted({k for r in result['rows'] for k in r}); w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
                        for row in clean(result['rows']):
                            # Neutralize formula injection without altering JSON raw copies.
                            w.writerow({k: ("'"+v if isinstance(v,str) and v.startswith(('=','+','-','@')) else json.dumps(v) if isinstance(v,(dict,list)) else v) for k,v in row.items()})
                    else: fail('EXPORT_FORMAT')
                files[p.name]=sha(p.read_bytes())
            manifest={k:v for k,v in result.items() if k not in ('rows','checkpoint')}
            manifest.update(target=self.client.base,query_time=now(),api_schema=self.cap.get('schema',{}),tool_version=VERSION,files=files)
            save(directory/'checkpoint.json',result['checkpoint'],True)
            save(directory/'manifest.json',manifest,True)
            return {'directory':str(directory),'manifest':manifest,'manifest_sha256':sha((directory/'manifest.json').read_bytes())}
        except Exception:
            save(directory/'failure.json',{'complete':False,'error':'EXPORT_FAILED'})
            raise
