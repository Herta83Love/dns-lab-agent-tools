"""Run only on the authorized validation host. Never emits response bodies or credentials."""
import ast
import datetime as dt
import hashlib
import http.cookiejar
import importlib.util
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo

ROOT=Path('/home/jackie_tsai/.local/state/dns-lab-agent-tools/capabilities')
COLLECTOR=Path('/home/jackie_tsai/dns-normal-collector/app/collector.py')
def write(name,obj):
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(ROOT,0o700)
    p=ROOT/name
    fd=os.open(p,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as f: json.dump(obj,f,indent=2)
    os.chmod(p,0o600)
def secret(path):
    p=Path(path)
    if p.is_symlink() or p.stat().st_mode & 0o777 != 0o600: raise ValueError('secret_permissions')
    return p.read_text().rstrip('\r\n')
def account_from_wrapper():
    t=ast.parse(Path('/home/jackie_tsai/dns-normal-collector/app/run_daily_collection.py').read_text())
    for n in ast.walk(t):
        if isinstance(n,(ast.List,ast.Tuple)):
            for i,e in enumerate(n.elts[:-1]):
                if isinstance(e,ast.Constant) and e.value=='--account':
                    v=n.elts[i+1]
                    if isinstance(v,ast.Constant) and isinstance(v.value,str): return v.value
    raise ValueError('SENTRY_ACCOUNT_required')
def main():
    spec=importlib.util.spec_from_file_location('verified_collector',COLLECTOR)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    records=[]
    for name,base in [('normal-dns','https://192.168.10.150:1606'),('lab-dns','http://172.16.30.209:1606')]:
        cap={'base_url':base,'verified_at':dt.datetime.now(dt.timezone.utc).isoformat(),'software_version':None,'api_base_path':'/webApi','read_only':True,'authentication':{'login_endpoint':'/login','method':'POST','provider':'environment_account_and_0600_text_password' if name=='normal-dns' else 'existing_dns_config_account_and_0600_text_password','account_environment':'SENTRY_ACCOUNT' if name=='normal-dns' else None},'tls':{'mode':'certificate_sha256_pinning','source_name':'existing_normal_collector_DEFAULT_CERT_SHA256'} if name=='normal-dns' else {'mode':'http_no_tls','source_name':None},'tests':[],'completeness_verified':False,'device_writes':0}
        try:
            if name=='normal-dns':
                opener,cookies=mod.build_opener(mod.DEFAULT_CERT_SHA256)
                account=os.environ.get('SENTRY_ACCOUNT') or account_from_wrapper()
                password=secret('/home/jackie_tsai/dns-normal-collector/secrets/sentry.password')
                mod.authenticate(opener,cookies,account,password)
                def request(path): return mod.request(opener,path)[2]
            else:
                cfg=json.loads(Path('/home/jackie_tsai/Herta-Chat/agent/dns_lab_config.json').read_text())
                p=next(v for v in cfg['profiles'].values() if v.get('secret_file')=='/home/jackie_tsai/.config/herta-chat/lab-dns.secret')
                account=p['account']; password=secret(p['secret_file'])
                cookies=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
                def request(path):
                    with opener.open(base+path,timeout=30) as r:return r.read(16*1024*1024+1)
                page=request('/login'); match=re.search(rb'name="_token"\s+value="([^"]+)"',page)
                if not match: raise ValueError('csrf_missing')
                form=urllib.parse.urlencode({'_token':match.group(1).decode(),'account':account,'password':password}).encode()
                req=urllib.request.Request(base+'/login',data=form,headers={'Content-Type':'application/x-www-form-urlencoded'})
                with opener.open(req,timeout=30) as r: body=r.read(1024*1024)
                if b'name="account"' in body or not any(c.name=='sentry_session' for c in cookies):raise ValueError('authentication_failed')
                cap['legacy_config_scheme_differs']=True
            del account,password
            cap['tests'].append({'test':'login','passed':True})
            end=dt.datetime.fromtimestamp(int((dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=3)).timestamp()),dt.timezone.utc);start=end-dt.timedelta(minutes=1)
            def logs(page,filters,lo=start,hi=end):
                query=urllib.parse.urlencode({'start_time':int(lo.timestamp()),'end_time':int(hi.timestamp()),'filter':json.dumps(filters,separators=(',',':'))})
                raw=request('/webApi/historylog/proxy/'+str(page)+'?'+query)
                rows=json.loads(raw)
                if not isinstance(rows,list) or any(not isinstance(x,dict) for x in rows):raise ValueError('log_schema')
                return rows
            rows=logs(1,{})
            cap['tests'].append({'test':'health_log_get','passed':True,'rows':len(rows),'schema_fields':sorted({k for r in rows for k in r if re.fullmatch('[a-zA-Z_][a-zA-Z0-9_]{0,40}',k) and not re.search('token|session|cookie|account|uuid|identifier',k,re.I)})})
            cap['logs']={'endpoint':'/webApi/historylog/proxy/{page}','method':'GET','pagination':{'kind':'page','first':1,'observed_page_limit':2500,'snapshot_support':'unknown','total_support':'unknown'},'time':{'parameters':['start_time','end_time'],'format':'unix_seconds','timezone':'UTC'},'filters':{}}
            for label,flt,predicate in [
                ('domain',{'qname':{'field':'domain','reverse':0,'rule':['taipeinetworks.com']}},lambda r:str(r.get('qname','')).rstrip('.').lower()=='taipeinetworks.com'),
                ('qtype',{'rtype':{'field':'type','reverse':0,'rule':['A']}},lambda r:str(r.get('qtype','')).upper()=='A')]:
                found=logs(1,flt,lo=end-dt.timedelta(minutes=10)) if label=='domain' else logs(1,flt)
                conforms=all(predicate(r) for r in found)
                cap['tests'].append({'test':label+'_filter','rows':len(found),'conforms':conforms,'verification':'inconclusive_empty' if not found else 'sample_conformance_only','query_values':'[MASKED]'})
                cap['logs']['filters'][label]={'encoding':label,'server_semantics_verified':False,'sample_conforms':conforms,'nonempty':bool(found)}
            if rows:
                candidate=next((str(r.get('qname','')).rstrip('.').lower() for r in rows if str(r.get('qname','')).count('.')>=2 and not str(r.get('qname','')).endswith('.arpa')),None)
                if candidate:
                    actual=logs(1,{'qname':{'field':'domain','reverse':0,'rule':[candidate]}})
                    expected=[r for r in rows if str(r.get('qname','')).rstrip('.').lower()==candidate or str(r.get('qname','')).rstrip('.').lower().endswith('.'+candidate)]
                    encode=lambda r:json.dumps(r,sort_keys=True)
                    same=sorted(map(encode,actual))==sorted(map(encode,expected))
                    cap['tests'].append({'test':'known_domain_suffix_differential','query_values':'[MASKED]','nonempty':bool(actual),'matches_baseline_suffix_subset':same,'exact_domain_verified':False})
                    cap['logs']['filters']['domain']['server_suffix_verified_on_sample']=bool(actual) and same
            cap['time_value_types']={k:sorted({type(r.get(k)).__name__ for r in rows}) for k in ('qtime','time')}
            cap['time_format_shapes']={k:('numeric_string' if rows and re.fullmatch(r'[0-9.]+',str(rows[0].get(k))) else 'iso_datetime' if rows and re.fullmatch(r'[0-9]{4}-[0-9TZ:+. -]+',str(rows[0].get(k))) else 'unknown') for k in ('qtime','time')}
            second=logs(2,{})
            cap['tests'].append({'test':'page_2','passed':True,'rows':len(second),'full_pagination_verified':False})
            repeated=logs(1,{})
            cap['tests'].append({'test':'bounded_window_repeat','same_result':rows==repeated,'raw_content_saved':False})
            parsed_times=[dt.datetime.fromisoformat(r['qtime']).replace(tzinfo=ZoneInfo('Asia/Taipei')).timestamp() for r in rows]
            cap['tests'].append({'test':'time_window','rows_within_bounds':all(start.timestamp()<=v<=end.timestamp()+1 for v in parsed_times),'row_timezone_interpretation':'Asia/Taipei','nonempty':bool(rows)})
            cap['logs']['time']['row_timezone']='Asia/Taipei'
            cap['logs']['time']['verified_on_sample']=bool(rows) and all(start.timestamp()<=v<=end.timestamp()+1 for v in parsed_times)
            page=request('/')
            paths=re.findall(rb'<script[^>]+src=["\']([^"\']+)',page)
            assets=[]
            for asset in paths[:12]:
                url=asset.decode(); parsed=urllib.parse.urlsplit(url)
                if (parsed.netloc and parsed.netloc!=urllib.parse.urlsplit(base).netloc) or not parsed.path.endswith('.js'): continue
                url=parsed.path if parsed.netloc else urllib.parse.urljoin('/',url); parsed=urllib.parse.urlsplit(url)
                code=request(url)
                assets.append({'path':parsed.path,'sha256':hashlib.sha256(code).hexdigest(),'contains_rcode_filter_terms':b'rcode' in code,'filter_key_candidates':sorted(set(m.decode() for m in re.findall(rb'(?i)[a-z_]{0,12}rcode[a-z_]{0,12}',code)))[:20]})
            cap['discovery_assets']=assets
            cap['html_contains_rcode_terms']=b'rcode' in page
            cap['html_script_count']=len(paths)
            cap['html_login_form_present']=b'name="account"' in page
            cap['logs']['filters']['qtype']['server_semantics_verified']=False
            cap['logs']['filters']['rcode']={'server_semantics_verified':False,'reason':'no_declared_endpoint_mapping_found'}
            cap['logs']['pagination']['completeness_verified']=False
            cap['authenticated']=True
        except Exception as exc:
            cap['error']={'class':type(exc).__name__,'message':'[MASKED]','http_status':getattr(exc,'code',None)}
        write(name+'.json',cap)
        records.append({'profile':name,'authenticated':cap.get('authenticated',False),'tests':cap['tests'],'error_class':cap.get('error',{}).get('class'),'http_status':cap.get('error',{}).get('http_status')})
    print(json.dumps(records))
if __name__=='__main__':main()
