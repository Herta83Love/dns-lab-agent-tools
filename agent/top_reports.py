"""iSafer Top Reports: authenticated, hash-correlated, bounded read-only queries."""
from __future__ import annotations
import datetime as dt
import hashlib
import html.parser
import importlib.util
import json
import math
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo

CATALOG = {
    'system': {k:'line' for k in ('cpu_us','cpu_lavg','memory','lps','qpm_rrm','hosts','disk')},
    'proxy': {'query_name':'table','response_name':'table','unique_domain':'table','query_domain':'pie','response_domain':'pie','query_type':'table','response_type':'table','response_code':'pie','source_ipv4':'table','source_ipv6':'table','blocked_query_name':'table','blocked_source_ipv4':'table','blocked_source_ipv6':'table','blocked_query_type':'pie','blocked_response_code':'pie','category':'pie','blocked_category':'pie'},
    'firewall': {'query_name':'pie','query_domain':'pie','query_type':'table','source_ipv4':'table','source_ipv6':'table','blocked_query_name':'table','blocked_query_type':'table','blocked_source_ipv4':'table','blocked_source_ipv6':'table'},
    'authority': {'query_name':'pie','query_domain':'pie','query_type':'table','source_ipv4':'table','source_ipv6':'table','blocked_query_name':'table','blocked_query_type':'table','blocked_source_ipv4':'table','blocked_source_ipv6':'table'},
}
DEFAULTS={'system':list(CATALOG['system']),'proxy':['query_name','query_type','response_code'],'firewall':['query_type'],'authority':['query_type']}
UNITS={'cpu_us':'percent','cpu_lavg':'device_load_average','memory':'percent','lps':'device_LPS','qpm_rrm':'device_QPM_RRM','hosts':'count','disk':'percent'}
SCHEMA={'type':'object','additionalProperties':False,'properties':{
    'dns_profile':{'type':'string','default':'lab-malicious'},
    'section':{'type':'string','enum':list(CATALOG),'default':'system'},
    'reports':{'type':'array','items':{'type':'string','enum':sorted({k for v in CATALOG.values() for k in v})},'minItems':1,'uniqueItems':True},
    'start_time':{'type':'string','description':'Offset-aware RFC3339; supply together with end_time.'},
    'end_time':{'type':'string','description':'Exclusive end, offset-aware RFC3339; no future window.'},
    'window_minutes':{'type':'integer','minimum':1,'default':120,'description':'Used only when explicit start/end are absent; not a retention guarantee.'},
    'timeout_seconds':{'type':'number','exclusiveMinimum':0,'default':45,'description':'Overall timeout, including login, subscription and all reports.'},
    'top_n':{'type':'integer','minimum':1,'maximum':10,'default':10},
    'max_points':{'type':'integer','minimum':1,'default':300,'description':'Returned points per series; statistics use every received point.'},
    'include_points':{'type':'boolean','default':False},
    'include_identifiers':{'type':'boolean','default':False,'description':'Return actual domain/IP ranking labels; default masks them.'},
    'stale_after_seconds':{'type':'number','minimum':0,'default':600},
}}
DEFINITIONS=[{'type':'function','function':{'name':'lab_dns_get_top_report_capabilities','description':'Local-only Top Reports catalog and dependencies. Start here to select valid section/report pairs; never guess chart types or WebSocket endpoints.','parameters':{'type':'object','additionalProperties':False,'properties':{'dns_profile':{'type':'string','default':'lab-malicious'}}}}},
 {'type':'function','function':{'name':'lab_dns_get_top_report','description':'Read Top Reports in one call: default hardware load summary (CPU, load average, memory, LPS, QPM/RRM, hosts, disk). Handles authenticated WebSocket delivery; returns ready/no_data/stale/pending per report. GET acknowledgment alone is not report data. No scheduled export, settings write or polling loop. See capabilities for valid combinations.', 'parameters':SCHEMA}}]

class ReportError(Exception):
    def __init__(self,code,retryable=False):self.code,self.retryable=code,retryable;super().__init__(code)
def reject(code,retryable=False):raise ReportError(code,retryable)
def capabilities():
    return {'schema_version':'top-reports-1','catalog':CATALOG,'default_reports':DEFAULTS,'units':UNITS,'websocket_dependency_available':importlib.util.find_spec('websocket') is not None,'transport':'GET acknowledgment plus authenticated private WebSocket statistics event','timezone':'query UTC Unix seconds; response timestamps normalized to explicit offsets','default_window_minutes':120,'known_limits':{'summary_top_n':10,'retention':'UI offers last 7 days; actual stored range unverified'},'read_only':True,'unavailable_features':['schedule/export report creation','detail pagination','arbitrary endpoint or chart type'],'next_action':'Call lab_dns_get_top_report with section=system for load, or choose reports from catalog.'}
def parse_time(value):
    try:parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    except (ValueError,AttributeError):reject('TOP_REPORT_INVALID_TIME')
    if parsed.tzinfo is None:reject('TOP_REPORT_TIMEZONE_REQUIRED')
    return parsed.astimezone(dt.timezone.utc)
def validate(args,now=None):
    if not isinstance(args,dict) or set(args)-set(SCHEMA['properties']):reject('TOP_REPORT_INVALID_ARGUMENTS')
    section=args.get('section','system')
    if section not in CATALOG:reject('TOP_REPORT_SECTION_UNSUPPORTED')
    reports=args.get('reports',DEFAULTS[section])
    if not isinstance(reports,list) or not reports or any(not isinstance(r,str) or r not in CATALOG[section] for r in reports) or len(reports)!=len(set(reports)):reject('TOP_REPORT_COMBINATION_UNSUPPORTED')
    for k,default in [('window_minutes',120),('top_n',10),('max_points',300)]:
        v=args.get(k,default)
        if isinstance(v,bool) or not isinstance(v,int) or v<1 or k=='top_n' and v>10:reject('TOP_REPORT_INVALID_ARGUMENTS')
    for k,default in [('timeout_seconds',45),('stale_after_seconds',600)]:
        v=args.get(k,default)
        if isinstance(v,bool) or not isinstance(v,(float,int)) or not math.isfinite(v) or v<0 or k=='timeout_seconds' and v==0:reject('TOP_REPORT_INVALID_ARGUMENTS')
    for k in ('include_points','include_identifiers'):
        if k in args and not isinstance(args[k],bool):reject('TOP_REPORT_INVALID_ARGUMENTS')
    now=now or dt.datetime.now(dt.timezone.utc)
    if ('start_time' in args)!=('end_time' in args):reject('TOP_REPORT_BOTH_TIMES_REQUIRED')
    if 'start_time' in args:
        if 'window_minutes' in args:reject('TOP_REPORT_AMBIGUOUS_WINDOW')
        start,end=parse_time(args['start_time']),parse_time(args['end_time'])
    else:
        end=now.replace(second=0,microsecond=0);start=end-dt.timedelta(minutes=args.get('window_minutes',120))
    if start>=end or int(end.timestamp())<=int(start.timestamp()):reject('TOP_REPORT_INVALID_WINDOW')
    if end>now:reject('TOP_REPORT_FUTURE_WINDOW')
    return section,list(reports),start,end

class _Meta(html.parser.HTMLParser):
    csrf=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='meta' and a.get('name')=='csrf-token':self.csrf=a.get('content')
class _Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self,base):self.base=urllib.parse.urlsplit(base)
    def redirect_request(self,req,fp,code,msg,headers,url):
        if urllib.parse.urlsplit(url)[:2]!=self.base[:2]:reject('TOP_REPORT_TARGET_REDIRECT')
        return super().redirect_request(req,fp,code,msg,headers,url)

class Transport:
    """One private subscription; identifiers/auth never leave this object."""
    def __init__(self,client,deadline,pinned_handler):
        self.client,self.deadline,self.ws=client,deadline,None
        self.base=client.cfg['base_url'].rstrip('/');self.headers={'X-Requested-With':'XMLHttpRequest'}
        target=urllib.parse.urlsplit(self.base)
        if target.scheme!='https' or target.username or target.password or target.path or target.query or target.fragment:reject('TOP_REPORT_HTTPS_PROFILE_REQUIRED')
        self.target=target
        pin=client.cfg.get('certificate_sha256','')
        if not re.fullmatch('[a-fA-F0-9]{64}',pin):reject('TOP_REPORT_TLS_PIN_REQUIRED')
        self.pin=pin.lower()
        self.opener=urllib.request.build_opener(_Redirect(self.base),urllib.request.HTTPCookieProcessor(client.cookies),pinned_handler(self.pin))
    def remaining(self):
        left=self.deadline-time.monotonic()
        if left<=0:reject('TOP_REPORT_TIMEOUT',True)
        return left
    def http(self,path,body=None):
        data=None if body is None else urllib.parse.urlencode(body).encode()
        headers=dict(self.headers)
        if data is not None:headers['Content-Type']='application/x-www-form-urlencoded'
        request=urllib.request.Request(self.base+path,data=data,headers=headers)
        try:
            with self.opener.open(request,timeout=self.remaining()) as r:
                raw=r.read(8*1024*1024+1)
                if len(raw)>8*1024*1024:reject('TOP_REPORT_RESPONSE_LIMIT')
                if urllib.parse.urlsplit(r.url).path=='/login':reject('TOP_REPORT_SESSION_EXPIRED',True)
                return r.status,raw
        except urllib.error.HTTPError as e:
            if e.code in (401,403,419):reject('TOP_REPORT_SESSION_EXPIRED',True)
            reject('TOP_REPORT_HTTP_'+str(e.code),e.code in (429,502,503,504))
    def start(self):
        try:import websocket
        except ImportError:reject('TOP_REPORT_DEPENDENCY_MISSING')
        _,page=self.http('/view/riskInsight/statistics');parser=_Meta();parser.feed(page.decode())
        if not parser.csrf:reject('TOP_REPORT_CSRF_MISSING')
        self.headers['X-CSRF-TOKEN']=parser.csrf
        _,asset=self.http('/js/iframe.js')
        match=re.search(rb'window.WebSocket=new \w+\(\{broadcaster:"pusher",key:"([a-zA-Z0-9_-]+)"',asset)
        if not match:reject('TOP_REPORT_FRONTEND_CHANGED')
        host,port=self.target.hostname,self.target.port or 443
        raw=None;secure=None
        try:
            raw=socket.create_connection((host,port),timeout=self.remaining())
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
            secure=context.wrap_socket(raw,server_hostname=host)
            if hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()!=self.pin:reject('TOP_REPORT_TLS_PIN_MISMATCH')
            self.ws=websocket.create_connection('wss://'+self.target.netloc+'/app/'+match.group(1).decode()+'?protocol=7&client=js&version=8.4.0&flash=false',socket=secure,timeout=self.remaining(),origin=self.base,cookie='; '.join(c.name+'='+c.value for c in self.client.cookies),redirect_limit=0)
            event=self.receive()
            if event.get('event')!='pusher:connection_established':reject('TOP_REPORT_SOCKET_HANDSHAKE')
            socket_id=self.decode(event.get('data'))['socket_id'];self.headers['X-Socket-Id']=socket_id
            _,auth=self.http('/broadcasting/auth',{'socket_id':socket_id,'channel_name':'private-boulevard'})
            auth=json.loads(auth)
            self.ws.send(json.dumps({'event':'pusher:subscribe','data':{'auth':auth['auth'],'channel':'private-boulevard'}}))
            while True:
                event=self.receive()
                if event.get('event')=='pusher_internal:subscription_succeeded' and event.get('channel')=='private-boulevard':break
                if event.get('event') in ('pusher:error','pusher:subscription_error'):reject('TOP_REPORT_SUBSCRIPTION_DENIED')
        except Exception:
            if self.ws is None:
                if secure is not None:secure.close()
                elif raw is not None:raw.close()
            raise
    @staticmethod
    def decode(value):
        return json.loads(value) if isinstance(value,str) else value
    def receive(self):
        while True:
            self.ws.settimeout(self.remaining())
            raw=self.ws.recv()
            if not raw:reject('TOP_REPORT_SOCKET_CLOSED',True)
            if len(raw)>8*1024*1024:reject('TOP_REPORT_RESPONSE_LIMIT')
            event=json.loads(raw)
            if not isinstance(event,dict):reject('TOP_REPORT_SOCKET_SCHEMA')
            if event.get('event')=='pusher:ping':self.ws.send(json.dumps({'event':'pusher:pong','data':{}}));continue
            return event
    def request(self,section,category,start,end):
        params={'ts_start':int(start.timestamp()),'ts_end':int(end.timestamp())-1}
        if section=='system':params['full_line']=1
        status,raw=self.http('/webApi/statistics/'+section+'/'+category+'/'+CATALOG[section][category]+'?'+urllib.parse.urlencode(params))
        ack=json.loads(raw)
        if not isinstance(ack,dict) or not isinstance(ack.get('hash_id'),str) or not ack['hash_id']:reject('TOP_REPORT_ACK_SCHEMA')
        return ack['hash_id'],status
    def collect(self,wanted):
        while True:
            event=self.receive()
            if event.get('event') in ('pusher:error','pusher:subscription_error'):reject('TOP_REPORT_SOCKET_ERROR',True)
            if event.get('event')!='statistics' or event.get('channel')!='private-boulevard':continue
            payload=self.decode(event.get('data'))
            if not isinstance(payload,dict):reject('TOP_REPORT_SOCKET_SCHEMA')
            if payload.get('hash_id') not in wanted:continue
            return payload['hash_id'],payload.get('data')
    def close(self):
        if self.ws is not None:
            try:self.ws.close(timeout=1)
            except Exception:pass

def numeric(value):
    if value is None:return None
    if isinstance(value,bool) or not isinstance(value,(float,int)) or not math.isfinite(value):reject('TOP_REPORT_DATA_SCHEMA')
    return value

def normalize(section,category,dataset,args,start,end,now=None):
    if not isinstance(dataset,dict) or not isinstance(dataset.get('data'),list):reject('TOP_REPORT_DATA_SCHEMA')
    now=now or dt.datetime.now(dt.timezone.utc)
    base={'status':'no_data','sample_count':0,'window_coverage':'not_guaranteed'}
    if section=='system':
        values=dataset['data'];raw_times=dataset.get('time',[])
        if not isinstance(raw_times,list):reject('TOP_REPORT_DATA_SCHEMA')
        if not values and not raw_times:return {**base,'series':[],'unit':UNITS[category]}
        try:
            times=[dt.datetime.fromisoformat(v.replace('Z','+00:00')) for v in raw_times]
            times=[(t.replace(tzinfo=ZoneInfo('Asia/Taipei')) if t.tzinfo is None else t).astimezone(dt.timezone.utc) for t in times]
        except Exception:reject('TOP_REPORT_TIMESTAMP_SCHEMA')
        if not times or any(a>=b for a,b in zip(times,times[1:])):reject('TOP_REPORT_TIMESTAMP_ORDER')
        if any(not start<=t<end for t in times):reject('TOP_REPORT_TIME_RANGE_MISMATCH')
        names=dataset.get('name')
        if names is None:series=[(category,values)]
        else:
            if not isinstance(names,list) or len(names)!=len(values) or any(not isinstance(n,str) or len(n)>64 for n in names):reject('TOP_REPORT_DATA_SCHEMA')
            series=list(zip(names,values))
        output=[]
        for name,points in series:
            if not isinstance(points,list) or len(points)!=len(times):reject('TOP_REPORT_SERIES_LENGTH')
            points=[numeric(v) for v in points];present=[(t,v) for t,v in zip(times,points) if v is not None]
            if not present:
                output.append({'name':name,'status':'no_data','sample_count':0});continue
            latest_time,latest=present[-1];age=max(0,(now-latest_time).total_seconds())
            item={'name':name,'status':'stale' if age>args.get('stale_after_seconds',600) else 'ready','sample_count':len(present),'missing_samples':len(points)-len(present),'latest':latest,'latest_time':latest_time.isoformat(),'age_seconds':age,'minimum':min(v for _,v in present),'maximum':max(v for _,v in present),'mean':sum(v for _,v in present)/len(present)}
            if args.get('include_points',False):
                maximum=args.get('max_points',300)
                item['points']=[{'time':t.isoformat(),'value':v} for t,v in list(zip(times,points))[-maximum:]]
                item['points_truncated']=len(times)>maximum
            output.append(item)
        states={item['status'] for item in output}
        return {**base,'status':'stale' if 'stale' in states else 'ready' if 'ready' in states else 'no_data','sample_count':len(times),'unit':UNITS[category],'series':output,'response_source_timezone':'Asia/Taipei for naive timestamps','timezone':'UTC'}
    raw_rows=dataset['data'];rows=[];padded=0
    public_labels=category in ('query_type','response_type','blocked_query_type','response_code','blocked_response_code')
    for row in raw_rows:
        if not isinstance(row,dict) or not isinstance(row.get('name'),str):reject('TOP_REPORT_DATA_SCHEMA')
        raw_value=row.get('value')
        if isinstance(raw_value,str):
            if not re.fullmatch(r'\s*(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?\s*',raw_value):reject('TOP_REPORT_DATA_SCHEMA')
            raw_value=float(raw_value.replace(',','').strip())
        value=numeric(raw_value)
        if value is None:reject('TOP_REPORT_DATA_SCHEMA')
        if row['name'].lower() in ('null','nodata','no data','') and value==0:padded+=1;continue
        item={'rank':len(rows)+1,'name':row['name'] if args.get('include_identifiers',False) or public_labels else '[MASKED]','value':value}
        if 'percentage' in row:
            percentage=row['percentage']
            if isinstance(percentage,str):
                if not re.fullmatch(r'\s*\d+(?:\.\d+)?\s*%?\s*',percentage):reject('TOP_REPORT_DATA_SCHEMA')
                percentage=float(percentage.strip().rstrip('%').strip())
            item['percentage']=numeric(percentage)
        if 'risk' in row:
            risk=row['risk']
            if isinstance(risk,list):item['risk']=[numeric(x) for x in risk]
            else:item['risk']=numeric(risk)
        rows.append(item)
    return {**base,'status':'ready' if rows else 'no_data','rows':rows[:args.get('top_n',10)],'returned_rows':min(len(rows),args.get('top_n',10)),'placeholder_rows_removed':padded,'identifiers_masked':not args.get('include_identifiers',False) and not public_labels,'top_n_mode':'client_truncation_of_device_summary','detail_complete':False}

def query(args,client_factory,pinned_handler,transport_factory=Transport):
    section,reports,start,end=validate(args)
    deadline=time.monotonic()+args.get('timeout_seconds',45)
    result={'schema_version':'top-reports-1','dns_profile':args.get('dns_profile','lab-malicious'),'section':section,'start_time':start.isoformat(),'end_time':end.isoformat(),'end_exclusive':True,'query_timezone':'UTC','observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),'delivery_complete':False,'reports':{r:{'status':'pending'} for r in reports},'input_sha256':hashlib.sha256(json.dumps({'section':section,'reports':reports,'start':start.isoformat(),'end':end.isoformat(),'arguments':args},sort_keys=True,separators=(',',':')).encode()).hexdigest(),'retries':0}
    for attempt in range(2):
        transport=None
        try:
            client=client_factory(args.get('dns_profile','lab-malicious'),deadline=deadline)
            result['target']=client.cfg['base_url']
            transport=transport_factory(client,deadline,pinned_handler);transport.start()
            wanted={};statuses={}
            for report in reports:
                if result['reports'][report]['status']!='pending':continue
                identifier,status=transport.request(section,report,start,end)
                if identifier in wanted:reject('TOP_REPORT_DUPLICATE_JOB')
                wanted[identifier]=report;statuses[report]=status
            while wanted:
                identifier,data=transport.collect(wanted)
                report=wanted.pop(identifier)
                result['reports'][report]={**normalize(section,report,data,args,start,end),'endpoint':'/webApi/statistics/'+section+'/'+report+'/'+CATALOG[section][report],'method':'GET','http_status':statuses[report]}
                if statuses[report]==202:result['reports'][report]['warning']='DEVICE_ACCEPTED_WITH_WARNING'
            result['delivery_complete']=True
            return result
        except ReportError as error:
            if error.code=='TOP_REPORT_SESSION_EXPIRED' and attempt==0 and time.monotonic()<deadline:
                result['retries']+=1;continue
            result['error_code']=error.code;result['retryable']=error.retryable;result['action']='stop_and_report';return result
        except (TimeoutError,socket.timeout):
            result.update(error_code='TOP_REPORT_TIMEOUT',retryable=True,action='stop_and_report');return result
        except ssl.SSLError:
            result.update(error_code='TOP_REPORT_TLS_FAILURE',retryable=False,action='stop_and_report');return result
        except urllib.error.HTTPError as error:
            code='TOP_REPORT_AUTH_FAILED' if error.code in (401,403,419) else 'TOP_REPORT_HTTP_'+str(error.code)
            result.update(error_code=code,retryable=False,action='stop_and_report');return result
        except urllib.error.URLError:
            result.update(error_code='TOP_REPORT_CONNECTION_FAILED',retryable=True,action='stop_and_report');return result
        except Exception as error:
            # Match dependency timeout types without emitting their exception text.
            payload=getattr(error,'payload',{})
            code='TOP_REPORT_TIMEOUT' if type(error).__name__=='WebSocketTimeoutException' or isinstance(payload,dict) and payload.get('error_code')=='TOP_REPORT_TIMEOUT' else 'TOP_REPORT_EXECUTION_FAILED'
            result.update(error_code=code,retryable=code=='TOP_REPORT_TIMEOUT',action='stop_and_report');return result
        finally:
            if transport is not None:transport.close()
    return result
