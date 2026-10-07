"""Bounded immutable raw Log pages; delivery is distinct from snapshot completeness."""
from __future__ import annotations
import datetime as dt
import json
from pathlib import Path
import re
import urllib.parse
from zoneinfo import ZoneInfo
try:
 from .manifest_traffic import atomic,canonical,protected_dir,sha,TrafficError
except ImportError:
 from dns_lab_manifest_traffic import atomic,canonical,protected_dir,sha,TrafficError

TX_FIELDS=('identity','transaction_id','transactionId','txid','uuid','id')
TIME_FIELDS=('time','timestamp','datetime','created_at','date')
def row_identity(row):
 if not isinstance(row,dict):return None
 for key in TX_FIELDS:
  value=row.get(key)
  if isinstance(value,(str,int)) and not isinstance(value,bool) and str(value):return str(value)
 return None

def row_time(row):
 if not isinstance(row,dict):return None
 for key in TIME_FIELDS:
  value=row.get(key)
  try:
   if isinstance(value,(int,float)) and not isinstance(value,bool):return dt.datetime.fromtimestamp(value,dt.timezone.utc).isoformat()
   if isinstance(value,str):
    parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:parsed=parsed.replace(tzinfo=ZoneInfo('Asia/Taipei'))
    return parsed.astimezone(dt.timezone.utc).isoformat()
  except (ValueError,OverflowError,OSError):pass
 return None

def export(api,args):
 cfg=api._config();profile=args.get('dns_profile',cfg['default_profile'])
 start=api._parse_time(args['start_time']);end=api._parse_time(args['end_time'])
 if end<=start or end>api._now()-dt.timedelta(minutes=2):raise ValueError('Log window must be positive and end at least two minutes ago')
 max_pages=args.get('max_pages',100);max_rows=args.get('max_rows',250000)
 if type(max_pages) is not int or not 1<=max_pages<=1000 or type(max_rows) is not int or not 1<=max_rows<=2500000:raise ValueError('Invalid bounded export limits')
 filters={}
 mapping={'domains':('qname','domain'),'qtypes':('rtype','type'),'source_ips':('srcip','from'),'categories':('category','category'),'result_terms':('rdata','result')}
 for source,(key,field) in mapping.items():
  if args.get(source):
   if not isinstance(args[source],list):raise ValueError('Log filters must be arrays')
   rule=[str(x) for x in args[source]]
   if source=='domains':rule=[x.strip().lower().rstrip('.') for x in rule]
   if source=='qtypes':rule=[x.upper() for x in rule]
   filters[key]={'field':field,'reverse':1 if source=='domains' and args.get('exclude_domains') else 0,'rule':rule}
 if args.get('actions'):
  codes={'Allow':[0,1],'Block':[2,3,4],'Truncate':[5],'Translate':[6]}
  filters['caction']={'field':'action','reverse':0,'rule':sum((codes[x] for x in args['actions']),[])}
 api._secure_dirs();batch=profile+'-log-'+api._now().strftime('%Y%m%dT%H%M%SZ')+'-'+api.uuid.uuid4().hex[:8]
 out=protected_dir(api.EXPORTS/batch);client=api.LabClient(profile)
 pages=[];count=0;size=0;seen_pages=set();seen_ids=set();duplicate_ids=0;times=[];error=None;delivery=False
 query=urllib.parse.urlencode({'start_time':int(start.timestamp()),'end_time':int(end.timestamp()),'filter':api._canonical(filters)})
 for page in range(1,max_pages+1):
  try:
   status,headers,raw=client.request('/webApi/historylog/proxy/'+str(page)+'?'+query)
   rows=json.loads(raw)
   if status!=200 or not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows):raise TrafficError('LOG_RESPONSE_SCHEMA')
   if size+len(raw)>cfg['max_export_bytes'] or api._free_bytes(out)-len(raw)<cfg['min_free_bytes']:raise TrafficError('LOG_EXPORT_STORAGE_LIMIT')
   if count+len(rows)>max_rows:raise TrafficError('LOG_EXPORT_ROW_LIMIT')
   digest=sha(raw)
   if digest in seen_pages and rows:raise TrafficError('LOG_PAGINATION_REPEATED_PAGE')
   # Raw bytes never transformed; save atomically without replacing existing evidence.
   path=out/('page-%06d.json'%page);fd=api.os.open(path,api.os.O_WRONLY|api.os.O_CREAT|api.os.O_EXCL,0o600)
   with api.os.fdopen(fd,'wb') as f:f.write(raw);f.flush();api.os.fsync(f.fileno())
   seen_pages.add(digest);count+=len(rows);size+=len(raw)
   reported=headers.get('X-Total-Count') or headers.get('x-total-count')
   reported=int(reported) if isinstance(reported,str) and reported.isdigit() else None
   page_times=[]
   for row in rows:
    identity=row_identity(row)
    if identity is not None:
     duplicate_ids+=identity in seen_ids;seen_ids.add(identity)
    time_value=row_time(row)
    if time_value:times.append(time_value);page_times.append(time_value)
   pages.append({'page':page,'offset':None,'cursor':None,'rows':len(rows),'sha256':digest,'api_reported_total':reported,'first_record_time':min(page_times) if page_times else None,'last_record_time':max(page_times) if page_times else None})
   if len(rows)<2500:delivery=True;break
  except TrafficError as e:error=e.code;break
  except Exception:error='LOG_EXPORT_REQUEST_FAILED';break
 else:error='LOG_EXPORT_PAGE_LIMIT'
 manifest={'batch_id':batch,'dns_profile':profile,'start':start.isoformat(),'end':end.isoformat(),'filter':filters,'rows':count,'raw_bytes':size,'pages':pages,'partition':'lab_unlabeled_staging','delivery_complete':delivery,'completeness_verified':False,'snapshot_token':None,'snapshot_verified':False,'api_reported_total':pages[-1]['api_reported_total'] if pages else None,'duplicate_transaction_ids':duplicate_ids if cfg.get('log_identity',{}).get('verified') is True else None,'candidate_identity_duplicate_rows':duplicate_ids,'transaction_identity_fields':list(TX_FIELDS),'transaction_identity_verified':cfg.get('log_identity',{}).get('verified') is True,'first_record_time':min(times) if times else None,'last_record_time':max(times) if times else None,'server_side_filter_verified':False,'error_code':error,'limitations':['Device returns page-number arrays; terminal short page uses observed 2500 page size, not a stable snapshot guarantee.','GUI/API parity and transaction identity are unverified. Raw pages and partial results retained.']}
 digest=atomic(out/'manifest.json',manifest,exclusive=True)
 api._audit('logs_exported',dns_profile=profile,batch_id=batch,rows=count,pages=len(pages),manifest_sha256=digest,delivery_complete=delivery,completeness_verified=False)
 result={k:v for k,v in manifest.items() if k not in ('pages','filter')}
 result.update(output=str(out),manifest_sha256=digest,pages=len(pages),page_metadata=pages,next_action='Use exact manifest reconciliation. Terminal pagination is delivery only; completeness remains unverified without stable snapshot and verified transaction pairing.')
 if error:result.update(error_code=error,retryable=False,action='stop_and_report')
 else:result.pop('error_code')
 return result
