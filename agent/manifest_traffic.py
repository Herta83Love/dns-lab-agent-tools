"""Guarded manifest traffic. Plans are immutable; attempts are never auto-replayed."""
from __future__ import annotations
import contextlib
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import time

TARGET=('172.16.30.222',53)
QTYPES={'A':1,'AAAA':28,'TXT':16,'CNAME':5}
SCHEMA='dns-lab-manifest-plan-1'
MAX_FILE=32*1024*1024
POLICY={'partition':'controlled_candidate','training_ready':False,'split':'training_only_candidate'}
PLAN_ARGS={'type':'object','additionalProperties':False,'properties':{
 'dns_profile':{'type':'string','default':'lab-malicious'},
 'batch_manifest_path':{'type':'string'},'batch_manifest_sha256':{'type':'string','pattern':'^[a-fA-F0-9]{64}$'},
 'session_id':{'type':'string','pattern':'^[a-zA-Z0-9_-]{1,80}$'},'planned_queries_sha256':{'type':'string','pattern':'^[a-fA-F0-9]{64}$'},
 'qps':{'type':'number','minimum':0.2,'maximum':0.5,'default':0.5},
 'queries_per_session':{'type':'integer','minimum':1,'maximum':500,'default':500,'description':'Explicit reviewed prefix size; original full JSONL SHA remains bound, selected list separately hashed.'},
 'cooldown_seconds':{'type':'integer','minimum':300,'default':300},
 'stop_on_any_loss':{'type':'boolean','const':True,'default':True},
 'dry_run':{'type':'boolean','default':True},'recovery_from_plan_id':{'type':'string'},
 },'required':['batch_manifest_path','batch_manifest_sha256','session_id','planned_queries_sha256']}
RUN_ARGS={'type':'object','additionalProperties':False,'properties':{'plan_id':{'type':'string'},'approval_token':{'type':'string'}},'required':['plan_id','approval_token']}
STATUS_ARGS={'type':'object','additionalProperties':False,'properties':{'plan_id':{'type':'string'}},'required':['plan_id']}
RECON_ARGS={'type':'object','additionalProperties':False,'properties':{'plan_id':{'type':'string'},'start_time':{'type':'string'},'end_time':{'type':'string'}},'required':['plan_id','start_time','end_time']}
DEFINITIONS=[{'type':'function','function':{'name':name,'description':desc,'parameters':schema}} for name,desc,schema in [
 ('lab_dns_plan_manifest_traffic','Create immutable one-session manifest preview; default dry_run. Exact protected manifest/list hashes, session marker, max 500 queries, 0.2–0.5 QPS, fixed lab target. No sends. Review SHA256 and obtain human approval for a non-dry plan.',PLAN_ARGS),
 ('lab_dns_run_manifest_traffic_plan','Claim an approved non-dry manifest plan once and start a durable worker. Rechecks fresh historical load and Log API. Returns promptly; use traffic status. Never retry an interrupted session. Requires one-time approval token; never appliance credentials.',RUN_ARGS),
 ('lab_dns_get_traffic_plan_status','Read immutable manifest plan/worker/receipt status without qnames or tokens. Identifies completed, not attempted and uncertain attempts after restart. Stop on loss; recovery requires a new plan.',STATUS_ARGS),
 ('lab_dns_reconcile_manifest_logs','Read bounded unfiltered Log export then exact qname/qtype/session-marker intersection with the immutable plan and receipts. Retains raw pages and separate matched/missing/duplicate/ambiguous artifacts. Unknown snapshot or pairing never establishes complete or training readiness.',RECON_ARGS),
]]

class TrafficError(Exception):
 def __init__(self,code):self.code=code;super().__init__(code)
def fail(code):raise TrafficError(code)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def now():return dt.datetime.now(dt.timezone.utc)
def timestamp():return now().isoformat()
def protected_dir(path):
 path.mkdir(parents=True,exist_ok=True,mode=0o700)
 if path.is_symlink() or path.stat().st_mode & 0o077:fail('TRAFFIC_WORKSPACE_NOT_PRIVATE')
 return path
def atomic(path,value,exclusive=False):
 protected_dir(path.parent)
 raw=canonical(value);temp=path.with_name('.'+path.name+'.'+secrets.token_hex(6))
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:
  with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  if exclusive:os.link(temp,path);temp.unlink()
  else:os.replace(temp,path)
  fd=os.open(path.parent,os.O_RDONLY)
  try:os.fsync(fd)
  finally:os.close(fd)
 finally:
  if temp.exists():temp.unlink()
 return sha(raw)
def read_private(path,limit=MAX_FILE):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'rb') as f:
   s=os.fstat(f.fileno())
   if not stat.S_ISREG(s.st_mode) or s.st_mode&0o077 or s.st_uid!=os.getuid():fail('TRAFFIC_FILE_NOT_PRIVATE')
   data=f.read(limit+1)
  if len(data)>limit:fail('TRAFFIC_FILE_TOO_LARGE')
  return data
 except (OSError,ValueError):fail('TRAFFIC_FILE_UNAVAILABLE')
def parse(v):
 try:t=dt.datetime.fromisoformat(v.replace('Z','+00:00'))
 except (ValueError,AttributeError):fail('TRAFFIC_INVALID_TIME')
 if t.tzinfo is None:fail('TRAFFIC_TIMEZONE_REQUIRED')
 return t.astimezone(dt.timezone.utc)
def normalize_name(v):return v.lower().rstrip('.')
def valid_name(v):
 if not isinstance(v,str) or len(v.rstrip('.'))>253 or not re.fullmatch(r'(?:[A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,63}\.?',v):fail('TRAFFIC_INVALID_QNAME')
 return v
def private_manifest_root(api):
 cfg=api._config();root=api.ROOT.resolve();base=Path(cfg.get('manifest_root',root/'manifests'))
 if not base.is_absolute() or base.is_symlink():fail('TRAFFIC_MANIFEST_ROOT_INVALID')
 base=base.resolve()
 if not base.is_relative_to(root) or base==root:fail('TRAFFIC_MANIFEST_ROOT_INVALID')
 protected_dir(base);return base

LABEL_MAP={'control_only':{'tunneling':1,'exfiltration':0},'one_way_chunks':{'tunneling':0,'exfiltration':1},'mixed_control_chunks':{'tunneling':1,'exfiltration':1}}
LABEL_MAP_VERSION='eidolon-controlled-class-map-v1'
def bounded_file(base,path):
 path=Path(path)
 if not path.is_absolute():path=base/path
 if any(p.is_symlink() for p in [path,*path.parents]):fail('TRAFFIC_MANIFEST_PATH_INVALID')
 path=path.resolve()
 if not path.is_relative_to(base):fail('TRAFFIC_MANIFEST_PATH_INVALID')
 return path

def json_file(path,digest):
 raw=read_private(path)
 if not isinstance(digest,str) or not re.fullmatch('[a-fA-F0-9]{64}',digest) or not secrets.compare_digest(sha(raw),digest.lower()):fail('TRAFFIC_ARTIFACT_HASH_MISMATCH')
 try:return json.loads(raw)
 except (ValueError,UnicodeError):fail('TRAFFIC_MANIFEST_SCHEMA')

def load_manifest(api,args):
 base=private_manifest_root(api);path=Path(args['batch_manifest_path'])
 if not path.is_absolute() or path.suffix!='.json':fail('TRAFFIC_MANIFEST_PATH_INVALID')
 path=bounded_file(base,path);manifest=json_file(path,args['batch_manifest_sha256'])
 if not isinstance(manifest,dict) or manifest.get('partition')!='controlled_candidate' or manifest.get('training_ready') is not False:fail('TRAFFIC_MANIFEST_POLICY')
 materialized=path.parent;lineage=manifest.get('lineage',{})
 if not isinstance(lineage,dict):fail('TRAFFIC_MANIFEST_SCHEMA')
 catalog_ref=lineage.get('catalog',{})
 if not isinstance(catalog_ref,dict) or catalog_ref.get('path')!='catalog.jsonl':fail('TRAFFIC_CATALOG_SCHEMA')
 raw=read_private(bounded_file(materialized,catalog_ref['path']))
 if sha(raw)!=catalog_ref.get('sha256'):fail('TRAFFIC_CATALOG_HASH_MISMATCH')
 try:catalog=[json.loads(line) for line in raw.splitlines() if line.strip()]
 except ValueError:fail('TRAFFIC_CATALOG_SCHEMA')
 if any(not isinstance(c,dict) for c in catalog):fail('TRAFFIC_CATALOG_SCHEMA')
 ids=[c.get('session_id') for c in catalog]
 if len(ids)!=len(set(ids)):fail('TRAFFIC_SESSION_NOT_UNIQUE')
 selected=[c for c in catalog if c.get('session_id')==args['session_id']]
 sessions=lineage.get('sessions',[])
 if not isinstance(sessions,list):fail('TRAFFIC_MANIFEST_SCHEMA')
 ls=[c for c in sessions if isinstance(c,dict) and c.get('session_id')==args['session_id']]
 if len(selected)!=1 or len(ls)!=1:fail('TRAFFIC_SESSION_NOT_UNIQUE')
 c=selected[0];ref=ls[0]
 if c.get('split')!='training_only_candidate':fail('TRAFFIC_MANIFEST_POLICY')
 if c.get('planned_queries_path')!=ref.get('planned_queries_path') or c.get('query_list_sha256')!=ref.get('query_list_sha256'):fail('TRAFFIC_SESSION_LINEAGE_MISMATCH')
 relative=c.get('planned_queries_path')
 if not isinstance(relative,str) or Path(relative).is_absolute() or Path(relative).parts!=('sessions',args['session_id'],'planned-queries.jsonl'):fail('TRAFFIC_MANIFEST_PATH_INVALID')
 query_path=bounded_file(materialized,relative)
 sm=json_file(query_path.parent/'session-manifest.json',ref.get('session_manifest_sha256'))
 if not isinstance(sm,dict) or sm.get('partition')!='controlled_candidate' or sm.get('training_ready') is not False or sm.get('split')!='training_only_candidate':fail('TRAFFIC_MANIFEST_POLICY')
 for key in ('session_id','split_group_id','class_code','session_seed','params','record_count','query_list_sha256'):
  if sm.get(key)!=c.get(key):fail('TRAFFIC_SESSION_LINEAGE_MISMATCH')
 raw=read_private(query_path);digest=sha(raw)
 if digest!=c.get('query_list_sha256') or not secrets.compare_digest(digest,args['planned_queries_sha256'].lower()):fail('TRAFFIC_QUERY_HASH_MISMATCH')
 try:queries=[json.loads(line) for line in raw.splitlines() if line.strip()]
 except ValueError:fail('TRAFFIC_QUERY_SCHEMA')
 if not 1<=len(queries)<=500 or len(queries)!=c.get('record_count'):fail('TRAFFIC_QUERY_COUNT')
 marker=c.get('params',{}).get('session_label')
 if not isinstance(marker,str) or not re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',marker):fail('TRAFFIC_SESSION_MARKER_INVALID')
 group=c.get('split_group_id');class_code=c.get('class_code')
 if not isinstance(group,str) or not re.fullmatch('[A-Za-z0-9_.-]{1,120}',group) or class_code not in LABEL_MAP:fail('TRAFFIC_MANIFEST_SCHEMA')
 names=set();cfg=api._config();previous=-1
 for i,q in enumerate(queries):
  if not isinstance(q,dict) or set(q)!={'index','qname','qtype','intended_relative_send_time_ms','frame_role','chunk_sha256'}:fail('TRAFFIC_QUERY_SCHEMA')
  if type(q['index']) is not int or q['index']!=i:fail('TRAFFIC_QUERY_ORDER')
  relative_ms=q['intended_relative_send_time_ms']
  if type(relative_ms) is not int or not 0<=relative_ms<=86400000 or relative_ms<previous:fail('TRAFFIC_QUERY_ORDER')
  previous=relative_ms;name=normalize_name(valid_name(q.get('qname')))
  if marker not in name.split('.') or not any(name.endswith('.'+suffix) for suffix in cfg['allowed_forward_suffixes']):fail('TRAFFIC_QUERY_MARKER_OR_SUFFIX')
  if name in names:fail('TRAFFIC_QNAME_NOT_UNIQUE')
  names.add(name)
  if q.get('qtype') not in QTYPES:fail('TRAFFIC_QTYPE_NOT_ALLOWED')
  if not isinstance(q['frame_role'],str) or len(q['frame_role'])>80:fail('TRAFFIC_QUERY_SCHEMA')
  if q['chunk_sha256'] is not None and (not isinstance(q['chunk_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',q['chunk_sha256'])):fail('TRAFFIC_QUERY_SCHEMA')
 session={**c,'session_marker':marker,'split_group':group,'intended_label':LABEL_MAP[class_code],'label_mapping_version':LABEL_MAP_VERSION,'planned_queries':[{'query_id':str(q['index']),**q} for q in queries],
 'catalog_sha256':catalog_ref['sha256'],'session_manifest_sha256':ref['session_manifest_sha256']}
 return session,path,digest

def plan_path(api,plan_id):
 if not isinstance(plan_id,str) or not re.fullmatch('manifest-[A-Za-z0-9T-]+',plan_id):fail('TRAFFIC_PLAN_ID_INVALID')
 return api.PLANS/(plan_id+'.json')
def load_plan(api,plan_id):
 path=plan_path(api,plan_id)
 try:p=json.loads(read_private(path))
 except (ValueError,UnicodeError):fail('TRAFFIC_PLAN_SCHEMA')
 digest=p.pop('plan_sha256',None)
 if digest!=sha(canonical(p)) or p.get('schema')!=SCHEMA or p.get('plan_id')!=plan_id:fail('TRAFFIC_PLAN_HASH_MISMATCH')
 p['plan_sha256']=digest;return p

def make_plan(api,args):
 from jsonschema import Draft202012Validator
 if not Draft202012Validator(PLAN_ARGS).is_valid(args):fail('TRAFFIC_INVALID_ARGUMENTS')
 if not math.isfinite(args.get('qps',0.5)):fail('TRAFFIC_INVALID_ARGUMENTS')
 cfg=api._config();profile=args.get('dns_profile',cfg['default_profile']);_,p=api._profile(profile)
 if profile!='lab-malicious' or (p.get('traffic_dns_server'),p.get('traffic_dns_port'))!=TARGET or p.get('base_url')!='https://172.16.30.209:1606':fail('TRAFFIC_LAB_TARGET_REQUIRED')
 session,path,digest=load_manifest(api,args);api._secure_dirs()
 selected=session['planned_queries'][:args.get('queries_per_session',500)]
 recovery=args.get('recovery_from_plan_id')
 if recovery:
  old=load_plan(api,recovery)
  if old['session_id']==session['session_id']:fail('TRAFFIC_RECOVERY_REQUIRES_NEW_SESSION')
 plan_id='manifest-'+now().strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(5)
 p={'schema':SCHEMA,'kind':'manifest_traffic','plan_id':plan_id,'created_at':timestamp(),'expires_at':(now()+dt.timedelta(seconds=max(1800,cfg['plan_ttl_seconds']))).isoformat(),
 'dns_profile':profile,'session_id':session['session_id'],'session_marker':session['session_marker'],'split_group':session['split_group'],'intended_label':session['intended_label'],
 'batch_manifest_path':str(path),'batch_manifest_sha256':args['batch_manifest_sha256'].lower(),'planned_queries_sha256':digest,
 'class_code':session['class_code'],'label_mapping_version':LABEL_MAP_VERSION,'catalog_sha256':session['catalog_sha256'],'session_manifest_sha256':session['session_manifest_sha256'],'selection':{'mode':'reviewed_prefix','source_query_count':len(session['planned_queries']),'count':len(selected),'selected_queries_sha256':sha(canonical(selected))},'queries':selected,'qps':args.get('qps',0.5),'cooldown_seconds':args.get('cooldown_seconds',300),'stop_on_any_loss':True,'dry_run':args.get('dry_run',True),
 'target_ip':TARGET[0],'target_port':TARGET[1],'dns_transport':'UDP','recovery_from_plan_id':recovery,
 'runtime_identity':api.runtime_identity(cfg),'preflight_policy':{'cpu_max_percent':85,'memory_max_percent':90,'max_report_age_seconds':600,'report_is_historical':True,'missing_is_not_zero':True,'login_and_log_required':True}}
 p['plan_sha256']=sha(canonical(p));atomic(plan_path(api,plan_id),p,exclusive=True)
 api._audit('manifest_plan_created',plan_id=plan_id,plan_sha256=p['plan_sha256'],session_id=p['session_id'],queries=len(p['queries']))
 return {'plan_id':plan_id,'plan_sha256':p['plan_sha256'],'dry_run':p['dry_run'],'planned':len(p['queries']),'session_id':p['session_id'],'planned_queries_sha256':digest,'batch_manifest_sha256':p['batch_manifest_sha256'],'requires_human_approval':not p['dry_run'],'target_ip':TARGET[0],'target_port':53,'qps':p['qps'],'cooldown_seconds':p['cooldown_seconds'],'selection':p['selection'],'preflight_policy':p['preflight_policy'],'next_action':'Review protected plan and approve exact plan SHA256; dry-run plans cannot send. Use a new non-dry plan for execution.'}

def runs(api):return protected_dir(api.ROOT/'traffic_runs')
def state_dir(api,plan_id):return protected_dir(runs(api)/plan_id)
def state(api,plan_id):
 path=state_dir(api,plan_id)/'state.json'
 return json.loads(read_private(path)) if path.exists() else {'status':'awaiting_human_approval'}
@contextlib.contextmanager
def locked(api):
 import fcntl
 path=runs(api)/'.lock';fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 try:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:fail('TRAFFIC_SESSION_BUSY')
  yield
 finally:os.close(fd)
def alive(pid):
 try:os.kill(pid,0);return True
 except (ProcessLookupError,TypeError):return False
 except PermissionError:return True

def claim(api,args,spawn=True):
 from jsonschema import Draft202012Validator
 if not Draft202012Validator(RUN_ARGS).is_valid(args):fail('TRAFFIC_INVALID_ARGUMENTS')
 p=load_plan(api,args['plan_id'])
 if p['dry_run']:fail('TRAFFIC_DRY_RUN_ONLY')
 if now()>parse(p['expires_at']):fail('TRAFFIC_PLAN_EXPIRED')
 cfg=api._config();_,profile=api._profile(p['dns_profile'])
 if (profile.get('traffic_dns_server'),profile.get('traffic_dns_port'))!=TARGET:fail('TRAFFIC_LAB_TARGET_REQUIRED')
 if api.runtime_identity(cfg)['config_fingerprint']!=p['runtime_identity']['config_fingerprint']:fail('TRAFFIC_CONFIG_CHANGED')
 if any(api.runtime_identity(cfg).get(k)!=p['runtime_identity'].get(k) for k in ('git_commit','source_fingerprint','tool_contract_version')):fail('TRAFFIC_RUNTIME_CHANGED')
 load_manifest(api,{'batch_manifest_path':p['batch_manifest_path'],'batch_manifest_sha256':p['batch_manifest_sha256'],'session_id':p['session_id'],'planned_queries_sha256':p['planned_queries_sha256']})
 auth_path=api.PLANS/(p['plan_id']+'.approval.json')
 if not auth_path.exists():fail('TRAFFIC_APPROVAL_REQUIRED')
 auth=json.loads(read_private(auth_path))
 if auth.get('plan_sha256')!=p['plan_sha256'] or not secrets.compare_digest(sha(args['approval_token'].encode()),auth.get('token_sha256','')):fail('TRAFFIC_APPROVAL_INVALID')
 with locked(api):
  active_path=runs(api)/'active.json';active=json.loads(read_private(active_path)) if active_path.exists() else {}
  if active.get('status') in ('queued','running','preflight','reconciling'):
   if not alive(active.get('worker_pid')) and p.get('recovery_from_plan_id')==active.get('plan_id'):
    active.update(status='interrupted',blocked_on_loss=True,finished_at=timestamp());atomic(active_path,active)
   else:fail('TRAFFIC_SESSION_BUSY_OR_INTERRUPTED')
  if active.get('blocked_on_loss') and p.get('recovery_from_plan_id')!=active.get('plan_id'):fail('TRAFFIC_RECOVERY_PLAN_REQUIRED')
  if active.get('finished_at') and (now()-parse(active['finished_at'])).total_seconds()<max(300,active.get('cooldown_seconds',300)):fail('TRAFFIC_COOLDOWN_REQUIRED')
  # Session use is persisted before launching: a crash cannot make it replayable.
  session_key=sha(p['session_id'].encode());used=runs(api)/('session-'+session_key+'.json')
  if used.exists():fail('TRAFFIC_SESSION_ALREADY_CLAIMED')
  atomic(used,{'plan_id':p['plan_id'],'session_id':p['session_id'],'claimed_at':timestamp()},exclusive=True)
  s={'status':'queued','plan_id':p['plan_id'],'session_id':p['session_id'],'plan_sha256':p['plan_sha256'],'claimed_at':timestamp(),'cooldown_seconds':p['cooldown_seconds'],'approval_consumed':True}
  atomic(state_dir(api,p['plan_id'])/'state.json',s);atomic(active_path,s)
  if spawn:
   try:
    child=subprocess.Popen([sys.executable,'-m','agent.manifest_worker','--config',str(api.CONFIG_PATH.resolve()),'--plan-id',p['plan_id']],cwd=Path(api.__file__).resolve().parent.parent,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    s['worker_pid']=child.pid;atomic(state_dir(api,p['plan_id'])/'state.json',s);atomic(active_path,s)
   except Exception:
    s.update(status='interrupted',blocked_on_loss=True,finished_at=timestamp());atomic(state_dir(api,p['plan_id'])/'state.json',s);atomic(active_path,s);fail('TRAFFIC_WORKER_START_FAILED')
  api._audit('manifest_execution_claimed',plan_id=p['plan_id'],session_id=p['session_id'])
 return {'plan_id':p['plan_id'],'status':'queued','approval_consumed':True,'next_action':'Poll lab_dns_get_traffic_plan_status. Do not repeat run; any recovery requires a new session and plan.'}

def receipt_paths(api,plan_id):return protected_dir(state_dir(api,plan_id)/'receipts')
def receipt_projection(api,p):
 root=receipt_paths(api,p['plan_id']);out=[]
 for q in p['queries']:
  key=sha(q['query_id'].encode());receipt=root/(key+'.json');intent=root/(key+'.intent.json')
  if receipt.exists():out.append(json.loads(read_private(receipt)))
  elif intent.exists():out.append({**json.loads(read_private(intent)),'response_status':'uncertain','send_succeeded':None,'error':'PROCESS_INTERRUPTED_OUTCOME_UNKNOWN','timeout':None,'rcode':None,'latency_ms':None,'source_host':None,'execution_output_sha256':None})
  else:out.append({'query_id':q['query_id'],'qname':q['qname'],'qtype':q['qtype'],'response_status':'not_attempted','session_id':p['session_id'],'split_group':p['split_group'],'intended_label':p['intended_label'],'manifest_sha256':p['batch_manifest_sha256'],'planned_queries_sha256':p['planned_queries_sha256'],'catalog_sha256':p['catalog_sha256'],'session_manifest_sha256':p['session_manifest_sha256'],'selected_queries_sha256':p['selection']['selected_queries_sha256'],'plan_sha256':p['plan_sha256'],'intended_relative_send_time_ms':q['intended_relative_send_time_ms'],'planned_send_time':None,'actual_send_time':None,'dns_transport':'UDP','source_host':None,'target_ip':TARGET[0],'target_port':53,'send_succeeded':False,'rcode':None,'timeout':None,'error':None,'latency_ms':None,'tool_contract_version':api.TOOL_CONTRACT_VERSION,'git_commit':p['runtime_identity']['git_commit'],'execution_input_sha256':sha(canonical(q)),'execution_output_sha256':None})
 return out

def status(api,args):
 p=load_plan(api,args['plan_id']);s=state(api,p['plan_id']);receipts=receipt_projection(api,p)
 status_name=s['status']
 if status_name=='awaiting_human_approval':
  if now()>parse(p['expires_at']):status_name='expired'
  elif p['dry_run']:status_name='dry_run'
  elif (api.PLANS/(p['plan_id']+'.approval.json')).exists():status_name='approved'
 if status_name in ('queued','preflight','running','reconciling') and not alive(s['worker_pid']):status_name='interrupted'
 counts={name:sum(r['response_status']==name for r in receipts) for name in ('received','timeout','error','uncertain','not_attempted')}
 return {'plan_id':p['plan_id'],'plan_sha256':p['plan_sha256'],'session_id':p['session_id'],'status':status_name,'dry_run':p['dry_run'],'planned':len(receipts),'send_attempted':len(receipts)-counts['not_attempted'],'send_succeeded':sum(bool(r.get('send_succeeded')) for r in receipts),'dns_responses':counts['received'],'receipt_counts':counts,'receipts_path':str(receipt_paths(api,p['plan_id'])),'preflight':s.get('preflight'),'postflight':s.get('postflight'),'reconciliation':s.get('reconciliation'),'error_code':s.get('error_code'),'complete':False if not s.get('reconciliation') else s['reconciliation'].get('complete',False),'training_ready':False,'next_action':('Dry-run preview only; create a distinct non-dry plan for reviewed human approval.' if p['dry_run'] else 'No automatic retransmission. Reconcile logs; missing/duplicate/uncertain results remain controlled_partial. Interrupted worker requires operator review and a newly approved recovery plan.')}

def preflight(api,p):
 cap=api._execute_dns_lab_tool('lab_dns_get_top_report_capabilities',{'dns_profile':p['dns_profile']})
 if not cap.get('websocket_dependency_available'):fail('TRAFFIC_PREFLIGHT_REPORT_DEPENDENCY')
 report=api._execute_dns_lab_tool('lab_dns_get_top_report',{'dns_profile':p['dns_profile'],'section':'system','reports':['cpu_us','memory'],'window_minutes':10,'timeout_seconds':45,'stale_after_seconds':600})
 safe={'observed_at':timestamp(),'historical_statistics':True,'report_sha256':sha(canonical(report)),'delivery_complete':report.get('delivery_complete'),'metrics':{}}
 for name in ('cpu_us','memory'):
  item=report.get('reports',{}).get(name,{});series=item.get('series',[])
  if len(series)==1:safe['metrics'][name]={key:series[0].get(key) for key in ('latest','age_seconds','latest_time','status')}
 def reject_gate(code):
  error=TrafficError(code);error.evidence=safe;raise error
 if report.get('delivery_complete') is not True:reject_gate('TRAFFIC_PREFLIGHT_REPORT_INCOMPLETE')
 for name,ceiling in [('cpu_us',85),('memory',90)]:
  r=report.get('reports',{}).get(name,{});series=r.get('series',[])
  if r.get('status')!='ready' or len(series)!=1:reject_gate('TRAFFIC_PREFLIGHT_REPORT_UNAVAILABLE')
  v=series[0];latest=v.get('latest');age=v.get('age_seconds')
  safe['metrics'][name]={'latest':latest,'age_seconds':age,'latest_time':v.get('latest_time')}
  if isinstance(latest,bool) or not isinstance(latest,(float,int)) or not math.isfinite(latest) or not 0<=latest<=ceiling:reject_gate('TRAFFIC_PREFLIGHT_LOAD_HIGH')
  try:freshness=(now()-parse(v.get('latest_time'))).total_seconds()
  except TrafficError:reject_gate('TRAFFIC_PREFLIGHT_REPORT_STALE')
  if v.get('status')!='ready' or isinstance(age,bool) or not isinstance(age,(int,float)) or not math.isfinite(age) or not 0<=age<=600 or not 0<=freshness<=600:reject_gate('TRAFFIC_PREFLIGHT_REPORT_STALE')
  safe['metrics'][name]={'latest':latest,'age_seconds':age,'latest_time':v['latest_time']}
 client=api.LabClient(p['dns_profile']);end=now()-dt.timedelta(minutes=3);start=end-dt.timedelta(minutes=1)
 query=api.urllib.parse.urlencode({'start_time':int(start.timestamp()),'end_time':int(end.timestamp()),'filter':'{}'})
 status_code,_,raw=client.request('/webApi/historylog/proxy/1?'+query)
 try:rows=json.loads(raw)
 except ValueError:reject_gate('TRAFFIC_PREFLIGHT_LOG_UNAVAILABLE')
 if status_code!=200 or not isinstance(rows,list):reject_gate('TRAFFIC_PREFLIGHT_LOG_UNAVAILABLE')
 safe['log_api']={'http_status':status_code,'row_count':len(rows),'response_sha256':sha(raw)}
 return safe

def _decode_question(packet):
 offset=12;labels=[]
 while offset<len(packet):
  n=packet[offset];offset+=1
  if n==0:break
  if n>63 or offset+n>len(packet):raise ValueError()
  labels.append(packet[offset:offset+n].decode('ascii'));offset+=n
 if offset+4>len(packet):raise ValueError()
 qt,qc=struct.unpack('!HH',packet[offset:offset+4]);return '.'.join(labels).lower(),qt,qc

def send_dns(q,target=TARGET,timeout=2):
 """One UDP packet, no retransmission, no alternate resolver or TCP fallback."""
 start=time.monotonic();sent=False;source=None;sent_at=None
 identifier=secrets.randbelow(65536)
 name=b''.join(bytes([len(x)])+x.encode('ascii') for x in q['qname'].rstrip('.').split('.'))+b'\0'
 packet=struct.pack('!HHHHHH',identifier,0x0100,1,0,0,0)+name+struct.pack('!HH',QTYPES[q['qtype']],1)
 try:
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
   sock.settimeout(timeout);sock.connect(target);source=sock.getsockname()[0];sent_at=timestamp();sock.send(packet);sent=True
   while True:
    remaining=timeout-(time.monotonic()-start)
    if remaining<=0:raise TimeoutError()
    sock.settimeout(remaining);response=sock.recv(65535)
    if len(response)<12:continue
    rid,flags,qd=struct.unpack('!HHH',response[:6])
    if rid!=identifier or not flags&0x8000 or qd!=1:continue
    try:rname,rtype,rclass=_decode_question(response)
    except ValueError:continue
    if (rname,rtype,rclass)!=(normalize_name(q['qname']),QTYPES[q['qtype']],1):continue
    truncated=bool(flags&0x0200)
    return {'send_succeeded':True,'response_status':'error' if truncated else 'received','rcode':flags&15,'timeout':False,'error':'DNS_TRUNCATED_NO_RETRY' if truncated else None,'latency_ms':round((time.monotonic()-start)*1000,3),'source_host':source,'dns_query_id':identifier,'actual_send_time':sent_at}
 except (socket.timeout,TimeoutError):return {'send_succeeded':sent,'response_status':'timeout','rcode':None,'timeout':True,'error':'DNS_TIMEOUT','latency_ms':round((time.monotonic()-start)*1000,3),'source_host':source,'dns_query_id':identifier,'actual_send_time':sent_at}
 except OSError:return {'send_succeeded':sent,'response_status':'error','rcode':None,'timeout':False,'error':'DNS_TRANSPORT_ERROR','latency_ms':round((time.monotonic()-start)*1000,3),'source_host':source,'dns_query_id':identifier,'actual_send_time':sent_at}

def execute_worker(api,plan_id,sender=send_dns,sleeper=time.sleep):
 p=load_plan(api,plan_id);s=state(api,plan_id);directory=state_dir(api,plan_id)
 with locked(api):
  active=json.loads(read_private(runs(api)/'active.json'))
  if s.get('status')!='queued' or not s.get('approval_consumed') or s.get('plan_sha256')!=p['plan_sha256'] or active.get('plan_id')!=plan_id:fail('TRAFFIC_WORKER_NOT_AUTHORIZED')
  s.update(status='preflight',worker_pid=os.getpid());atomic(directory/'state.json',s);atomic(runs(api)/'active.json',s)
  blocked=True
  try:
   if p['dry_run'] or (p['target_ip'],p['target_port'])!=TARGET:fail('TRAFFIC_WORKER_NOT_AUTHORIZED')
   if api.runtime_identity(api._config())['config_fingerprint']!=p['runtime_identity']['config_fingerprint']:fail('TRAFFIC_CONFIG_CHANGED')
   if any(api.runtime_identity(api._config()).get(k)!=p['runtime_identity'].get(k) for k in ('git_commit','source_fingerprint','tool_contract_version')):fail('TRAFFIC_RUNTIME_CHANGED')
   load_manifest(api,{'batch_manifest_path':p['batch_manifest_path'],'batch_manifest_sha256':p['batch_manifest_sha256'],'session_id':p['session_id'],'planned_queries_sha256':p['planned_queries_sha256']})
   s['preflight']=preflight(api,p);atomic(directory/'preflight.json',s['preflight'])
   s.update(status='running',started_at=timestamp());atomic(directory/'state.json',s)
   started=time.monotonic();last_send=None;anchor=now();root=receipt_paths(api,plan_id)
   for index,q in enumerate(p['queries']):
    schedule_offset=max(index/p['qps'],q['intended_relative_send_time_ms']/1000)
    due=max(started+schedule_offset,(last_send+1/p['qps']) if last_send is not None else started)
    wait=due-time.monotonic()
    if wait>0:sleeper(wait)
    schedule_offset=due-started
    key=sha(q['query_id'].encode());receipt=root/(key+'.json');intent=root/(key+'.intent.json')
    if receipt.exists() or intent.exists():fail('TRAFFIC_ATTEMPT_ALREADY_EXISTS')
    record={'query_id':q['query_id'],'session_id':p['session_id'],'split_group':p['split_group'],'intended_label':p['intended_label'],
     'manifest_sha256':p['batch_manifest_sha256'],'planned_queries_sha256':p['planned_queries_sha256'],'catalog_sha256':p['catalog_sha256'],'session_manifest_sha256':p['session_manifest_sha256'],'selected_queries_sha256':p['selection']['selected_queries_sha256'],'plan_sha256':p['plan_sha256'],
     'qname':q['qname'],'qtype':q['qtype'],'planned_send_time':(anchor+dt.timedelta(milliseconds=q['intended_relative_send_time_ms'])).isoformat(),'rate_limited_send_time':(anchor+dt.timedelta(seconds=schedule_offset)).isoformat(),'send_intent_time':timestamp(),'actual_send_time':None,'intended_relative_send_time_ms':q['intended_relative_send_time_ms'],'class_code':p['class_code'],'label_mapping_version':LABEL_MAP_VERSION,
     'dns_transport':'UDP','target_ip':TARGET[0],'target_port':53,'tool_contract_version':api.TOOL_CONTRACT_VERSION,'git_commit':p['runtime_identity']['git_commit'],
     'execution_input_sha256':sha(canonical(q)),'preflight_evidence_sha256':sha(canonical(s['preflight']))}
    atomic(intent,record,exclusive=True) # fsync before network; crash makes outcome uncertain.
    result=sender(q);record.update(result);record['execution_output_sha256']=sha(canonical(result));atomic(receipt,record,exclusive=True)
    last_send=time.monotonic()
    if result['response_status']!='received':break
   s['send_finished_at']=timestamp();atomic(directory/'state.json',s)
   s['postflight']=preflight(api,p);atomic(directory/'postflight.json',s['postflight'])
   s.update(status='awaiting_reconciliation')
   # Loss is unknown until exact Log pairing succeeds. Block next sessions by default.
   s['blocked_on_loss']=True
   atomic(directory/'state.json',s)
  except BaseException as error:
   if isinstance(error,TrafficError) and hasattr(error,'evidence'):
    key='postflight' if s.get('status')=='running' else 'preflight';s[key]=error.evidence;atomic(directory/(key+'.json'),error.evidence)
   s.update(status='controlled_partial',error_code=error.code if isinstance(error,TrafficError) else 'TRAFFIC_EXECUTION_STOPPED',blocked_on_loss=True)
  finally:
   receipts=receipt_projection(api,p);atomic(directory/'receipt-index.json',{'receipts':receipts,'plan_sha256':p['plan_sha256'],'preflight_evidence_sha256':sha(canonical(s['preflight'])) if s.get('preflight') else None,'postflight_evidence_sha256':sha(canonical(s['postflight'])) if s.get('postflight') else None})
   s['finished_at']=timestamp();s['blocked_on_loss']=blocked;atomic(directory/'state.json',s);atomic(runs(api)/'active.json',s)
 return status(api,{'plan_id':plan_id})

def reconciliation(api,p,export_result):
 """Exact intersection; pairing must use an explicitly validated identity mapping."""
 try:
  from .log_exports import row_time
 except ImportError:
  from dns_lab_log_exports import row_time
 directory=Path(export_result['output']);manifest_raw=read_private(directory/'manifest.json')
 if sha(manifest_raw)!=export_result['manifest_sha256']:fail('TRAFFIC_LOG_ARTIFACT_CHANGED')
 manifest=json.loads(manifest_raw)
 raw_rows=[]
 for page in manifest['pages']:
  raw=read_private(directory/('page-%06d.json'%page['page']))
  if sha(raw)!=page['sha256']:fail('TRAFFIC_LOG_ARTIFACT_CHANGED')
  raw_rows.extend(json.loads(raw))
 planned={normalize_name(q['qname']):q for q in p['queries']};receipts={r['query_id']:r for r in receipt_projection(api,p)}
 identity=api._config().get('log_identity',{})
 qfield=identity.get('qname_field','qname');qtfield=identity.get('qtype_field','qtype')
 matched={q['query_id']:[] for q in p['queries']};unrelated=0;ambiguous=[];seen={};exact_duplicates=[]
 for row in raw_rows:
  name=row.get(qfield)
  if not isinstance(name,str):unrelated+=1;continue
  normalized=normalize_name(name)
  if normalized not in planned or p['session_marker'] not in normalized.split('.'):
   unrelated+=1;continue
  q=planned[normalized];rtype=row.get(qtfield)
  if isinstance(rtype,int) and not isinstance(rtype,bool):rtype={v:k for k,v in QTYPES.items()}.get(rtype)
  if not isinstance(rtype,str) or rtype.upper()!=q['qtype']:
   ambiguous.append({'query_id':q['query_id'],'reason':'QTYPE_MISSING_OR_DIFFERENT'});continue
  digest=sha(canonical(row))
  if digest in seen:exact_duplicates.append({'query_id':q['query_id'],'record_sha256':digest})
  seen[digest]=True;matched[q['query_id']].append(row)
 missing=[];duplicates=[];pairs=[]
 for q in p['queries']:
  query_id=q['query_id'];rows=matched[query_id];receipt=receipts[query_id]
  if not rows:missing.append({'query_id':query_id,'qname':q['qname'],'qtype':q['qtype']});continue
  if len(rows)>1:
   duplicates.append({'query_id':query_id,'row_count':len(rows)});ambiguous.append({'query_id':query_id,'reason':'MULTIPLE_ROWS_FOR_SINGLE_PLANNED_QUERY'});continue
  row=rows[0]
  if identity.get('verified') is not True or identity.get('row_is_paired_transaction') is not True:
   ambiguous.append({'query_id':query_id,'reason':'TRANSACTION_IDENTITY_UNVERIFIED'});continue
  tx=row.get(identity.get('transaction_id_field','transaction_id'))
  timeval=row.get(identity.get('timestamp_field','timestamp'))
  source=row.get(identity.get('source_ip_field','source_ip'));rcode=row.get(identity.get('response_rcode_field','rcode'))
  try:
   t=parse(timeval);actual=parse(receipt.get('actual_send_time'))
   valid=abs((t-actual).total_seconds())<=5 and bool(tx) and source==receipt.get('source_host') and rcode==receipt.get('rcode') and receipt['response_status']=='received'
  except TrafficError:valid=False
  if not valid:ambiguous.append({'query_id':query_id,'reason':'RECEIPT_TRANSACTION_PAIR_NOT_PROVEN'});continue
  pairs.append({'query_id':query_id,'transaction_id_sha256':sha(str(tx).encode()),'record_sha256':sha(canonical(row))})
 pair_ids=[x['transaction_id_sha256'] for x in pairs]
 if len(set(pair_ids))!=len(pair_ids):ambiguous.append({'reason':'TRANSACTION_ID_REUSED'});pairs=[]
 counts={'planned':len(p['queries']),'send_attempted':sum(r['response_status']!='not_attempted' for r in receipts.values()),'send_succeeded':sum(bool(r.get('send_succeeded')) for r in receipts.values()),'dns_responses':sum(r['response_status']=='received' for r in receipts.values()),'exported_rows':len(raw_rows),'unique_qname_matches':sum(bool(v) for v in matched.values()),'paired_transactions':len(pairs),'duplicates':sum(len(v)-1 for v in matched.values() if len(v)>1),'exact_duplicates':len(exact_duplicates),'missing':len(missing),'ambiguous':len(ambiguous),'accepted':0}
 complete=bool(export_result.get('delivery_complete') is True and export_result.get('completeness_verified') is True and not duplicates and not missing and not ambiguous and counts['planned']==counts['paired_transactions']==counts['dns_responses'])
 counts['accepted']=len(pairs) if complete else 0
 result={**counts,'complete':complete,'partition':'controlled_candidate' if complete else 'controlled_partial','training_ready':False,'split':'training_only_candidate','delivery_complete':export_result.get('delivery_complete',False),'completeness_verified':export_result.get('completeness_verified',False),'server_side_filter_verified':False,'server_filter_mode':'none; bounded time-only raw export','unrelated_rows':unrelated,'manifest_sha256':p['batch_manifest_sha256'],'planned_queries_sha256':p['planned_queries_sha256'],'raw_export_manifest_sha256':export_result['manifest_sha256'],'raw_output':str(directory),'label_mapping_version':LABEL_MAP_VERSION,'intended_label':p['intended_label'],'limitations':['Snapshot stability, transaction identity, and GUI parity must be independently verified. External governance still required; never promote automatically.']}
 out=protected_dir(state_dir(api,p['plan_id'])/('reconciliation-'+secrets.token_hex(5)))
 for name,value in [('matched',matched),('missing',missing),('duplicate',{'duplicates':duplicates,'exact_duplicates':exact_duplicates}),('ambiguous',ambiguous),('paired',pairs)]:atomic(out/(name+'.json'),value,exclusive=True)
 result['output']=str(out);result['artifact_sha256']={f.name:sha(read_private(f)) for f in out.glob('*.json')};atomic(out/'summary.json',result,exclusive=True)
 return result

def reconcile(api,args):
 try:
  from .log_exports import export
 except ImportError:
  from dns_lab_log_exports import export
 p=load_plan(api,args['plan_id']);start=parse(args['start_time']);end=parse(args['end_time']);s=state(api,p['plan_id'])
 if s.get('status') in ('queued','running','preflight','reconciling') and alive(s.get('worker_pid')):fail('TRAFFIC_SESSION_BUSY')
 receipts=receipt_projection(api,p);attempt_times=[parse(r.get('actual_send_time') or r.get('send_intent_time')) for r in receipts if r.get('actual_send_time') or r.get('send_intent_time')]
 if attempt_times and now()-max(attempt_times)<dt.timedelta(seconds=300):fail('TRAFFIC_LOG_SETTLING_REQUIRED')
 if attempt_times and not (start<=min(attempt_times) and end>max(attempt_times)+dt.timedelta(seconds=2)):fail('TRAFFIC_LOG_WINDOW_DOES_NOT_COVER_SENDS')
 if s.get('send_finished_at') and now()-parse(s['send_finished_at'])<dt.timedelta(seconds=300):fail('TRAFFIC_LOG_SETTLING_REQUIRED')
 result=export(api,{'dns_profile':p['dns_profile'],'start_time':args['start_time'],'end_time':args['end_time'],'max_pages':100,'max_rows':250000})
 summary=reconciliation(api,p,result)
 with locked(api):
  s.update(status='complete' if summary['complete'] else 'controlled_partial',reconciliation=summary,blocked_on_loss=not summary['complete'])
  if not s.get('finished_at'):s['finished_at']=timestamp()
  atomic(state_dir(api,p['plan_id'])/'state.json',s)
  active_path=runs(api)/'active.json'
  if active_path.exists():
   active=json.loads(read_private(active_path))
   if active.get('plan_id')==p['plan_id']:atomic(active_path,s)
 return summary

def approve(api,plan_id,expected_sha256):
 p=load_plan(api,plan_id)
 if p['dry_run']:fail('TRAFFIC_DRY_RUN_ONLY')
 if expected_sha256!=p['plan_sha256']:fail('TRAFFIC_APPROVAL_SHA_REQUIRED')
 if now()>parse(p['expires_at']):fail('TRAFFIC_PLAN_EXPIRED')
 if state(api,plan_id).get('approval_consumed'):fail('TRAFFIC_PLAN_ALREADY_CLAIMED')
 token=secrets.token_urlsafe(32)
 auth={'plan_id':plan_id,'plan_sha256':p['plan_sha256'],'token_sha256':sha(token.encode()),'approved_at':timestamp()}
 atomic(api.PLANS/(plan_id+'.approval.json'),auth,exclusive=True)
 api._audit('manifest_plan_human_approved',plan_id=plan_id,plan_sha256=p['plan_sha256'])
 return token

def plan_summary(api,path):
 p=load_plan(api,path.stem);s=status(api,{'plan_id':p['plan_id']})
 return {'plan_id':p['plan_id'],'kind':'manifest_traffic','state':s['status'],'created_at':p['created_at'],'expires_at':p['expires_at'],'plan_sha256':p['plan_sha256'],'preview':{'session_id':p['session_id'],'planned':len(p['queries']),'dry_run':p['dry_run'],'target_ip':TARGET[0],'target_port':53,'qps':p['qps'],'intended_label':p['intended_label']},'next_action':s['next_action']}

def dispatch(api,name,args):
 if os.name!='posix':fail('TRAFFIC_POSIX_GATEWAY_REQUIRED')
 functions={'lab_dns_plan_manifest_traffic':make_plan,'lab_dns_run_manifest_traffic_plan':claim,'lab_dns_get_traffic_plan_status':status,'lab_dns_reconcile_manifest_logs':reconcile}
 return functions[name](api,args)
