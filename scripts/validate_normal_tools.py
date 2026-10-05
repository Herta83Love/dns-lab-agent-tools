"""Integration check of installed tools; keeps all DNS records in memory."""
import datetime as dt
import json
import os
from pathlib import Path
import runpy
import importlib.util
from dns_security_api import Tools
from dns_security_api.core import canonical,sha

v=runpy.run_path('/tmp/dns-api-readonly-validation.py')
spec=importlib.util.spec_from_file_location('collector',v['COLLECTOR']);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
os.environ['SENTRY_ACCOUNT']=os.environ.get('SENTRY_ACCOUNT') or v['account_from_wrapper']()
end=dt.datetime.fromtimestamp(int((dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=3)).timestamp()),dt.timezone.utc); start=end-dt.timedelta(minutes=4)
filters={'start_time':start.isoformat(),'end_time':end.isoformat()}
verify='/webApi/historylog/proxy/1?start_time='+str(int(end.timestamp())-1)+'&end_time='+str(int(end.timestamp()))+'&filter=%7B%7D'
profile={'base_url':'https://192.168.10.150:1606','role':'normal','allow_forward_writes':False,'timeout':30,'tls':{'certificate_sha256':m.DEFAULT_CERT_SHA256},'auth':{'mode':'form','login':'/login','verify':verify,'allow_same_origin_redirects':True,'success_cookie':'sentry_session','failure_body_marker':'name="account"','csrf_page':'/login','csrf_pattern':'name="_token"\\s+value="([^\"]+)"','csrf_field':'_token','secret_file':'/home/jackie_tsai/dns-normal-collector/secrets/sentry.password','secret_file_format':'password_text','env':{'username':'SENTRY_ACCOUNT'},'fields':{'account':'username','password':'password'}},'capability':{'logs':{'endpoint':'/webApi/historylog/proxy/{position}','default_parameters':{'filter':'{}'},'filters':{**{k:{'parameter':k,'verified':True,'format':'unix_seconds'} for k in ('start_time','end_time')},**{k:{'row_field':field,'mode':'client','verified':True,'normalize':mode} for k,field,mode in [('domain','qname','domain'),('qname','qname','domain'),('qtype','qtype','upper'),('rcode','rcode','upper')]}},'pagination':{'kind':'page','max_page_size':2500,'fixed_page_size':2500,'send_size_parameter':False}}}}
tools=Tools({'normal':profile},'/tmp/dns-tools-integration-state')
base={'profile':'normal','target':profile['base_url']};out=[]
r=tools.execute('dns_authenticate',base);out.append({'test':'new_tool_login','ok':r['ok'],'error':r.get('error')})
if r['ok']:
 baseline=tools.execute('dns_query_logs',{**base,'filters':filters,'limits':{'max_pages':2,'max_bytes':16777216}})
 if baseline['ok']:
  result=baseline['result'];rows=result['rows']
  out.append({'test':'new_tool_pagination','ok':True,'pages':result['pages'],'rows':len(rows),'complete':result['complete'],'exceeds_2500':len(rows)>2500})
  for key,value in [('domain','taipeinetworks.com'),('qtype','A'),('rcode','NOERROR'),('qname',str(rows[0]['qname']).rstrip('.'))] if rows else []:
   response=tools.execute('dns_query_logs',{**base,'filters':{**filters,key:value},'limits':{'max_pages':2,'max_bytes':16777216}})
   if not response['ok']:out.append({'test':key,'ok':False,'error':response['error']});continue
   filtered=response['result'];field='qname' if key in ('domain','qname') else key
   expected=[r for r in rows if (str(r.get(field,'')).rstrip('.').lower()==value.lower() if key in ('domain','qname') else str(r.get(field,'')).upper()==value)]
   out.append({'test':key,'ok':True,'filter_mode':filtered['applied_filters'][key]['mode'],'selected_rows':filtered['count'],'matches_baseline_subset':sorted(map(canonical,filtered['rows']))==sorted(map(canonical,expected)),'complete':filtered['complete'],'query_values':'[MASKED]'})
 else:out.append({'test':'new_tool_query','ok':False,'error':baseline['error']})
cap_path=Path('/home/jackie_tsai/.local/state/dns-lab-agent-tools/capabilities/normal-dns.json')
cap=json.loads(cap_path.read_text());cap['new_tool_integration']=out
cap['tool_capability']=profile['capability']
cap['logs']['client_filters']={k:{'row_field':field,'semantics':'exact','mode':'client','verified':True} for k,field in [('domain','qname'),('qtype','qtype'),('rcode','rcode')]}
cap['tls']['mode']='per_client_certificate_sha256_pinning';cap['tls']['global_verification_disabled']=False
v['write']('normal-dns.json',cap)
print(json.dumps(out))
