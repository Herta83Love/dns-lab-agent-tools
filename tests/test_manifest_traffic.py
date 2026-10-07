import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch
from agent import dns_lab_tools as api
from agent import manifest_traffic as t
from agent import log_exports

class ManifestTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
  self.config=self.root/'config.json';self.workspace=self.root/'workspace';self.workspace.mkdir(mode=0o700)
  self.materialized=self.workspace/'manifests'/'reviewed';self.materialized.mkdir(parents=True,mode=0o700);self.materialized.parent.chmod(0o700)
  self.cfg=json.loads((Path(__file__).parents[1]/'agent/dns_lab_config.example.json').read_text());self.cfg.update(workspace_root=str(self.workspace),manifest_root=str(self.workspace/'manifests'),min_free_bytes=0)
  self.cfg['profiles']['lab-malicious'].update(base_url='https://172.16.30.209:1606',traffic_dns_server=t.TARGET[0],traffic_dns_port=53)
  self.config.write_text(json.dumps(self.cfg));self.config.chmod(0o600)
  self.old=(api.CONFIG_PATH,api.ROOT,api.PLANS,api.EXPORTS,api.AUDIT);api.CONFIG_PATH=self.config;api._config()
  self.build()
 def tearDown(self):
  api.CONFIG_PATH,api.ROOT,api.PLANS,api.EXPORTS,api.AUDIT=self.old;self.temp.cleanup()
 def put(self,path,value,lines=False):
  path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  raw=b''.join(t.canonical(x)+b'\n' for x in value) if lines else t.canonical(value)
  path.write_bytes(raw);path.chmod(0o600);return t.sha(raw)
 def build(self,sid='session1',marker='sid1',count=3,override=None):
  queries=[{'index':i,'qname':f'q{i}.{marker}.eidolon-synth.test','qtype':['A','AAAA','TXT','CNAME'][i%4],'intended_relative_send_time_ms':i*100,'frame_role':'control','chunk_sha256':None} for i in range(count)]
  if override:override(queries)
  relative=f'sessions/{sid}/planned-queries.jsonl';digest=self.put(self.materialized/relative,queries,True)
  catalog={'session_id':sid,'class_code':'control_only','session_seed':3,'split':'training_only_candidate','split_group_id':'group1','params':{'session_label':marker},'record_count':count,'planned_queries_path':relative,'query_list_sha256':digest}
  session={**catalog,'partition':'controlled_candidate','training_ready':False};session.pop('planned_queries_path')
  sm=self.put(self.materialized/relative.replace('planned-queries.jsonl','session-manifest.json'),session)
  cd=self.put(self.materialized/'catalog.jsonl',[catalog],True)
  batch={'partition':'controlled_candidate','training_ready':False,'lineage':{'catalog':{'path':'catalog.jsonl','sha256':cd},'sessions':[{'session_id':sid,'planned_queries_path':relative,'query_list_sha256':digest,'session_manifest_sha256':sm}]}}
  bd=self.put(self.materialized/'batch-manifest.json',batch)
  self.args={'batch_manifest_path':str(self.materialized/'batch-manifest.json'),'batch_manifest_sha256':bd,'session_id':sid,'planned_queries_sha256':digest}
  return queries
 def plan(self,dry=False):return t.make_plan(api,{**self.args,'dry_run':dry})
 def approved(self):
  plan=self.plan();token=t.approve(api,plan['plan_id'],plan['plan_sha256']);return plan,token
 def claim(self):
  p,token=self.approved();t.claim(api,{'plan_id':p['plan_id'],'approval_token':token},spawn=False);return p
 def test_defaults_and_exact_payload_label_map(self):
  p=t.make_plan(api,self.args);saved=t.load_plan(api,p['plan_id'])
  self.assertTrue(saved['dry_run']);self.assertEqual(saved['qps'],0.5)
  self.assertEqual(saved['intended_label'],{'tunneling':1,'exfiltration':0});self.assertEqual(saved['label_mapping_version'],t.LABEL_MAP_VERSION)
  self.assertEqual(saved['queries'][0]['qname'],'q0.sid1.eidolon-synth.test')
  with self.assertRaisesRegex(t.TrafficError,'DRY_RUN'):t.claim(api,{'plan_id':p['plan_id'],'approval_token':'fixture'})
 def test_layers_tamper_and_path_escape(self):
  for name in ['batch-manifest.json','catalog.jsonl','sessions/session1/session-manifest.json','sessions/session1/planned-queries.jsonl']:
   path=self.materialized/name;original=path.read_bytes();path.write_bytes(original+b' ')
   with self.assertRaises(t.TrafficError):t.make_plan(api,self.args)
   path.write_bytes(original)
  with self.assertRaisesRegex(t.TrafficError,'PATH'):t.make_plan(api,{**self.args,'batch_manifest_path':str(self.config)})
  link=self.materialized/'link.json';link.symlink_to(self.materialized/'batch-manifest.json')
  with self.assertRaisesRegex(t.TrafficError,'PATH'):t.make_plan(api,{**self.args,'batch_manifest_path':str(link)})
 def test_modes_query_types_duplicates_order_marker(self):
  cases=[lambda q:q[0].update(qtype='ANY'),lambda q:q[1].update(qname=q[0]['qname']),lambda q:q[0].update(index=9),lambda q:q[0].update(qname='wrong.eidolon-synth.test'),lambda q:q[1].update(intended_relative_send_time_ms=-1)]
  for modify in cases:
   self.build(override=modify)
   with self.assertRaises(t.TrafficError):t.make_plan(api,self.args)
 def test_limits_and_unknown_inputs(self):
  for extra in [{'qps':1},{'qps':float('nan')},{'cooldown_seconds':299},{'queries_per_session':501},{'stop_on_any_loss':False},{'payload_file':'anything'},{'stdin':'anything'}]:
   with self.assertRaises(t.TrafficError):t.make_plan(api,{**self.args,**extra})
  self.build(count=501)
  with self.assertRaisesRegex(t.TrafficError,'COUNT'):t.make_plan(api,self.args)
 def test_target_separation_and_normal_profile_rejection(self):
  self.cfg['profiles']['lab-malicious']['traffic_dns_server']='172.16.30.209';self.config.write_text(json.dumps(self.cfg))
  with self.assertRaisesRegex(t.TrafficError,'TARGET'):self.plan()
 def test_immutable_plan_approval_sha_and_once(self):
  p=self.plan();path=t.plan_path(api,p['plan_id']);before=path.read_bytes()
  with self.assertRaisesRegex(t.TrafficError,'SHA'):t.approve(api,p['plan_id'],'0'*64)
  token=t.approve(api,p['plan_id'],p['plan_sha256'])
  with self.assertRaisesRegex(t.TrafficError,'INVALID'):t.claim(api,{'plan_id':p['plan_id'],'approval_token':'wrong'})
  t.claim(api,{'plan_id':p['plan_id'],'approval_token':token},spawn=False)
  with self.assertRaises(t.TrafficError):t.claim(api,{'plan_id':p['plan_id'],'approval_token':token},spawn=False)
  self.assertEqual(path.read_bytes(),before)
 def test_plan_hash_corruption(self):
  p=self.plan();path=t.plan_path(api,p['plan_id']);data=json.loads(path.read_text());data['queries'][0]['qname']='tampered.sid1.test';self.put(path,data)
  with self.assertRaisesRegex(t.TrafficError,'HASH'):t.load_plan(api,p['plan_id'])
 def fake_result(self,q):return {'send_succeeded':True,'response_status':'received','rcode':0,'timeout':False,'error':None,'latency_ms':1,'source_host':'127.0.0.1','dns_query_id':12,'actual_send_time':t.timestamp()}
 def test_worker_receipts_stop_loss_and_no_replay(self):
  p=self.claim();path=t.plan_path(api,p['plan_id']);before=path.read_bytes();sender=Mock(side_effect=[self.fake_result({}),{'send_succeeded':True,'response_status':'timeout','rcode':None,'timeout':True,'error':'DNS_TIMEOUT','latency_ms':2000,'source_host':'127.0.0.1'}]);gate=Mock(return_value={'report_sha256':'fixture','historical_statistics':True})
  with patch.object(t,'preflight',gate):s=t.execute_worker(api,p['plan_id'],sender,lambda delay:None)
  self.assertEqual(sender.call_count,2);self.assertEqual(s['planned'],3);self.assertEqual(s['receipt_counts']['not_attempted'],1);self.assertEqual(s['receipt_counts']['timeout'],1)
  self.assertEqual(path.read_bytes(),before)
  index=json.loads((t.state_dir(api,p['plan_id'])/'receipt-index.json').read_text());self.assertEqual(len(index['receipts']),3);self.assertTrue(index['postflight_evidence_sha256'])
  for receipt in index['receipts']:
   for key in ['planned_send_time','actual_send_time','qname','qtype','intended_label','source_host','execution_input_sha256','execution_output_sha256']:self.assertIn(key,receipt)
  with patch.object(t,'preflight',gate),self.assertRaises(t.TrafficError):t.execute_worker(api,p['plan_id'],sender,lambda delay:None)
  self.assertEqual(sender.call_count,2)
 def test_crash_after_intent_is_uncertain_never_retry(self):
  p=self.claim();sender=Mock(side_effect=KeyboardInterrupt())
  with patch.object(t,'preflight',return_value={'fixture':True}):s=t.execute_worker(api,p['plan_id'],sender,lambda delay:None)
  self.assertEqual(s['receipt_counts']['uncertain'],1);self.assertEqual(s['receipt_counts']['not_attempted'],2)
  sender.assert_called_once();self.assertFalse(s['complete'])
 def test_preflight_failure_sends_nothing_and_keeps_reason(self):
  p=self.claim();sender=Mock();error=t.TrafficError('TRAFFIC_PREFLIGHT_LOAD_HIGH');error.evidence={'historical_statistics':True,'metrics':{'cpu_us':{'latest':95}}}
  with patch.object(t,'preflight',side_effect=error):s=t.execute_worker(api,p['plan_id'],sender)
  sender.assert_not_called();self.assertEqual(s['error_code'],'TRAFFIC_PREFLIGHT_LOAD_HIGH');self.assertEqual(s['preflight']['metrics']['cpu_us']['latest'],95)
 def good_report(self):
  time=t.timestamp()
  return {'delivery_complete':True,'reports':{name:{'status':'ready','series':[{'status':'ready','latest':value,'age_seconds':1,'latest_time':time}]} for name,value in [('cpu_us',20),('memory',30)]}}
 def test_gate_missing_stale_high_and_log_health(self):
  p=self.plan();p=t.load_plan(api,p['plan_id'])
  good=self.good_report();responses=[{'delivery_complete':False},self.good_report(),self.good_report(),self.good_report()]
  responses[1]['reports']['cpu_us']['series'][0]['latest']=95
  responses[2]['reports']['memory']['status']='no_data'
  responses[3]['reports']['cpu_us']['series'][0]['age_seconds']=601
  for report in responses:
   with patch.object(api,'_execute_dns_lab_tool',side_effect=[{'websocket_dependency_available':True},report]),self.assertRaises(t.TrafficError):t.preflight(api,p)
  client=Mock();client.request.return_value=(200,{},b'[]')
  with patch.object(api,'_execute_dns_lab_tool',side_effect=[{'websocket_dependency_available':True},good]),patch.object(api,'LabClient',return_value=client):self.assertEqual(t.preflight(api,p)['log_api']['row_count'],0)
 def test_receipt_exact_reconciliation_duplicates_and_missing(self):
  p=self.claim()
  with patch.object(t,'preflight',return_value={'fixture':True}):t.execute_worker(api,p['plan_id'],self.fake_result,lambda delay:None)
  saved=t.load_plan(api,p['plan_id']);receipts=t.receipt_projection(api,saved);first=receipts[0]
  row={'qname':first['qname'].upper()+'.','qtype':first['qtype'],'transaction_id':'fixture1','timestamp':first['actual_send_time'],'source_ip':first['source_host'],'rcode':0}
  output=t.protected_dir(api.EXPORTS/'fixture');raw=t.canonical([row,row,{'qname':'other.sid1.eidolon-synth.test','qtype':'A'}]);(output/'page-000001.json').write_bytes(raw);(output/'page-000001.json').chmod(0o600)
  md={'pages':[{'page':1,'sha256':t.sha(raw)}]};mdsha=t.atomic(output/'manifest.json',md)
  result=t.reconciliation(api,saved,{'output':str(output),'manifest_sha256':mdsha,'delivery_complete':True,'completeness_verified':False})
  self.assertEqual(result['unique_qname_matches'],1);self.assertEqual(result['duplicates'],1);self.assertEqual(result['exact_duplicates'],1);self.assertEqual(result['missing'],2);self.assertEqual(result['unrelated_rows'],1);self.assertFalse(result['complete']);self.assertFalse(result['training_ready'])
 def test_single_exact_match_not_proven_without_identity(self):
  p=self.plan();saved=t.load_plan(api,p['plan_id']);rows=[{'qname':q['qname'],'qtype':q['qtype']} for q in saved['queries']]
  output=t.protected_dir(api.EXPORTS/'fixture');raw=t.canonical(rows);(output/'page-000001.json').write_bytes(raw);(output/'page-000001.json').chmod(0o600)
  mdsha=t.atomic(output/'manifest.json',{'pages':[{'page':1,'sha256':t.sha(raw)}]})
  r=t.reconciliation(api,saved,{'output':str(output),'manifest_sha256':mdsha,'delivery_complete':True,'completeness_verified':False})
  self.assertEqual(r['unique_qname_matches'],3);self.assertEqual(r['paired_transactions'],0);self.assertEqual(r['accepted'],0);self.assertFalse(r['complete'])
 def test_bounded_export_metadata_no_snapshot_and_partial_retention(self):
  old=t.now()-dt.timedelta(minutes=10);client=Mock();client.request.side_effect=[(200,{'X-Total-Count':'2501'},t.canonical([{'qname':'fixture.test','identity':str(i),'time':old.isoformat()} for i in range(2500)])),(200,{'X-Total-Count':'2501'},t.canonical([{'qname':'fixture2.test','identity':'0','time':old.isoformat()}]))]
  with patch.object(api,'LabClient',return_value=client):r=log_exports.export(api,{'start_time':(old-dt.timedelta(minutes=1)).isoformat(),'end_time':(old+dt.timedelta(minutes=1)).isoformat()})
  self.assertEqual(r['rows'],2501);self.assertEqual(r['pages'],2);self.assertIsNone(r['duplicate_transaction_ids']);self.assertEqual(r['candidate_identity_duplicate_rows'],1);self.assertTrue(r['delivery_complete']);self.assertFalse(r['completeness_verified']);self.assertIsNone(r['snapshot_token'])
  self.assertEqual(r['page_metadata'][1]['api_reported_total'],2501)
 def test_export_failure_keeps_previous_pages(self):
  old=t.now()-dt.timedelta(minutes=10);client=Mock();client.request.side_effect=[(200,{},t.canonical([{'identity':str(i)} for i in range(2500)])),TimeoutError()]
  with patch.object(api,'LabClient',return_value=client):r=log_exports.export(api,{'start_time':old.isoformat(),'end_time':(old+dt.timedelta(minutes=1)).isoformat()})
  self.assertFalse(r['delivery_complete']);self.assertEqual(r['rows'],2500);self.assertTrue((Path(r['output'])/'page-000001.json').exists())
 def test_runtime_identity_excludes_credentials(self):
  a=api.runtime_identity();self.cfg['profiles']['lab-malicious']['account']='different-fixture-account';self.cfg['profiles']['lab-malicious']['secret_file']='/different-fixture-secret';self.config.write_text(json.dumps(self.cfg));b=api.runtime_identity()
  self.assertEqual(a['config_fingerprint'],b['config_fingerprint']);self.assertNotIn('different-fixture',json.dumps(b));self.assertTrue(b['config_presence'])
 def test_fake_udp_receiver_question_and_timeout_receipts(self):
  server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',0));target=server.getsockname()
  def respond():
   packet,source=server.recvfrom(4096);identifier=struct.unpack('!H',packet[:2])[0];response=struct.pack('!HHHHHH',identifier,0x8183,1,0,0,0)+packet[12:];server.sendto(response,source);server.close()
  thread=threading.Thread(target=respond);thread.start()
  r=t.send_dns({'qname':'fixture.sid1.test','qtype':'A'},target,timeout=1);thread.join(2)
  self.assertEqual(r['response_status'],'received');self.assertEqual(r['rcode'],3);self.assertTrue(r['send_succeeded'])
  server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',0));target=server.getsockname()
  try:r=t.send_dns({'qname':'fixture.sid1.test','qtype':'TXT'},target,timeout=0.03)
  finally:server.close()
  self.assertEqual(r['response_status'],'timeout');self.assertTrue(r['send_succeeded']);self.assertIsNone(r['rcode'])

 def test_cooldown_and_recovery_require_new_session(self):
  p=self.claim()
  with patch.object(t,'preflight',return_value={'fixture':True}):t.execute_worker(api,p['plan_id'],self.fake_result,lambda delay:None)
  with self.assertRaisesRegex(t.TrafficError,'NEW_SESSION'):t.make_plan(api,{**self.args,'dry_run':False,'recovery_from_plan_id':p['plan_id']})
  self.build(sid='session2',marker='sid2');p2=t.make_plan(api,{**self.args,'dry_run':False,'recovery_from_plan_id':p['plan_id']});token=t.approve(api,p2['plan_id'],p2['plan_sha256'])
  with self.assertRaisesRegex(t.TrafficError,'COOLDOWN'):t.claim(api,{'plan_id':p2['plan_id'],'approval_token':token},spawn=False)
 def test_config_change_rejects_before_worker_start(self):
  p,token=self.approved();self.cfg['max_traffic_queries']=200;self.config.write_text(json.dumps(self.cfg))
  with self.assertRaisesRegex(t.TrafficError,'CONFIG_CHANGED'):t.claim(api,{'plan_id':p['plan_id'],'approval_token':token},spawn=False)
 def test_two_plans_cannot_claim_concurrent_sessions(self):
  first=self.claim();self.build(sid='session2',marker='sid2');p,token=self.approved()
  with self.assertRaisesRegex(t.TrafficError,'BUSY'):t.claim(api,{'plan_id':p['plan_id'],'approval_token':token},spawn=False)
 def test_expired_plan_rejected_even_with_valid_approval(self):
  p,token=self.approved()
  future=t.now()+dt.timedelta(hours=2)
  with patch.object(t,'now',return_value=future),self.assertRaisesRegex(t.TrafficError,'EXPIRED'):t.claim(api,{'plan_id':p['plan_id'],'approval_token':token},spawn=False)
 def test_verified_pairing_still_needs_snapshot(self):
  p=self.claim()
  with patch.object(t,'preflight',return_value={'fixture':True}):t.execute_worker(api,p['plan_id'],self.fake_result,lambda delay:None)
  saved=t.load_plan(api,p['plan_id']);receipts=t.receipt_projection(api,saved)
  rows=[{'qname':r['qname'].upper()+'.','qtype':r['qtype'],'transaction_id':'fixture-'+r['query_id'],'timestamp':r['actual_send_time'],'source_ip':r['source_host'],'rcode':r['rcode']} for r in receipts]
  output=t.protected_dir(api.EXPORTS/'fixture');raw=t.canonical(rows);(output/'page-000001.json').write_bytes(raw);(output/'page-000001.json').chmod(0o600);mdsha=t.atomic(output/'manifest.json',{'pages':[{'page':1,'sha256':t.sha(raw)}]})
  self.cfg['log_identity']={'verified':True,'row_is_paired_transaction':True};self.config.write_text(json.dumps(self.cfg))
  result=t.reconciliation(api,saved,{'output':str(output),'manifest_sha256':mdsha,'delivery_complete':True,'completeness_verified':False})
  self.assertEqual(result['paired_transactions'],3);self.assertFalse(result['complete']);self.assertEqual(result['accepted'],0)

 def test_dns_payload_labels_are_not_hostname_labels(self):
  self.build(override=lambda q:q[0].update(qname='-fixture_.sid1.eidolon-synth.test'))
  p=self.plan();self.assertEqual(t.load_plan(api,p['plan_id'])['queries'][0]['qname'],'-fixture_.sid1.eidolon-synth.test')
  with self.assertRaises(t.TrafficError):t.valid_name('bad\\032label.sid1.test')

 def test_reviewed_prefix_is_explicit_and_hashes_full_source(self):
  plan=t.make_plan(api,{**self.args,'queries_per_session':2});saved=t.load_plan(api,plan['plan_id'])
  self.assertEqual(plan['planned'],2);self.assertEqual(saved['selection']['source_query_count'],3)
  self.assertEqual(saved['planned_queries_sha256'],self.args['planned_queries_sha256']);self.assertEqual(saved['selection']['selected_queries_sha256'],t.sha(t.canonical(saved['queries'])))
 def test_approval_cli_never_prints_token_and_requires_exact_sha(self):
  import subprocess,sys
  p=self.plan();target=self.root/'approval.secret'
  command=[sys.executable,'-m','agent.approve_dns_lab_plan',p['plan_id'],'--config',str(self.config),'--plan-sha256',p['plan_sha256'],'--token-file',str(target)]
  result=subprocess.run(command,capture_output=True,text=True)
  self.assertEqual(result.returncode,0);token=target.read_text().strip()
  self.assertTrue(token not in result.stdout+result.stderr);self.assertEqual(target.stat().st_mode&0o777,0o600)
  auth=json.loads((api.PLANS/(p['plan_id']+'.approval.json')).read_text());self.assertEqual(auth['token_sha256'],t.sha(token.encode()))
 def test_deployment_failure_does_not_switch_current(self):
  from scripts import deploy_runtime
  import shutil
  bundle=self.root/'bundle';bundle.mkdir();repo=Path(__file__).parents[1]
  files=['agent/__init__.py','agent/dns_lab_tools.py','agent/top_reports.py','agent/manifest_traffic.py','agent/manifest_worker.py','agent/log_exports.py','agent/mcp_server.py','agent/approve_dns_lab_plan.py','agent/dns_lab_config.example.json','scripts/deploy_runtime.py','scripts/import_reviewed_manifest.py','scripts/deploy_acceptance.py','requirements-mcp.lock.txt']
  for name in files:
   dest=bundle/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(repo/name,dest)
  self.put(bundle/'tool-manifest.json',{'source_sha256':{name:t.sha((bundle/name).read_bytes()) for name in files}})
  self.put(bundle/'runtime-metadata.json',{'git_commit':'1'*40})
  secret=self.root/'fixture.secret';secret.write_text('fixture');secret.chmod(0o600)
  self.cfg['profiles']['lab-malicious']['secret_file']=str(secret);self.config.write_text(json.dumps(self.cfg));original=self.config.read_bytes()
  deployment=self.root/'runtime';deployment.mkdir();old=deployment/'old';old.mkdir();(deployment/'current').symlink_to(old)
  with patch.object(deploy_runtime.subprocess,'run',side_effect=[Mock(returncode=0),Mock(returncode=0),Mock(returncode=1)]),self.assertRaises(ValueError):deploy_runtime.deploy(bundle,self.config,deployment)
  self.assertEqual((deployment/'current').resolve(),old);self.assertEqual(self.config.read_bytes(),original)
