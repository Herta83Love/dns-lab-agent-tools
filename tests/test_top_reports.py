import datetime as dt
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from agent import top_reports as t
NOW=dt.datetime(2026,10,7,4,0,tzinfo=dt.timezone.utc)
START=NOW-dt.timedelta(minutes=10)
DATA={'title':'CPU','time':['2026-10-07 11:50','2026-10-07 11:55'],'data':[0,20]}
class Client:
 def __init__(self,*a,**kw):self.cfg={'base_url':'https://172.16.30.209:1606','certificate_sha256':'0'*64};self.cookies=[]
class FakeTransport:
 closed=0
 def __init__(self,*a):self.requests=[]
 def start(self):pass
 def request(self,section,report,start,end):self.requests.append(report);return report,200
 def collect(self,wanted):
  key=next(iter(wanted));return key,DATA
 def close(self):FakeTransport.closed+=1
class Tests(unittest.TestCase):
 def args(self,**kw):return {'start_time':START.isoformat(),'end_time':NOW.isoformat(),**kw}
 def test_invalid_combinations_no_network(self):
  for a in [{'section':'invalid'},{'section':'system','reports':['query_name']},{'reports':['cpu_us','cpu_us']},{'start_time':'2026-10-07T11:50:00+08:00'},{'timeout_seconds':True},{'include_identifiers':'false'},{'top_n':11},{'device':'dns-lab'}]:
   factory=Mock()
   with self.assertRaises(t.ReportError):t.query(a,factory,None)
   factory.assert_not_called()
 def test_timezone_and_ambiguous_window(self):
  with self.assertRaisesRegex(t.ReportError,'TIMEZONE'):t.validate({'start_time':'2026-10-07T11:50','end_time':'2026-10-07T12:00'})
  with self.assertRaisesRegex(t.ReportError,'AMBIGUOUS'):t.validate(self.args(window_minutes=10),NOW)
 def test_no_hardcoded_two_hour_limit(self):
  _,_,start,end=t.validate({'window_minutes':360},NOW);self.assertEqual((end-start).total_seconds(),21600)
 def test_future_rejected(self):
  with self.assertRaisesRegex(t.ReportError,'FUTURE'):t.validate(self.args(end_time=(NOW+dt.timedelta(minutes=1)).isoformat()),NOW)
 def test_zero_is_data_and_timezone_explicit(self):
  r=t.normalize('system','cpu_us',DATA,{},START,NOW,NOW)
  self.assertEqual(r['status'],'ready');self.assertEqual(r['series'][0]['mean'],10);self.assertEqual(r['series'][0]['latest_time'],'2026-10-07T03:55:00+00:00')
 def test_stale_and_point_limit(self):
  r=t.normalize('system','cpu_us',DATA,{'include_points':True,'max_points':1,'stale_after_seconds':100},START,NOW,NOW)
  self.assertEqual(r['status'],'stale');self.assertTrue(r['series'][0]['points_truncated']);self.assertEqual(r['series'][0]['mean'],10)
 def test_multiseries_and_missing(self):
  data={**DATA,'name':['QPM','RRM'],'data':[[1,2],[None,0]]}
  r=t.normalize('system','qpm_rrm',data,{},START,NOW,NOW)
  self.assertEqual(len(r['series']),2);self.assertEqual(r['series'][1]['missing_samples'],1)
 def test_empty_and_null_padding(self):
  r=t.normalize('system','cpu_us',{'data':[],'time':[]},{},START,NOW,NOW);self.assertEqual(r['status'],'no_data')
  r=t.normalize('proxy','query_name',{'data':[{'name':'Null','value':0}]},{},START,NOW,NOW);self.assertEqual(r['status'],'no_data')
 def test_identifier_mask_and_public_codes(self):
  data={'data':[{'name':'fixture.example','value':1,'percentage':10}]}
  r=t.normalize('proxy','query_name',data,{},START,NOW,NOW);self.assertEqual(r['rows'][0]['name'],'[MASKED]')
  r=t.normalize('proxy','query_name',data,{'include_identifiers':True},START,NOW,NOW);self.assertEqual(r['rows'][0]['name'],'fixture.example')
  r=t.normalize('proxy','response_code',{'data':[{'name':'NOERROR','value':10}]},{},START,NOW,NOW);self.assertEqual(r['rows'][0]['name'],'NOERROR')
 def test_series_length_time_order_and_finite(self):
  for bad in [{**DATA,'data':[1]},{**DATA,'time':list(reversed(DATA['time']))},{**DATA,'data':[float('nan'),1]},{**DATA,'time':['2026-10-07 08:00','2026-10-07 08:05']}]:
   with self.assertRaises(t.ReportError):t.normalize('system','cpu_us',bad,{},START,NOW,NOW)
 def test_query_ack_plus_delivery(self):
  r=t.query(self.args(reports=['cpu_us']),Client,None,FakeTransport)
  self.assertTrue(r['delivery_complete']);self.assertNotIn('hash_id',json.dumps(r));self.assertEqual(r['reports']['cpu_us']['method'],'GET')
 def test_partial_timeout_preserves_ready_report(self):
  class Partial(FakeTransport):
   def collect(self,wanted):
    if 'cpu_us' in wanted:return 'cpu_us',DATA
    raise t.ReportError('TOP_REPORT_TIMEOUT',True)
  r=t.query(self.args(reports=['cpu_us','memory']),Client,None,Partial)
  self.assertFalse(r['delivery_complete']);self.assertEqual(r['reports']['memory']['status'],'pending');self.assertIn('series',r['reports']['cpu_us'])
 def test_session_expiry_reauth_once(self):
  count=[]
  class Expiry(FakeTransport):
   def start(self):
    count.append(1)
    if len(count)==1:raise t.ReportError('TOP_REPORT_SESSION_EXPIRED',True)
  r=t.query(self.args(reports=['cpu_us']),Client,None,Expiry)
  self.assertTrue(r['delivery_complete']);self.assertEqual(r['retries'],1)
 def test_duplicate_job_fails_closed(self):
  class Duplicate(FakeTransport):
   def request(self,*a):return 'same',200
  r=t.query(self.args(reports=['cpu_us','memory']),Client,None,Duplicate)
  self.assertEqual(r['error_code'],'TOP_REPORT_DUPLICATE_JOB')
 def test_exception_and_auth_data_not_echoed(self):
  factory=Mock(side_effect=RuntimeError('fixture-sensitive-value'))
  r=t.query(self.args(reports=['cpu_us']),factory,None)
  self.assertNotIn('fixture-sensitive-value',str(r))
 def test_ping_and_channel_correlation(self):
  transport=t.Transport(Client(),__import__('time').monotonic()+30,lambda pin:__import__('urllib.request',fromlist=['HTTPSHandler']).HTTPSHandler())
  transport.ws=Mock();transport.ws.recv.side_effect=[json.dumps({'event':'pusher:ping'}),json.dumps({'event':'statistics','channel':'unrelated','data':{'hash_id':'wanted'}}),json.dumps({'event':'statistics','channel':'private-boulevard','data':{'hash_id':'other'}}),json.dumps({'event':'statistics','channel':'private-boulevard','data':{'hash_id':'wanted','data':DATA}})]
  self.assertEqual(transport.collect({'wanted':'cpu_us'})[1],DATA);transport.ws.send.assert_called_once()
 def test_https_and_pin_required(self):
  c=Client();c.cfg['base_url']='http://172.16.30.209:1606'
  with self.assertRaisesRegex(t.ReportError,'HTTPS'):t.Transport(c,0,None)
 def test_standalone_import_keeps_registration(self):
  p=Path(__file__).resolve().parents[1]/'agent/dns_lab_tools.py';spec=importlib.util.spec_from_file_location('standalone_tools',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  self.assertIn('lab_dns_get_top_report',[d['function']['name'] for d in m.DNS_LAB_TOOL_DEFINITIONS])

 def test_device_percentage_string(self):
  r=t.normalize('proxy','query_name',{'data':[{'name':'fixture','value':2,'percentage':'12.50%'}]}, {},START,NOW,NOW)
  self.assertEqual(r['rows'][0]['percentage'],12.5)
  self.assertEqual(r['rows'][0]['name'],'[MASKED]')
 def test_wrong_pin_never_sends_websocket_credentials(self):
  transport=t.Transport(Client(),t.time.monotonic()+10,lambda pin:t.urllib.request.HTTPSHandler())
  transport.http=Mock(side_effect=[(200,b'<meta name="csrf-token" content="fixture">'),(200,b'window.WebSocket=new X({broadcaster:"pusher",key:"fixture"')])
  raw=Mock();secure=Mock();secure.getpeercert.return_value=b'wrong-certificate'
  context=Mock();context.wrap_socket.return_value=secure
  with patch.object(t.socket,'create_connection',return_value=raw),patch.object(t.ssl,'SSLContext',return_value=context),patch('websocket.create_connection') as connect:
   with self.assertRaisesRegex(t.ReportError,'PIN_MISMATCH'):transport.start()
   connect.assert_not_called();secure.close.assert_called_once()

 def test_pie_numeric_string_and_grouping(self):
  for value in ['1234','1,234']:
   r=t.normalize('proxy','response_code',{'data':[{'name':'NOERROR','value':value}]},{},START,NOW,NOW)
   self.assertEqual(r['rows'][0]['value'],1234)
  with self.assertRaises(t.ReportError):t.normalize('proxy','response_code',{'data':[{'name':'NOERROR','value':'NaN'}]},{},START,NOW,NOW)
