import copy
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from src.dns_security_api.core import Client, Error, LAB, NORMAL, Logs, clean, sha, canonical
from src.dns_security_api.tools import Tools

FILTER={'start_time':'2026-01-01T00:00:00+08:00','end_time':'2026-01-02T00:00:00+08:00','domain':'taipeinetworks.com','qtype':'A','rcode':'NOERROR'}
CAP={'logs':{'endpoint':'/logs','filters':{k:{'parameter':k,'verified':True,'semantics':'exact'} for k in FILTER},'pagination':{'kind':'page','max_page_size':2500,'verified_snapshot':True,'snapshot_parameter':'snapshot'}}}
class Fake:
    def __init__(self,p=None):
        self.base=(p or {}).get('base_url',LAB); self.events=[]; self.config=[{'domain':'example.test','primary':'172.16.30.1'}]; self.calls=[]; self.batches=[]
    def request(self,path,method='GET',body=None):
        self.calls.append((path,method,body))
        if path.startswith('/logs'): return self.batches.pop(0)
        if method=='PUT': self.config=body
        return copy.deepcopy(self.config)
    def authenticate(self): return {'authenticated':True}
    def logout(self): return {'logged_out':True}
class Tests(unittest.TestCase):
    def batch(self,rows,total,snapshot='fixed'): return {'rows':rows,'total':total,'snapshot':snapshot}
    def query(self,batches,cap=None,**kwargs):
        c=Fake(); c.batches=batches
        return Logs(c,cap or CAP).query(FILTER,**kwargs)
    def test_multipage_2501_and_filters(self):
        rows=[{'id':i} for i in range(2501)]
        r=self.query([self.batch(rows[:2500],2501),self.batch(rows[2500:],2501)])
        self.assertTrue(r['complete']); self.assertEqual(r['count'],2501)
        self.assertEqual(r['applied_filters']['domain']['value'],'taipeinetworks.com')
    def test_filter_rejected(self):
        cap=copy.deepcopy(CAP); cap['logs']['filters'].pop('rcode')
        with self.assertRaisesRegex(Error,'FILTER_UNVERIFIED_RCODE'): self.query([],cap)
    def test_duplicate_page(self):
        batch=self.batch([{'id':1}],2)
        with self.assertRaisesRegex(Error,'DUPLICATE_PAGE'): self.query([batch,batch],limits={'page_size':1})
    def test_drift(self):
        with self.assertRaisesRegex(Error,'PAGINATION_DRIFT'): self.query([self.batch([{'id':1}],2),self.batch([],2,'changed')],limits={'page_size':1})
    def test_total_mismatch(self):
        with self.assertRaisesRegex(Error,'TOTAL_MISMATCH'): self.query([self.batch([{'id':1}],2)])
    def test_resume_and_target_guard(self):
        r=self.query([self.batch([{'id':1}],2)],limits={'page_size':1,'max_pages':1})
        self.assertFalse(r['complete'])
        resumed=self.query([self.batch([{'id':2}],2),self.batch([],2)],limits={'page_size':1},checkpoint=r['checkpoint'])
        self.assertTrue(resumed['complete'])
        bad=copy.deepcopy(r['checkpoint']); bad['fingerprint']='bad'
        with self.assertRaisesRegex(Error,'CHECKPOINT_TARGET'): self.query([],limits={'page_size':1},checkpoint=bad)
    def test_unproven_short_page_incomplete(self):
        self.assertFalse(self.query([[{'id':1}]])['complete'])
    def test_timezone(self):
        with self.assertRaisesRegex(Error,'TIMEZONE_REQUIRED'): Logs(Fake(),CAP).query({**FILTER,'start_time':'2026-01-01'})
    def test_formats_sha_and_immutable(self):
        c=Fake(); c.batches=[self.batch([{'id':1,'domain':'=formula'}],1)]
        l=Logs(c,CAP); result=l.query(FILTER)
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'export'; exported=l.export(result,out,['json','jsonl','csv'])
            for filename,digest in exported['manifest']['files'].items(): self.assertEqual(sha((out/filename).read_bytes()),digest)
            self.assertIn("'=formula",(out/'logs.csv').read_text())
            with self.assertRaises(FileExistsError): l.export(result,out,['json'])
    def test_redaction(self):
        r=clean({'password':'a','nested':{'Authorization':'b','cookie':'c','access_token':'d'}})
        self.assertNotIn('"a"',json.dumps(r)); self.assertEqual(r['nested']['cookie'],'[REDACTED]')
    def forward(self,td,target=LAB):
        p={'base_url':target,'role':'lab','allow_forward_writes':True,'capability':{'forward':{'read_endpoint':'/forward','write_endpoint':'/forward','write_verified':True}}}
        c=Fake(p); return Tools({'lab':p},td,lambda p:c),c,{'profile':'lab','target':target}
    def test_forward_apply_rollback_dryrun(self):
        with tempfile.TemporaryDirectory() as td:
            t,c,a=self.forward(td); plan=t.execute('dns_plan_forward_change',{**a,'desired':[{'domain':'example.test','primary':'172.16.30.2'}]})['result']
            b={**a,'plan_id':plan['plan_id']}
            self.assertTrue(t.execute('dns_apply_forward_change',b)['result']['dry_run'])
            self.assertEqual(len([x for x in c.calls if x[1]=='PUT']),0)
            self.assertTrue(t.execute('dns_apply_forward_change',{**b,'dry_run':False,'approved_sha256':plan['plan_sha256']})['ok'])
            self.assertTrue(t.execute('dns_rollback_forward_change',{**b,'dry_run':False,'approved_sha256':plan['plan_sha256']})['ok'])
            self.assertEqual(c.config,plan['before'])
    def test_normal_write_guard_and_host_confusion(self):
        with tempfile.TemporaryDirectory() as td:
            t,c,a=self.forward(td,NORMAL); plan=t.execute('dns_plan_forward_change',{**a,'desired':c.config})['result']
            r=t.execute('dns_apply_forward_change',{**a,'plan_id':plan['plan_id'],'dry_run':False,'approved_sha256':plan['plan_sha256']})
            self.assertEqual(r['error']['code'],'NORMAL_OR_UNKNOWN_DNS_WRITE_PROTECTED')
            self.assertEqual(t.execute('dns_get_forward_config',{**a,'target':LAB})['error']['code'],'TARGET_MISMATCH')
    def test_http_and_tls(self):
        self.assertEqual(Client({'base_url':LAB}).base,LAB)
        with self.assertRaisesRegex(Error,'INSECURE_TLS'): Client({'base_url':NORMAL,'tls':{'insecure':True}})
    def test_auth_success_failure_expiry(self):
        p={'base_url':LAB,'auth':{'mode':'json','login':'/login','verify':'/me','fields':{'user':'username','password':'password'},'env':{'username':'TEST_USER','password':'TEST_PASSWORD'}}}
        with patch.dict('os.environ',{'TEST_USER':'test','TEST_PASSWORD':'fixture-value'}):
            c=Client(p)
            with patch.object(c,'raw',side_effect=[b'{}',b'{}']): self.assertTrue(c.authenticate()['authenticated'])
            with patch.object(c,'raw',side_effect=Error('AUTH_EXPIRED')):
                with self.assertRaisesRegex(Error,'AUTH_FAILED'): c.authenticate()
            c.authenticated=True
            with patch.object(c,'raw',side_effect=[Error('AUTH_EXPIRED'),b'{}',b'{}',b'[]']): self.assertEqual(c.request('/logs'),[])
    def test_mutation_not_replayed(self):
        c=Client({'base_url':LAB}); c.authenticated=True
        with patch.object(c,'raw',side_effect=Error('AUTH_EXPIRED')) as req:
            with self.assertRaises(Error): c.request('/forward','PUT',[])
            self.assertEqual(req.call_count,1)

    def test_offset_cursor_next_token(self):
        for kind in ('offset','cursor','next_token'):
            cap=copy.deepcopy(CAP); pg=cap['logs']['pagination']; pg['kind']=kind; pg['first']=0 if kind=='offset' else None
            c=Fake(); c.batches=[{**self.batch([{'id':1}],1),'next':None}]
            r=Logs(c,cap).query(FILTER)
            self.assertTrue(r['complete'])
            if kind=='offset': self.assertIn('page=0',c.calls[0][0])
    def test_checkpoint_corruption(self):
        r=self.query([self.batch([{'id':1}],2)],limits={'page_size':1,'max_pages':1})
        r['checkpoint']['rows'][0]['id']=999
        with self.assertRaisesRegex(Error,'CHECKPOINT_CORRUPTED'): self.query([],limits={'page_size':1},checkpoint=r['checkpoint'])
    def test_tls_self_signed_error_is_not_retryable(self):
        import ssl, urllib.error
        c=Client({'base_url':NORMAL})
        with patch.object(c.opener,'open',side_effect=urllib.error.URLError(ssl.SSLCertVerificationError('fixture'))):
            with self.assertRaises(Error) as caught: c.raw('/health')
            self.assertEqual(caught.exception.code,'TLS_FAILURE'); self.assertFalse(caught.exception.retryable)
