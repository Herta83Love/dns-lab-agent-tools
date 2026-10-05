from pathlib import Path
import json
import uuid
from .core import Client, Error, Logs, LAB, NORMAL, VERSION, canonical, clean, fail, now, save, sha

COMMON={'profile':{'type':'string'},'target':{'type':'string','description':'Must exactly match the configured base URL.'}}
FILTERS={k:{'type':'string'} for k in ('start_time','end_time','domain','qname','qtype','client_ip','resolver_ip','rcode','action','category','tunneling','garbled')}
LIMITS={'type':'object','properties':{k:{'type':'number' if k=='max_seconds' else 'integer','exclusiveMinimum':0} for k in ('page_size','max_pages','max_records','max_seconds','max_bytes')},'additionalProperties':False}
SPECS={
 'dns_authenticate':({},[]),
 'dns_logout':({},[]),
 'dns_health_check':({},[]),
 'dns_discover_capabilities':({},[]),
 'dns_query_logs':({'filters':{'type':'object','properties':FILTERS,'additionalProperties':False,'required':['start_time','end_time']},'limits':LIMITS,'checkpoint':{'type':'object'}},['filters']),
 'dns_export_logs':({'filters':{'type':'object','properties':FILTERS,'required':['start_time','end_time'],'additionalProperties':False},'limits':LIMITS,'checkpoint':{'type':'object'},'directory':{'type':'string'},'formats':{'type':'array','items':{'enum':['json','jsonl','csv']},'default':['json','jsonl','csv']}},['filters','directory']),
 'dns_get_forward_config':({},[]),
 'dns_plan_forward_change':({'desired':{'type':'array','items':{'type':'object'}}},['desired']),
 'dns_apply_forward_change':({'plan_id':{'type':'string'},'approved_sha256':{'type':'string'},'dry_run':{'type':'boolean','default':True}},['plan_id']),
 'dns_rollback_forward_change':({'plan_id':{'type':'string'},'approved_sha256':{'type':'string'},'dry_run':{'type':'boolean','default':True}},['plan_id']),
}
DNS_TOOL_DEFINITIONS=[{'type':'function','function':{'name':name,'description':('Forward write requires explicit approval of the preview SHA-256; dry-run defaults true. ' if 'change' in name else 'Profile-bound DNS API operation. ')+'Timeout defaults to 30 seconds. Errors are structured; do not guess endpoints.','parameters':{'type':'object','properties':{**COMMON,**props},'required':['profile','target',*required],'additionalProperties':False}}} for name,(props,required) in SPECS.items()]

class Tools:
    def __init__(self, profiles, state_dir, client_factory=Client):
        self.profiles,self.state_dir,self.client_factory=profiles,Path(state_dir),client_factory
        self.clients={}
    def execute(self,name,args):
        try:
            if name not in SPECS: fail('UNKNOWN_TOOL')
            props,required=SPECS[name]
            if set(args)-set(COMMON)-set(props): fail('UNKNOWN_ARGUMENT')
            if any(k not in args for k in ['profile','target',*required]): fail('ARGUMENT_REQUIRED')
            if 'dry_run' in args and not isinstance(args['dry_run'],bool): fail('ARGUMENT_TYPE')
            if 'limits' in args:
                allowed={'page_size','max_pages','max_records','max_seconds','max_bytes'}
                if set(args['limits'])-allowed or any(not isinstance(v,(int,float)) or isinstance(v,bool) or v<=0 for v in args['limits'].values()): fail('LIMITS_INVALID')
            if 'filters' in args and (set(args['filters'])-set(FILTERS) or any(not isinstance(v,str) for v in args['filters'].values())): fail('FILTER_INVALID')
            profile=self.profiles.get(args['profile'])
            if profile is None: fail('UNKNOWN_PROFILE')
            if args['target']!=profile['base_url']: fail('TARGET_MISMATCH')
            if args['profile'] not in self.clients: self.clients[args['profile']]=self.client_factory(profile)
            client=self.clients[args['profile']]
            result=self._run(name,args,profile,client)
            return {'ok':True,'tool_version':VERSION,'result':clean(result)}
        except Error as e:
            return {'ok':False,'error':{'code':e.code,'retryable':e.retryable,'next_action':'retry_same_read' if e.retryable else 'stop_and_report'}}
        except Exception:
            # Never expose appliance response, credentials, or traceback.
            return {'ok':False,'error':{'code':'INVALID_INPUT_OR_PROFILE','retryable':False,'next_action':'stop_and_report'}}
    def _run(self,name,a,p,c):
        if name=='dns_authenticate': return c.authenticate()
        if name=='dns_logout': return c.logout()
        if name=='dns_health_check':
            c.request(p['health_endpoint']); return {'reachable':True,'target':c.base,'at':now()}
        if name=='dns_discover_capabilities':
            # Only a vendor/operator-declared read-only discovery endpoint is requested.
            if not p.get('discovery_endpoint'): fail('DISCOVERY_ENDPOINT_REQUIRED')
            evidence=c.request(p['discovery_endpoint'])
            cap=clean(evidence)
            if not isinstance(cap,dict): fail('DISCOVERY_SCHEMA')
            save(self.state_dir/(a['profile']+'.capability.json'),{'target':c.base,'observed_at':now(),'capability':cap,'tool_version':VERSION})
            return {'capability':cap,'evidence_sha256':sha(canonical(cap)),'verified':False,'next_action':'Map vendor evidence into profile; verify filter semantics before enabling.'}
        if name in ('dns_query_logs','dns_export_logs'):
            logs=Logs(c,p['capability']); result=logs.query(a['filters'],a.get('limits'),a.get('checkpoint'))
            if name=='dns_query_logs': return result
            formats=a.get('formats',['json','jsonl','csv'])
            if not formats or len(formats)!=len(set(formats)) or any(f not in ('json','jsonl','csv') for f in formats): fail('EXPORT_FORMAT')
            return logs.export(result,a['directory'],formats)
        cfg=p.get('capability',{}).get('forward',{})
        if not cfg.get('read_endpoint'): fail('FORWARD_ENDPOINT_UNVERIFIED')
        if name=='dns_get_forward_config': return {'target':c.base,'config':c.request(cfg['read_endpoint'])}
        if name=='dns_plan_forward_change':
            desired=a['desired']; self.validate(desired,cfg)
            before=c.request(cfg['read_endpoint']); plan_id=uuid.uuid4().hex
            plan={'plan_id':plan_id,'target':c.base,'profile':a['profile'],'before':before,'desired':desired,'before_sha256':sha(canonical(before)),'created_at':now(),'diff':{'before':before,'after':desired},'tool_version':VERSION}
            plan['plan_sha256']=sha(canonical(plan)); save(self.state_dir/(plan_id+'.json'),plan,True)
            return {**plan,'dry_run':True}
        plan_id=a['plan_id']
        if len(plan_id)!=32 or any(ch not in '0123456789abcdef' for ch in plan_id): fail('PLAN_ID')
        path=self.state_dir/(plan_id+'.json'); plan=json.loads(path.read_text())
        digest=plan.pop('plan_sha256')
        if sha(canonical(plan))!=digest: fail('PLAN_TAMPERED')
        if plan['target']!=c.base or plan['profile']!=a['profile']: fail('PLAN_TARGET_MISMATCH')
        rollback=name=='dns_rollback_forward_change'
        after_path=self.state_dir/(plan_id+'.after.json')
        if rollback:
            if not after_path.exists(): fail('NO_VERIFIED_AFTER_SNAPSHOT')
            after=json.loads(after_path.read_text()); expected=after['config']; desired=plan['before']
        else: expected=plan['before']; desired=plan['desired']
        current=c.request(cfg['read_endpoint'])
        if canonical(current)!=canonical(expected): fail('FORWARD_STATE_DRIFT')
        if a.get('dry_run',True): return {'dry_run':True,'plan_sha256':digest,'diff':{'before':current,'after':desired}}
        if c.base!=LAB or p.get('role')!='lab' or not p.get('allow_forward_writes'): fail('NORMAL_OR_UNKNOWN_DNS_WRITE_PROTECTED')
        if a.get('approved_sha256')!=digest: fail('EXPLICIT_APPROVAL_REQUIRED')
        if not cfg.get('write_verified') or not cfg.get('write_endpoint'): fail('FORWARD_WRITE_UNVERIFIED')
        self.validate(desired,cfg)
        # Atomic claim prevents replay and concurrent use; uncertain writes require operator recovery.
        claim=self.state_dir/(plan_id+('.rollback.claim' if rollback else '.apply.claim'))
        try: save(claim,{'target':c.base,'at':now()},True)
        except FileExistsError: fail('PLAN_ALREADY_CONSUMED')
        try:
            c.request(cfg['write_endpoint'],cfg.get('method','PUT'),desired)
            actual=c.request(cfg['read_endpoint'])
            save(self.state_dir/(plan_id+('.rollback.after.json' if rollback else '.after.json')),{'config':actual,'sha256':sha(canonical(actual))},True)
            if canonical(actual)!=canonical(desired): fail('FORWARD_VERIFY_FAILED')
        except Error:
            save(self.state_dir/(plan_id+'.failure.json'),{'target':c.base,'before_sha256':plan['before_sha256'],'rollback_tool':'dns_rollback_forward_change','requires_operator_recovery':True})
            raise
        return {'applied':True,'rollback':rollback,'after_sha256':sha(canonical(actual))}
    @staticmethod
    def validate(desired,cfg):
        import ipaddress
        if not isinstance(desired,list) or not desired: fail('FORWARD_CONFIG_INVALID')
        allowed=cfg.get('allowed_fields',['domain','primary','secondary','enabled','recursive'])
        domains=set()
        for row in desired:
            if not isinstance(row,dict) or set(row)-set(allowed): fail('FORWARD_CONFIG_INVALID')
            domain=row.get('domain','')
            if not isinstance(domain,str) or not domain or domain in ('.','*') or domain in domains: fail('FORWARD_DOMAIN_INVALID')
            domains.add(domain)
            for key in ('primary','secondary'):
                if row.get(key):
                    try: ipaddress.ip_address(row[key])
                    except ValueError: fail('FORWARD_ADDRESS_INVALID')
