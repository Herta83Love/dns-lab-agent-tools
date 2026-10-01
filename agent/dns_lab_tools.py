from __future__ import annotations

import base64
import csv
import datetime as dt
import fcntl
import getpass
import hashlib
import http.client
import http.cookiejar
import ipaddress
import json
import math
import os
import random
import re
import secrets
import ssl
import string
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path.home() / "Herta-Chat" / "agent_workspace" / "dns_lab"
CONFIG_PATH = Path(__file__).with_name("dns_lab_config.json")
AUDIT = ROOT / "audit.jsonl"
PLANS = ROOT / "plans"
EXPORTS = ROOT / "exports"

DNS_LAB_TOOL_DEFINITIONS = [
    {"type":"function","function":{"name":"lab_dns_get_forwarders","description":"依具名 DNS profile 唯讀取得 forward 設定；不做變更。","parameters":{"type":"object","properties":{"dns_profile":{"type":"string","default":"lab-malicious"}}}}},
    {"type":"function","function":{"name":"lab_dns_export_logs","description":"依具名 DNS profile 匯出任意有效歷史時間窗的配對 Proxy Log。支援伺服器端 domain/QTYPE/action/source/category/result 篩選，只回傳統計與雜湊。","parameters":{"type":"object","properties":{"dns_profile":{"type":"string","default":"lab-malicious"},"start_time":{"type":"string","description":"含時區 RFC3339"},"end_time":{"type":"string","description":"含時區 RFC3339"},"domains":{"type":"array","items":{"type":"string"},"maxItems":200},"exclude_domains":{"type":"boolean","default":False},"qtypes":{"type":"array","items":{"type":"string"},"maxItems":20},"actions":{"type":"array","items":{"type":"string","enum":["Allow","Block","Truncate","Translate"]},"maxItems":4},"source_ips":{"type":"array","items":{"type":"string"},"maxItems":100},"categories":{"type":"array","items":{"type":"string"},"maxItems":100},"result_terms":{"type":"array","items":{"type":"string"},"maxItems":100}},"required":["start_time","end_time"]}}},
    {"type":"function","function":{"name":"lab_dns_plan_forward_change","description":"依具名 DNS profile 建立 forward 新增、修改或刪除的唯讀預覽計畫；不套用。正式套用需要人工核准 token。","parameters":{"type":"object","properties":{"dns_profile":{"type":"string","default":"lab-malicious"},"operation":{"type":"string","enum":["add","modify","delete"]},"domain":{"type":"string"},"primary":{"type":"string","description":"私有 IP，可附 :53 或 :5353"},"secondary":{"type":"string"},"recursive":{"type":"boolean","default":False},"enabled":{"type":"boolean","default":True},"uuid":{"type":"string","description":"modify/delete 必填，必須來自現況"}},"required":["operation","domain"]}}},
    {"type":"function","function":{"name":"lab_dns_apply_forward_plan","description":"以人工提供的一次性 token 套用先前建立的 forward 計畫。不能直接傳任意設定。","parameters":{"type":"object","properties":{"plan_id":{"type":"string"},"approval_token":{"type":"string"}},"required":["plan_id","approval_token"]}}},
    {"type":"function","function":{"name":"lab_dns_plan_synthetic_traffic","description":"依具名 DNS profile 建立受限的合成高熵或 DGA-like DNS 流量計畫；不執行、不讀取真實資料。","parameters":{"type":"object","properties":{"dns_profile":{"type":"string","default":"lab-malicious"},"mode":{"type":"string","enum":["high_entropy","dga_like","nxdomain_burst","synthetic_tunnel_shape"]},"domain_suffix":{"type":"string","description":"只允許核准的 .test/.example/.invalid 後綴"},"count":{"type":"integer","minimum":1,"maximum":500},"qps":{"type":"number","minimum":0.2,"maximum":20},"qtype":{"type":"string","enum":["A","AAAA","TXT","CNAME"]},"seed":{"type":"integer"}},"required":["mode","domain_suffix","count","qps","qtype","seed"]}}},
    {"type":"function","function":{"name":"lab_dns_run_synthetic_traffic_plan","description":"以人工提供的一次性 token 執行先前核准的合成 DNS 流量計畫。","parameters":{"type":"object","properties":{"plan_id":{"type":"string"},"approval_token":{"type":"string"}},"required":["plan_id","approval_token"]}}},
]

def _config(): return json.loads(CONFIG_PATH.read_text())
def _profile(name=None):
    cfg=_config(); name=name or cfg["default_profile"]
    if name not in cfg["profiles"]: raise ValueError("unknown DNS profile")
    return name,cfg["profiles"][name]
def _sha(data: bytes): return hashlib.sha256(data).hexdigest()
def _canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def _now(): return dt.datetime.now(dt.timezone.utc)
def _secure_dirs():
    for path in (ROOT,PLANS,EXPORTS): path.mkdir(parents=True,exist_ok=True); os.chmod(path,0o700)
def _audit(event, **fields):
    _secure_dirs(); record={"at":_now().isoformat(),"event":event,**fields}
    with AUDIT.open("a") as f:
        fcntl.flock(f,fcntl.LOCK_EX); f.write(_canonical(record)+"\n"); fcntl.flock(f,fcntl.LOCK_UN)
    os.chmod(AUDIT,0o600)

class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self,host,expected="",**kwargs):
        self.expected=expected
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
        super().__init__(host,context=context,**kwargs)
    def connect(self):
        super().connect(); actual=_sha(self.sock.getpeercert(binary_form=True))
        if actual != self.expected: self.close(); raise ssl.SSLError("lab DNS certificate fingerprint mismatch")
class _PinnedHandler(urllib.request.HTTPSHandler):
    def __init__(self,expected): super().__init__(); self.expected=expected
    def https_open(self,request):
        expected=self.expected
        def factory(host,**kwargs): return _PinnedConnection(host,expected=expected,**kwargs)
        return self.do_open(factory,request)

class LabClient:
    def __init__(self,profile_name=None):
        self.profile_name,self.cfg=_profile(profile_name)
        secret=Path(self.cfg["secret_file"])
        if not secret.is_file() or secret.stat().st_mode & 0o077: raise RuntimeError("lab DNS secret missing or not mode 0600")
        self.password=secret.read_text().rstrip("\r\n")
        self.cookies=http.cookiejar.CookieJar()
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies),_PinnedHandler(self.cfg["certificate_sha256"]))
        self.login()
    def request(self,path,method="GET",body=None):
        headers={}; data=None
        if body is not None: data=_canonical(body).encode(); headers["Content-Type"]="application/json"
        xsrf=next((urllib.parse.unquote(c.value) for c in self.cookies if c.name=="XSRF-TOKEN"),None)
        if xsrf: headers["X-XSRF-TOKEN"]=xsrf
        req=urllib.request.Request(self.cfg["base_url"]+path,data=data,headers=headers,method=method)
        with self.opener.open(req,timeout=45) as r:return r.status,dict(r.headers),r.read()
    def login(self):
        _,_,page=self.request("/login")
        match=re.search(rb'name="_token"\s+value="([^"]+)"',page)
        if not match: raise RuntimeError("lab DNS CSRF token missing")
        form=urllib.parse.urlencode({"_token":match.group(1).decode(),"account":self.cfg["account"],"password":self.password}).encode()
        req=urllib.request.Request(self.cfg["base_url"]+"/login",data=form,headers={"Content-Type":"application/x-www-form-urlencoded"})
        with self.opener.open(req,timeout=45) as r: body=r.read()
        self.password=""
        if b'name="account"' in body: raise RuntimeError("lab DNS login failed")

def _parse_time(value):
    parsed=dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None: raise ValueError("time must include UTC offset")
    return parsed.astimezone(dt.timezone.utc)
def _forwarders(client=None,profile_name=None):
    client=client or LabClient(profile_name); status,_,raw=client.request("/webApi/recursor/forward")
    data=json.loads(raw); return data if isinstance(data,list) else ([data] if data else [])
def _sanitized_forward(item):
    keys=("uuid","domain","state","enable","recursive","primary","secondary","primary_ipv4","secondary_ipv4","status","method")
    return {k:item.get(k) for k in keys if k in item}
def _split_target(value,cfg):
    if not value: return ""
    value=str(value).strip(); host=value; port=53
    if value.count(":")==1: host,p=value.rsplit(":",1); port=int(p)
    address=ipaddress.ip_address(host)
    if not any(address in ipaddress.ip_network(n) for n in cfg["allowed_forward_networks"]): raise ValueError("forward target must be inside an allowed private lab network")
    if port not in cfg["allowed_forward_ports"]: raise ValueError("forward port is not allowed")
    return f"{address}:{port}"
def _domain(value,cfg):
    value=str(value).strip().rstrip(".").lower()
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",value): raise ValueError("invalid domain")
    if not any(value==s or value.endswith("."+s) for s in cfg["allowed_forward_suffixes"]): raise ValueError("domain suffix is not allowed by lab policy")
    return value
def _write_plan(kind,payload,before):
    _secure_dirs(); cfg=_config(); plan_id=f"{kind}-{_now():%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    plan={"schema":"dns-lab-plan-1.0","plan_id":plan_id,"kind":kind,"created_at":_now().isoformat(),"expires_at":(_now()+dt.timedelta(seconds=cfg["plan_ttl_seconds"])).isoformat(),"payload":payload,"before_sha256":_sha(_canonical(before).encode()),"used":False}
    plan["plan_sha256"]=_sha(_canonical(plan).encode()); path=PLANS/f"{plan_id}.json"; path.write_text(json.dumps(plan,indent=2,sort_keys=True)+"\n"); os.chmod(path,0o600)
    _audit("plan_created",plan_id=plan_id,kind=kind,plan_sha256=plan["plan_sha256"])
    return {"plan_id":plan_id,"plan_sha256":plan["plan_sha256"],"expires_at":plan["expires_at"],"requires_human_approval":True}
def _consume_approval(plan_id,token):
    path=PLANS/f"{plan_id}.json"; approval=PLANS/f"{plan_id}.approval.json"
    if not path.is_file() or not approval.is_file(): raise ValueError("plan or human approval not found")
    plan=json.loads(path.read_text()); auth=json.loads(approval.read_text())
    if plan["used"]: raise ValueError("plan already used")
    if _now() > dt.datetime.fromisoformat(plan["expires_at"]): raise ValueError("plan expired")
    if not secrets.compare_digest(_sha(token.encode()),auth["token_sha256"]): raise ValueError("invalid approval token")
    if auth["plan_sha256"]!=plan["plan_sha256"]: raise ValueError("approval is bound to another plan")
    return plan,path,approval
def _mark_used(plan,path):
    plan["used"]=True; plan["used_at"]=_now().isoformat(); path.write_text(json.dumps(plan,indent=2,sort_keys=True)+"\n"); os.chmod(path,0o600)

def execute_dns_lab_tool(name,args):
    cfg=_config()
    profile_name=str(args.get("dns_profile",cfg["default_profile"]))
    _,profile=_profile(profile_name)
    if name=="lab_dns_get_forwarders":
        values=[_sanitized_forward(x) for x in _forwarders(profile_name=profile_name)]; _audit("forward_read",dns_profile=profile_name,count=len(values)); return {"dns_profile":profile_name,"count":len(values),"forwarders":values}
    if name=="lab_dns_export_logs":
        start=_parse_time(args["start_time"]); end=_parse_time(args["end_time"])
        if end<=start: raise ValueError("log window must be positive")
        if end>_now()-dt.timedelta(minutes=2): raise ValueError("end time must be at least 2 minutes in the past")
        filters={}
        if args.get("domains"): filters["qname"]={"field":"domain","reverse":1 if args.get("exclude_domains") else 0,"rule":[str(x).strip().rstrip(".").lower() for x in args["domains"]]}
        if args.get("qtypes"): filters["rtype"]={"field":"type","reverse":0,"rule":[str(x).upper() for x in args["qtypes"]]}
        if args.get("actions"):
            codes={"Allow":[0,1],"Block":[2,3,4],"Truncate":[5],"Translate":[6]}; filters["caction"]={"field":"action","reverse":0,"rule":sum((codes[x] for x in args["actions"]),[])}
        if args.get("source_ips"): filters["srcip"]={"field":"from","reverse":0,"rule":[str(x) for x in args["source_ips"]]}
        if args.get("categories"): filters["category"]={"field":"category","reverse":0,"rule":[str(x) for x in args["categories"]]}
        if args.get("result_terms"): filters["rdata"]={"field":"result","reverse":0,"rule":[str(x) for x in args["result_terms"]]}
        client=LabClient(profile_name)
        batch=f"{profile_name}-log-{start:%Y%m%dT%H%M%SZ}-{end:%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}"; out=EXPORTS/batch; out.mkdir(parents=True); os.chmod(out,0o700)
        pages=[]; total=0; total_bytes=0; seen_page_hashes=set()
        query=urllib.parse.urlencode({"start_time":int(start.timestamp()),"end_time":int(end.timestamp()),"filter":_canonical(filters)})
        page=1
        while True:
            status,_,raw=client.request(f"/webApi/historylog/proxy/{page}?{query}"); rows=json.loads(raw)
            if not isinstance(rows,list): raise RuntimeError("log API did not return a list")
            page_sha=_sha(raw)
            if page_sha in seen_page_hashes: raise RuntimeError("repeated page detected during unbounded pagination")
            if total_bytes+len(raw)>cfg["max_export_bytes"]: raise RuntimeError("export byte guard triggered")
            if os.statvfs(out).f_bavail*os.statvfs(out).f_frsize-len(raw)<cfg["min_free_bytes"]: raise RuntimeError("minimum free-space guard triggered")
            path=out/f"page-{page:06d}.json"; path.write_bytes(raw); os.chmod(path,0o600)
            pages.append({"page":page,"rows":len(rows),"sha256":page_sha}); seen_page_hashes.add(page_sha); total+=len(rows); total_bytes+=len(raw)
            if len(rows)<2500: break
            page+=1
        manifest={"batch_id":batch,"dns_profile":profile_name,"start":start.isoformat(),"end":end.isoformat(),"filter":filters,"rows":total,"raw_bytes":total_bytes,"pages":pages,"partition":"lab_unlabeled_staging"}
        mp=out/"manifest.json"; mp.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n"); os.chmod(mp,0o600)
        _audit("logs_exported",dns_profile=profile_name,batch_id=batch,rows=total,pages=len(pages),manifest_sha256=_sha(mp.read_bytes()))
        return {"dns_profile":profile_name,"batch_id":batch,"rows":total,"pages":len(pages),"raw_bytes":total_bytes,"filter":filters,"manifest_sha256":_sha(mp.read_bytes()),"output":str(out)}
    if name=="lab_dns_plan_forward_change":
        if not profile.get("allow_forward_writes",False): raise ValueError("forward writes are disabled for this DNS profile")
        operation=args["operation"]; domain=_domain(args["domain"],cfg); current=_forwarders(profile_name=profile_name); uuid_value=str(args.get("uuid","")).strip()
        existing=next((x for x in current if str(x.get("uuid"))==uuid_value),None)
        if operation in {"modify","delete"} and not existing: raise ValueError("uuid does not match a current forward entry")
        payload={"dns_profile":profile_name,"operation":operation,"domain":domain,"uuid":uuid_value}
        if operation!="delete": payload.update({"primary":_split_target(args.get("primary",""),cfg),"secondary":_split_target(args.get("secondary",""),cfg),"recursive":bool(args.get("recursive",False)),"state":bool(args.get("enabled",True))})
        return {**_write_plan("forward",payload,current),"preview":payload,"current_count":len(current)}
    if name=="lab_dns_apply_forward_plan":
        plan,path,_=_consume_approval(args["plan_id"],args["approval_token"])
        if plan["kind"]!="forward": raise ValueError("not a forward plan")
        profile_name=plan["payload"]["dns_profile"]; _,profile=_profile(profile_name)
        if not profile.get("allow_forward_writes",False): raise ValueError("forward writes are disabled for this DNS profile")
        client=LabClient(profile_name); before=_forwarders(client)
        if _sha(_canonical(before).encode())!=plan["before_sha256"]: raise RuntimeError("forward configuration changed after preview")
        p=plan["payload"]; operation=p["operation"]
        if operation=="add": body={"domain":p["domain"],"primary":p["primary"],"secondary":p["secondary"],"recursive":p["recursive"],"state":p["state"]}; method="POST"
        elif operation=="modify": body={"uuid":p["uuid"],"domain":p["domain"],"primary":p["primary"],"secondary":p["secondary"],"recursive":p["recursive"],"state":p["state"]}; method="PATCH"
        else: body={"list":[p["uuid"]]}; method="DELETE"
        backup=PLANS/f"{plan['plan_id']}.before.json"; backup.write_text(json.dumps(before,indent=2,sort_keys=True)+"\n"); os.chmod(backup,0o600)
        status,_,raw=client.request("/webApi/recursor/forward",method,body); after=_forwarders(client); _mark_used(plan,path)
        _audit("forward_applied",plan_id=plan["plan_id"],operation=operation,http_status=status,before_sha256=_sha(_canonical(before).encode()),after_sha256=_sha(_canonical(after).encode()))
        return {"applied":True,"plan_id":plan["plan_id"],"operation":operation,"http_status":status,"before_count":len(before),"after_count":len(after),"backup":str(backup)}
    if name=="lab_dns_plan_synthetic_traffic":
        suffix=_domain(args["domain_suffix"],cfg); count=int(args["count"]); qps=float(args["qps"])
        if count>cfg["max_traffic_queries"] or qps>cfg["max_traffic_qps"]: raise ValueError("traffic limit exceeded")
        payload={"dns_profile":profile_name,"mode":args["mode"],"domain_suffix":suffix,"count":count,"qps":qps,"qtype":args["qtype"],"seed":int(args["seed"]),"server":profile["traffic_dns_server"],"port":profile["traffic_dns_port"]}
        return {**_write_plan("traffic",payload,{}),"preview":payload,"synthetic_only":True}
    if name=="lab_dns_run_synthetic_traffic_plan":
        plan,path,_=_consume_approval(args["plan_id"],args["approval_token"])
        if plan["kind"]!="traffic": raise ValueError("not a traffic plan")
        p=plan["payload"]; rng=random.Random(p["seed"]); alphabet=string.ascii_lowercase+string.digits
        started=time.monotonic(); ok=0; failed=0
        for index in range(p["count"]):
            if p["mode"]=="high_entropy": label="".join(rng.choice(alphabet) for _ in range(40))
            elif p["mode"]=="dga_like": label="".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(12,24)))
            elif p["mode"]=="nxdomain_burst": label=f"nx-{p['seed']}-{index}-{rng.randrange(10**8):08d}"
            else:
                raw=hashlib.sha256(f"synthetic:{p['seed']}:{index}".encode()).digest(); label=base64.b32encode(raw).decode().lower().rstrip("=")[:50]
            qname=f"{label}.{p['domain_suffix']}"
            result=subprocess.run(["/usr/bin/dig",f"@{p['server']}","-p",str(p["port"]),qname,p["qtype"],"+tries=1","+time=2","+short"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=4)
            ok += result.returncode==0; failed += result.returncode!=0
            target=(index+1)/p["qps"]; delay=target-(time.monotonic()-started)
            if delay>0: time.sleep(delay)
        _mark_used(plan,path); _audit("synthetic_traffic_completed",plan_id=plan["plan_id"],mode=p["mode"],count=p["count"],ok=ok,failed=failed,duration_seconds=round(time.monotonic()-started,3))
        return {"completed":True,"plan_id":plan["plan_id"],"mode":p["mode"],"sent":p["count"],"ok":ok,"failed":failed,"synthetic_only":True}
    raise ValueError(f"unknown DNS lab tool: {name}")

def approve_plan_cli(plan_id):
    _secure_dirs(); path=PLANS/f"{plan_id}.json"
    if not path.is_file(): raise FileNotFoundError("plan not found")
    plan=json.loads(path.read_text())
    if _now()>dt.datetime.fromisoformat(plan["expires_at"]): raise ValueError("plan expired")
    token=secrets.token_urlsafe(32); approval={"plan_id":plan_id,"plan_sha256":plan["plan_sha256"],"token_sha256":_sha(token.encode()),"approved_at":_now().isoformat(),"approved_by":getpass.getuser()}
    out=PLANS/f"{plan_id}.approval.json"; out.write_text(json.dumps(approval,indent=2,sort_keys=True)+"\n"); os.chmod(out,0o600); _audit("plan_human_approved",plan_id=plan_id,kind=plan["kind"])
    return token
