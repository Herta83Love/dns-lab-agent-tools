from __future__ import annotations

import base64
import csv
import datetime as dt
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
import shutil
import ssl
import string
import subprocess
import time
import urllib.parse
import urllib.error
import urllib.request
import uuid
from pathlib import Path

DEFAULT_ROOT = Path.home() / "Herta-Chat" / "agent_workspace" / "dns_lab"
ROOT = DEFAULT_ROOT
CONFIG_PATH = Path(__file__).with_name("dns_lab_config.json")
AUDIT = ROOT / "audit.jsonl"
PLANS = ROOT / "plans"
EXPORTS = ROOT / "exports"
TOOL_CONTRACT_VERSION = "3.0"

AGENT_RECOVERY_RULES = [
    "每次新任務或對話壓縮後，先呼叫 lab_dns_get_context；不要搜尋工具檔案或猜測 API。",
    "只能透過 lab_dns_* 工具操作設備；不得改用 shell、curl、瀏覽器或自行重放 HTTP request。",
    "帳號密碼由工具從 mode-0600 secret file 讀取；不得要求、顯示或放入參數、命令、文件與回覆。",
    "寫入操作固定為 context → read current state → plan → human approval → apply → verify。",
    "遇到 retryable=false 或 action=stop_and_report 時立即停止；不得改 method、endpoint 或 payload 猜測重試。",
    "Log 匯出結果是 unlabeled staging，不得自動當成 strong training data。",
]


class DNSLabToolError(RuntimeError):
    """Machine-readable, secret-free failure contract for the calling Agent."""

    def __init__(self, code, message, *, retryable=False, next_action="stop_and_report", details=None):
        self.payload = {
            "error_code": code,
            "message": message,
            "retryable": bool(retryable),
            "action": "retry_with_same_tool" if retryable else "stop_and_report",
            "next_action": next_action,
        }
        if details:
            self.payload["details"] = details
        super().__init__(_canonical(self.payload))


def _bind_workspace(cfg):
    global ROOT, AUDIT, PLANS, EXPORTS
    raw = cfg.get("workspace_root")
    root = Path(raw).expanduser() if raw else DEFAULT_ROOT
    if not root.is_absolute():
        raise DNSLabToolError(
            "CONFIG_INVALID",
            "workspace_root must be an absolute path.",
            next_action="Stop. Fix the protected dns_lab_config.json. Do not point workspace_root at the repository example or a secret file.",
        )
    ROOT = root
    AUDIT = root / "audit.jsonl"
    PLANS = root / "plans"
    EXPORTS = root / "exports"


def _config():
    if not CONFIG_PATH.is_file():
        raise DNSLabToolError(
            "CONFIG_MISSING",
            "dns_lab_config.json is not present beside the canonical module.",
            next_action="Stop. Install the protected deployment config on the agent host. dns_lab_config.example.json is placeholders only and must not be renamed into service. Do not curl the appliance or guess credentials.",
        )
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise DNSLabToolError(
            "CONFIG_INVALID",
            "dns_lab_config.json could not be read as JSON.",
            next_action="Stop. Ask the human operator to repair the protected config. Do not print the file or replace it with the example.",
        ) from None
    if not isinstance(cfg, dict):
        raise DNSLabToolError(
            "CONFIG_INVALID",
            "dns_lab_config.json must be a JSON object.",
            next_action="Stop. Ask the human operator to repair the protected config.",
        )
    _bind_workspace(cfg)
    return cfg


def _lock_exclusive(file_obj):
    if os.name == "nt":
        import msvcrt
        file_obj.seek(0)
        msvcrt.locking(file_obj.fileno(), msvcrt.LK_LOCK, 1)
        return
    import fcntl
    fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)


def _unlock(file_obj):
    if os.name == "nt":
        import msvcrt
        file_obj.seek(0)
        msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl
    fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)


def _nt_owner_only(path):
    """True when a Windows DACL grants read to the owner, SYSTEM, and Administrators only."""
    import ctypes
    from ctypes import wintypes

    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    info = 0x1 | 0x4  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    get_info = adv.GetNamedSecurityInfoW
    get_info.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_info.restype = wintypes.DWORD
    status = get_info(str(path), 1, info, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if status != 0 or not descriptor.value:
        return False
    try:
        if not owner.value or not dacl.value:
            return False
        convert = adv.ConvertSidToStringSidW
        convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        convert.restype = wintypes.BOOL
        local_free = kernel.LocalFree
        local_free.argtypes = [ctypes.c_void_p]
        local_free.restype = ctypes.c_void_p

        def sid_text(sid_ptr):
            out = ctypes.c_void_p()
            if not convert(sid_ptr, ctypes.byref(out)) or not out.value:
                return ""
            try:
                return ctypes.cast(out, ctypes.c_wchar_p).value or ""
            finally:
                local_free(out)

        owner_sid = sid_text(owner)
        if not owner_sid:
            return False
        allowed = {owner_sid, "S-1-5-18", "S-1-5-32-544"}

        class ACL(ctypes.Structure):
            _fields_ = [
                ("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                ("AclSize", wintypes.WORD), ("AceCount", wintypes.WORD), ("Sbz2", wintypes.WORD),
            ]

        class ACE_HEADER(ctypes.Structure):
            _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]

        acl = ctypes.cast(dacl, ctypes.POINTER(ACL)).contents
        get_ace = adv.GetAce
        get_ace.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        get_ace.restype = wintypes.BOOL
        read_mask = 0x1 | 0x80000000 | 0x10000000  # FILE_READ_DATA | GENERIC_READ | GENERIC_ALL
        for index in range(acl.AceCount):
            ace = ctypes.c_void_p()
            if not get_ace(dacl, index, ctypes.byref(ace)) or not ace.value:
                return False
            header = ctypes.cast(ace, ctypes.POINTER(ACE_HEADER)).contents
            if header.AceType != 0:  # ACCESS_ALLOWED_ACE_TYPE
                continue
            mask = ctypes.cast(ace.value + ctypes.sizeof(ACE_HEADER), ctypes.POINTER(wintypes.DWORD)).contents.value
            if (mask & read_mask) == 0:
                continue
            sid = sid_text(ace.value + ctypes.sizeof(ACE_HEADER) + ctypes.sizeof(wintypes.DWORD))
            if sid not in allowed:
                return False
        return True
    finally:
        kernel.LocalFree(descriptor)


def _is_windows():
    return os.name == "nt"


def _read_private_secret(path):
    secret = Path(path)
    if not secret.is_file():
        private = False
    elif _is_windows():
        private = _nt_owner_only(secret)
    else:
        private = (secret.stat().st_mode & 0o077) == 0
    if not private:
        raise DNSLabToolError(
            "SECRET_UNAVAILABLE",
            "lab DNS secret missing or not private to the owner",
            next_action="Stop. Ask the human operator to install the secret on the agent host as a POSIX mode-0600 file or a Windows owner-only ACL. Do not request, paste, or invent the password.",
        )
    return secret.read_text(encoding="utf-8").rstrip("\r\n")


def _free_bytes(path):
    return shutil.disk_usage(path).free


def _dig_executable():
    if os.name != "nt":
        path = Path("/usr/bin/dig")
        if path.is_file():
            return str(path)
    else:
        found = shutil.which("dig")
        if found and Path(found).name.lower() == "dig.exe":
            return found
    raise DNSLabToolError(
        "DIG_UNAVAILABLE",
        "The dig executable required for synthetic traffic is not available.",
        next_action="Stop. Do not substitute shell, nslookup, curl, or another resolver.",
    )


DNS_LAB_TOOL_DEFINITIONS = [
    {"type":"function","function":{"name":"lab_dns_get_context","description":"任務起點與壓縮後恢復工具。回傳可用 profile、安全限制、正確工作流程、已知設備限制及最近計畫；不連線設備、不回傳秘密。開始 DNS lab 工作前先呼叫此工具，禁止自行搜尋檔案或猜 API。若 error_code 是 CONFIG_MISSING、CONFIG_INVALID 或 SECRET_UNAVAILABLE，停止並原樣回報，不要搜尋設定檔、機密檔或改走 shell/curl。","parameters":{"type":"object","properties":{"dns_profile":{"type":"string","description":"可選；指定後只回傳該 profile 的公開能力"}}}}},
    {"type":"function","function":{"name":"lab_dns_get_plan_status","description":"恢復既有 forward/traffic 計畫狀態與下一步。只讀；不回傳 approval token。壓縮後若記得 plan_id，先用此工具，不要重建或重試寫入。","parameters":{"type":"object","properties":{"plan_id":{"type":"string","description":"可省略；省略時列出最近 10 個計畫"}}}}},
    {"type":"function","function":{"name":"lab_dns_get_forwarders","description":"唯讀取得指定 DNS profile 的現行 forward 清單及 UUID。修改前必須先呼叫；不得以 shell/curl 重查或直接猜 UUID。","parameters":{"type":"object","properties":{"dns_profile":{"type":"string","default":"lab-malicious"}}}}},
    {"type":"function","function":{"name":"lab_dns_export_logs","description":"唯讀匯出指定時間窗的 Proxy DNS Log 到受保護目錄，只回傳統計、路徑與 SHA-256。時間必須是含 UTC offset 的 RFC3339，end 至少早於現在 2 分鐘。domain 規則使用字串陣列；若回傳結構化不可重試錯誤，停止且不要自行呼叫 API。輸出固定是 lab_unlabeled_staging。","parameters":{"type":"object","properties":{"dns_profile":{"type":"string","default":"lab-malicious"},"start_time":{"type":"string","description":"含時區 RFC3339，例如 2026-10-01T14:00:00+08:00"},"end_time":{"type":"string","description":"含時區 RFC3339；至少早於現在 2 分鐘"},"domains":{"type":"array","items":{"type":"string"},"maxItems":200,"description":"完整 domain/suffix 字串陣列，不要傳 scalar"},"exclude_domains":{"type":"boolean","default":False},"qtypes":{"type":"array","items":{"type":"string"},"maxItems":20},"actions":{"type":"array","items":{"type":"string","enum":["Allow","Block","Truncate","Translate"]},"maxItems":4},"source_ips":{"type":"array","items":{"type":"string"},"maxItems":100},"categories":{"type":"array","items":{"type":"string"},"maxItems":100},"result_terms":{"type":"array","items":{"type":"string"},"maxItems":100}},"required":["start_time","end_time"]}}},
    {"type":"function","function":{"name":"lab_dns_plan_forward_change","description":"只建立 forward add/modify/delete 預覽，不寫設備。固定流程：get_context → get_forwarders → plan → 人工核准 → apply。modify/delete 的 UUID 必須來自最新 get_forwarders。primary/secondary 必須是允許的私網 IP[:port]；允許值以 get_context 為準，不要猜。","parameters":{"type":"object","properties":{"dns_profile":{"type":"string","default":"lab-malicious"},"operation":{"type":"string","enum":["add","modify","delete"]},"domain":{"type":"string"},"primary":{"type":"string","description":"允許的私有 IP，可附核准 port；add/modify 必填"},"secondary":{"type":"string"},"recursive":{"type":"boolean","default":False},"enabled":{"type":"boolean","default":True},"uuid":{"type":"string","description":"modify/delete 必填，必須來自最新現況"}},"required":["operation","domain"]}}},
    {"type":"function","function":{"name":"lab_dns_apply_forward_plan","description":"套用既有且人工核准的 forward 計畫。只接受 plan_id 與一次性 token；不得放入設備密碼。若錯誤標記 retryable=false，立即停止並原樣回報 error_code/next_action，禁止猜測其他 endpoint、HTTP method 或 payload。","parameters":{"type":"object","properties":{"plan_id":{"type":"string"},"approval_token":{"type":"string"}},"required":["plan_id","approval_token"]}}},
    {"type":"function","function":{"name":"lab_dns_plan_synthetic_traffic","description":"建立受限的合成高熵/DGA-like DNS 流量預覽；不執行且不讀取檔案或真實 payload。domain_suffix、count、qps 與 port 限制以 lab_dns_get_context 為準，不要依聊天記憶猜測。","parameters":{"type":"object","properties":{"dns_profile":{"type":"string","default":"lab-malicious"},"mode":{"type":"string","enum":["high_entropy","dga_like","nxdomain_burst","synthetic_tunnel_shape"]},"domain_suffix":{"type":"string","description":"必須符合 get_context 回傳的 allowed_forward_suffixes"},"count":{"type":"integer","minimum":1,"maximum":500},"qps":{"type":"number","minimum":0.2,"maximum":20},"qtype":{"type":"string","enum":["A","AAAA","TXT","CNAME"]},"seed":{"type":"integer"}},"required":["mode","domain_suffix","count","qps","qtype","seed"]}}},
    {"type":"function","function":{"name":"lab_dns_run_synthetic_traffic_plan","description":"執行既有且人工核准的合成流量計畫。只接受 plan_id 與一次性 token；遇到不可重試錯誤立即停止，不得改用 shell/dig 自行補跑。","parameters":{"type":"object","properties":{"plan_id":{"type":"string"},"approval_token":{"type":"string"}},"required":["plan_id","approval_token"]}}},
]

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
    line=_canonical(record)+"\n"
    if os.name=="nt":
        lock_path=AUDIT.with_name(AUDIT.name+".lock")
        with lock_path.open("a+b") as lockf:
            lockf.seek(0)
            if lockf.read(1)==b"":
                lockf.seek(0); lockf.write(b"\0"); lockf.flush()
            lockf.seek(0); _lock_exclusive(lockf)
            try:
                with AUDIT.open("a",encoding="utf-8",newline="\n") as handle: handle.write(line)
            finally: _unlock(lockf)
        os.chmod(lock_path,0o600)
    else:
        with AUDIT.open("a",encoding="utf-8",newline="\n") as handle:
            _lock_exclusive(handle)
            try: handle.write(line)
            finally: _unlock(handle)
    os.chmod(AUDIT,0o600)


def _public_profile(name, profile):
    return {
        "dns_profile": name,
        "allow_forward_writes": bool(profile.get("allow_forward_writes", False)),
        "forward_write_status": profile.get(
            "forward_write_status",
            "enabled" if profile.get("allow_forward_writes", False) else "disabled",
        ),
        "traffic_dns_server": profile.get("traffic_dns_server"),
        "traffic_dns_port": profile.get("traffic_dns_port"),
        "operator_notes": profile.get("operator_notes", []),
    }


def _plan_summary(path):
    plan=json.loads(path.read_text())
    approval=path.with_name(f"{plan['plan_id']}.approval.json")
    expired=_now()>dt.datetime.fromisoformat(plan["expires_at"])
    if plan.get("used"):
        state="used"
        next_action="No action: this one-time plan has already been consumed. Create a new plan if needed."
    elif expired:
        state="expired"
        next_action="Create a new preview plan; expired plans must never be reused."
    elif approval.is_file():
        state="approved"
        next_action="Ask the human operator for the one-time token, then call the matching apply/run tool once."
    else:
        state="awaiting_human_approval"
        next_action=f"Human runs: python -m agent.approve_dns_lab_plan {plan['plan_id']}"
    return {
        "plan_id": plan["plan_id"],
        "kind": plan["kind"],
        "state": state,
        "created_at": plan["created_at"],
        "expires_at": plan["expires_at"],
        "plan_sha256": plan["plan_sha256"],
        "preview": plan["payload"],
        "next_action": next_action,
    }


def _context(profile_name=None):
    cfg=_config()
    if profile_name:
        name,profile=_profile(profile_name)
        profiles=[_public_profile(name,profile)]
    else:
        profiles=[_public_profile(name,profile) for name,profile in cfg["profiles"].items()]
    recent=[]
    if PLANS.is_dir():
        for path in sorted(PLANS.glob("*.json"),key=lambda item:item.stat().st_mtime,reverse=True):
            if path.name.endswith(".approval.json") or path.name.endswith(".before.json"):
                continue
            try: recent.append(_plan_summary(path))
            except (KeyError,ValueError,json.JSONDecodeError): continue
            if len(recent)>=10: break
    return {
        "tool_contract_version": TOOL_CONTRACT_VERSION,
        "default_profile": cfg["default_profile"],
        "profiles": profiles,
        "policy": {
            "allowed_forward_suffixes": cfg["allowed_forward_suffixes"],
            "allowed_forward_networks": cfg["allowed_forward_networks"],
            "allowed_forward_ports": cfg["allowed_forward_ports"],
            "max_export_bytes": cfg["max_export_bytes"],
            "min_free_bytes": cfg["min_free_bytes"],
            "max_traffic_queries": cfg["max_traffic_queries"],
            "max_traffic_qps": cfg["max_traffic_qps"],
            "plan_ttl_seconds": cfg["plan_ttl_seconds"],
        },
        "recovery_rules": AGENT_RECOVERY_RULES,
        "known_limitations": cfg.get("known_limitations", []),
        "recent_plans": recent,
        "recommended_first_read": "Call lab_dns_get_forwarders for current device state before planning a change.",
    }

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
        self.password=_read_private_secret(self.cfg["secret_file"])
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

def execute_dns_lab_tool(name, args=None):
    try:
        return _execute_dns_lab_tool(name, args or {})
    except DNSLabToolError:
        raise
    except ValueError as error:
        raise DNSLabToolError(
            "INVALID_ARGUMENT",
            str(error),
            next_action="Stop and correct the arguments from lab_dns_get_context. Do not guess endpoints, methods, or payload shapes.",
        ) from None
    except urllib.error.HTTPError as error:
        raise DNSLabToolError(
            "HTTP_ERROR",
            "The appliance returned an HTTP error.",
            next_action="Stop and report this error. Do not switch to curl or another endpoint.",
            details={"http_status": error.code},
        ) from None
    except (TimeoutError, urllib.error.URLError):
        raise DNSLabToolError(
            "TRANSPORT_ERROR",
            "The appliance request failed before a confirmed response.",
            next_action="Stop and report this error. Do not switch to curl, a browser, or another endpoint.",
            details={"error_type": "transport"},
        ) from None
    except FileNotFoundError:
        raise DNSLabToolError(
            "NOT_FOUND",
            "A required local file is missing.",
            next_action="Stop and report this error. Do not search the workspace for secrets or credentials.",
        ) from None
    except RuntimeError as error:
        message=str(error)
        lowered=message.lower()
        if "secret" in lowered or "password" in lowered:
            raise DNSLabToolError(
                "SECRET_UNAVAILABLE",
                "lab DNS secret or login material is unavailable",
                next_action="Stop. Do not request, paste, or invent passwords, cookies, or CSRF tokens.",
            ) from None
        raise DNSLabToolError(
            "RUNTIME_REJECTED",
            message,
            next_action="Stop and report error_code and next_action. Do not vary the endpoint, method, or payload.",
        ) from None

def _execute_dns_lab_tool(name, args):
    cfg=_config()
    if name=="lab_dns_get_context":
        result=_context(args.get("dns_profile")); _audit("context_read",dns_profile=args.get("dns_profile")); return result
    if name=="lab_dns_get_plan_status":
        plan_id=str(args.get("plan_id","")).strip()
        if plan_id:
            if not re.fullmatch(r"(?:forward|traffic)-[A-Za-z0-9T-]+",plan_id):
                raise DNSLabToolError("INVALID_PLAN_ID","plan_id format is invalid",next_action="Call lab_dns_get_context to recover recent valid plan IDs.")
            path=PLANS/f"{plan_id}.json"
            if not path.is_file():
                raise DNSLabToolError("PLAN_NOT_FOUND","No plan exists with that ID.",next_action="Call lab_dns_get_context to list recent plans; do not guess IDs.")
            plans=[_plan_summary(path)]
        else:
            plans=_context().get("recent_plans",[])
        _audit("plan_status_read",plan_id=plan_id or None,count=len(plans)); return {"plans":plans,"count":len(plans),"secrets_returned":False}
    profile_name=str(args.get("dns_profile",cfg["default_profile"]))
    _,profile=_profile(profile_name)
    if name=="lab_dns_get_forwarders":
        values=[_sanitized_forward(x) for x in _forwarders(profile_name=profile_name)]; _audit("forward_read",dns_profile=profile_name,count=len(values)); return {"dns_profile":profile_name,"count":len(values),"forwarders":values,"next_action":"For changes, pass an exact current UUID to lab_dns_plan_forward_change. Do not call the appliance API directly."}
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
            if _free_bytes(out)-len(raw)<cfg["min_free_bytes"]: raise RuntimeError("minimum free-space guard triggered")
            path=out/f"page-{page:06d}.json"; path.write_bytes(raw); os.chmod(path,0o600)
            pages.append({"page":page,"rows":len(rows),"sha256":page_sha}); seen_page_hashes.add(page_sha); total+=len(rows); total_bytes+=len(raw)
            if len(rows)<2500: break
            page+=1
        manifest={"batch_id":batch,"dns_profile":profile_name,"start":start.isoformat(),"end":end.isoformat(),"filter":filters,"rows":total,"raw_bytes":total_bytes,"pages":pages,"partition":"lab_unlabeled_staging"}
        mp=out/"manifest.json"; mp.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n"); os.chmod(mp,0o600)
        _audit("logs_exported",dns_profile=profile_name,batch_id=batch,rows=total,pages=len(pages),manifest_sha256=_sha(mp.read_bytes()))
        return {"dns_profile":profile_name,"batch_id":batch,"rows":total,"pages":len(pages),"raw_bytes":total_bytes,"filter":filters,"manifest_sha256":_sha(mp.read_bytes()),"output":str(out),"partition":"lab_unlabeled_staging","next_action":"Validate schema, ownership, deduplication, labels and leakage outside this tool before any Dataset intake. Never treat this export as strong-labeled data."}
    if name=="lab_dns_plan_forward_change":
        if not profile.get("allow_forward_writes",False): raise ValueError("forward writes are disabled for this DNS profile")
        operation=args["operation"]; domain=_domain(args["domain"],cfg); current=_forwarders(profile_name=profile_name); uuid_value=str(args.get("uuid","")).strip()
        existing=next((x for x in current if str(x.get("uuid"))==uuid_value),None)
        if operation in {"modify","delete"} and not existing: raise ValueError("uuid does not match a current forward entry")
        if operation in {"add","modify"} and not str(args.get("primary","")).strip(): raise ValueError("primary is required for add/modify")
        payload={"dns_profile":profile_name,"operation":operation,"domain":domain,"uuid":uuid_value}
        if operation!="delete": payload.update({"primary":_split_target(args.get("primary",""),cfg),"secondary":_split_target(args.get("secondary",""),cfg),"recursive":bool(args.get("recursive",False)),"state":bool(args.get("enabled",True))})
        result={**_write_plan("forward",payload,current),"preview":payload,"current_count":len(current)}
        result["next_action"]=f"Human reviews this immutable preview and runs: python -m agent.approve_dns_lab_plan {result['plan_id']}. Then call lab_dns_apply_forward_plan once with the returned token."
        result["do_not"]= "Do not call curl/shell/browser APIs, change HTTP methods, or recreate the plan unless it expires or current state changes."
        return result
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
        try:
            status,_,raw=client.request("/webApi/recursor/forward",method,body)
        except urllib.error.HTTPError as error:
            raw_error=error.read(2048).decode("utf-8",errors="replace")
            digest=_sha(raw_error.encode())
            _audit("forward_apply_rejected",plan_id=plan["plan_id"],operation=operation,http_status=error.code,response_sha256=digest)
            raise DNSLabToolError(
                "FORWARD_API_REJECTED",
                "The appliance rejected the approved forward write. The plan remains unused.",
                retryable=False,
                next_action="Stop. Report plan_id, HTTP status and response_sha256 to the human operator. Use the appliance GUI or vendor/admin remediation; do not probe alternate endpoints, methods or payload shapes.",
                details={"plan_id":plan["plan_id"],"http_status":error.code,"response_sha256":digest},
            ) from None
        except (TimeoutError,urllib.error.URLError) as error:
            _audit("forward_apply_transport_error",plan_id=plan["plan_id"],operation=operation,error_type=type(error).__name__)
            raise DNSLabToolError(
                "FORWARD_TRANSPORT_ERROR",
                "The approved write did not receive a confirmed appliance response; outcome is unknown and the plan remains unused.",
                retryable=False,
                next_action="Stop and call lab_dns_get_forwarders to verify current state. Do not blindly retry the write.",
                details={"plan_id":plan["plan_id"]},
            ) from None
        after=_forwarders(client); _mark_used(plan,path)
        _audit("forward_applied",plan_id=plan["plan_id"],operation=operation,http_status=status,before_sha256=_sha(_canonical(before).encode()),after_sha256=_sha(_canonical(after).encode()))
        return {"applied":True,"plan_id":plan["plan_id"],"operation":operation,"http_status":status,"before_count":len(before),"after_count":len(after),"backup":str(backup),"next_action":"Verify the intended domain/target in lab_dns_get_forwarders, then record the after-state hash in the experiment manifest."}
    if name=="lab_dns_plan_synthetic_traffic":
        suffix=_domain(args["domain_suffix"],cfg); count=int(args["count"]); qps=float(args["qps"])
        if count>cfg["max_traffic_queries"] or qps>cfg["max_traffic_qps"]: raise ValueError("traffic limit exceeded")
        payload={"dns_profile":profile_name,"mode":args["mode"],"domain_suffix":suffix,"count":count,"qps":qps,"qtype":args["qtype"],"seed":int(args["seed"]),"server":profile["traffic_dns_server"],"port":profile["traffic_dns_port"]}
        result={**_write_plan("traffic",payload,{}),"preview":payload,"synthetic_only":True}
        result["next_action"]=f"Human reviews this immutable preview and runs: python -m agent.approve_dns_lab_plan {result['plan_id']}. Then call lab_dns_run_synthetic_traffic_plan once with the returned token."
        result["do_not"]="Do not replace this tool with shell/dig and do not use real files, credentials or user data as payload."
        return result
    if name=="lab_dns_run_synthetic_traffic_plan":
        plan,path,_=_consume_approval(args["plan_id"],args["approval_token"])
        if plan["kind"]!="traffic": raise ValueError("not a traffic plan")
        p=plan["payload"]; rng=random.Random(p["seed"]); alphabet=string.ascii_lowercase+string.digits
        dig=_dig_executable(); started=time.monotonic(); ok=0; failed=0
        for index in range(p["count"]):
            if p["mode"]=="high_entropy": label="".join(rng.choice(alphabet) for _ in range(40))
            elif p["mode"]=="dga_like": label="".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(12,24)))
            elif p["mode"]=="nxdomain_burst": label=f"nx-{p['seed']}-{index}-{rng.randrange(10**8):08d}"
            else:
                raw=hashlib.sha256(f"synthetic:{p['seed']}:{index}".encode()).digest(); label=base64.b32encode(raw).decode().lower().rstrip("=")[:50]
            qname=f"{label}.{p['domain_suffix']}"
            result=subprocess.run([dig,f"@{p['server']}","-p",str(p["port"]),qname,p["qtype"],"+tries=1","+time=2","+short"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=4)
            ok += result.returncode==0; failed += result.returncode!=0
            target=(index+1)/p["qps"]; delay=target-(time.monotonic()-started)
            if delay>0: time.sleep(delay)
        _mark_used(plan,path); _audit("synthetic_traffic_completed",plan_id=plan["plan_id"],mode=p["mode"],count=p["count"],ok=ok,failed=failed,duration_seconds=round(time.monotonic()-started,3))
        return {"completed":True,"plan_id":plan["plan_id"],"mode":p["mode"],"sent":p["count"],"ok":ok,"failed":failed,"synthetic_only":True,"next_action":"Export the exact capture window with lab_dns_export_logs, then run governance checks. This result alone is not label evidence."}
    raise DNSLabToolError("UNKNOWN_TOOL","Unknown DNS lab tool.",next_action="Call only the registered lab_dns_* tools. Start with lab_dns_get_context.")

def approve_plan_cli(plan_id):
    _secure_dirs(); path=PLANS/f"{plan_id}.json"
    if not path.is_file(): raise FileNotFoundError("plan not found")
    plan=json.loads(path.read_text())
    if _now()>dt.datetime.fromisoformat(plan["expires_at"]): raise ValueError("plan expired")
    token=secrets.token_urlsafe(32); approval={"plan_id":plan_id,"plan_sha256":plan["plan_sha256"],"token_sha256":_sha(token.encode()),"approved_at":_now().isoformat(),"approved_by":getpass.getuser()}
    out=PLANS/f"{plan_id}.approval.json"; out.write_text(json.dumps(approval,indent=2,sort_keys=True)+"\n"); os.chmod(out,0o600); _audit("plan_human_approved",plan_id=plan_id,kind=plan["kind"])
    return token
