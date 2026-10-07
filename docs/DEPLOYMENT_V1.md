> Historical v1 deployment reference. Current deployment/config/token flow is [contract 3.3](MANIFEST_TRAFFIC.md); do not copy this archived installation into production.

# VLLM Agent DNS Lab Tools Deployment

**Date:** 2026-10-01 (Asia/Taipei)  
**Agent Runtime:** Herta 27B Agent, port 8002  
**Lab DNS:** `https://172.16.30.209:1606`  
**Normal DNS:** Remains managed separately by the existing Claude Code pipeline

## Endpoint correction

Port 1606 on the lab DNS is HTTPS-only. Plain HTTP returns `400 The plain HTTP request was sent to HTTPS port`. The tools pin this appliance certificate SHA-256:

```text
e5c2b44c3c7b832a58eefe206727b140ba39477370c33adb35b982f9dce342d3
```

This differs from the normal DNS appliance fingerprint.

## Deployed tools

The Agent now exposes 14 tools, including six DNS lab tools.

### `lab_dns_get_forwarders`

Read-only access to `GET /webApi/recursor/forward`.

### `lab_dns_export_logs`

Exports paired Proxy DNS logs through `GET /webApi/historylog/proxy/{page}`. It accepts RFC3339 start/end times and a page limit.

Limits:

- maximum two-hour window;
- end time at least two minutes in the past;
- maximum 100 pages, 2,500 records per page;
- fixed time window across pagination;
- raw records stay in a protected local export directory;
- the model receives only IDs, counts, paths, and hashes.

### `lab_dns_plan_forward_change`

Creates a preview-only plan for `add`, `modify`, or `delete`. It does not call a write API.

Safety policy:

- any syntactically valid FQDN may be used for an approved forward change;
- targets only in private `10/8`, `172.16/12`, or `192.168/16` networks;
- any valid port from 1 through 65535 may be used for an approved forward change;
- the target IP must still be inside an explicitly configured private lab network;
- modify/delete UUID must exist in current configuration;
- no delete-all or default/root forward tool;
- plans expire after 30 minutes;
- each plan is bound to the current configuration SHA-256.

### `lab_dns_apply_forward_plan`

Applies only an existing preview plan with a human-generated one-time token. Before applying, it rechecks expiry, one-time status, token binding, and current configuration SHA-256. It saves a mode-0600 before-state backup, applies only the approved payload, marks the plan used, rereads the result, and writes an audit event.

For iSafer UI build `v2.4.0.2443028217-1`, add and modify requests use the
device's nested domain-route schema. The canonical tool translates an approved
plan internally to this shape; callers must not construct it or replay it with
direct HTTP:

```json
{
  "domain": "sample.lab.test",
  "recursive": true,
  "enable": true,
  "ipv4": {"enable": true, "primary": "172.16.30.210:53", "secondary": ""},
  "ipv6": {"enable": false, "primary": "", "secondary": ""},
  "precedance": 4
}
```

`precedance` is the spelling required by the appliance. The former flat
`primary`/`secondary`/`state` request was invalid and could surface PHP type
errors wrapped as HTTP 404. A 404 containing a controller type error therefore
does not prove that the route is absent.

### `lab_dns_plan_synthetic_traffic`

Creates but does not run a bounded synthetic traffic plan. Supported modes:

```text
high_entropy
dga_like
nxdomain_burst
synthetic_tunnel_shape
```

Supported QTYPEs are `A`, `AAAA`, `TXT`, and `CNAME`.

Limits:

- target fixed to `172.16.30.209:53`;
- maximum 500 queries per plan;
- maximum 20 queries per second;
- suffix restricted to `.test`, `.example`, or `.invalid`;
- content generated only from a numeric seed;
- cannot read files, encode user data, or exfiltrate real content;
- no arbitrary DNS server, shell command, or destination.

### `lab_dns_run_synthetic_traffic_plan`

Runs only a previously previewed and human-approved traffic plan. It invokes `/usr/bin/dig` with a fixed argument list and no shell. Audit data contains plan ID, mode, counts, duration, and success/failure totals.

## Human approval

After the Agent returns `plan_id`, `plan_sha256`, and `expires_at`, review the plan and run:

```text
cd /home/jackie_tsai/Herta-Chat
/home/jackie_tsai/.conda/envs/herta_train/bin/python \
  -m agent.approve_dns_lab_plan <plan_id> --token-file /absolute/private/new-approval-token.secret
```

The command saves the token in a new private file and never prints it. Supply it through a protected operator input channel, keeping it out of chat/logs/Git. Only the token SHA-256 is stored; it cannot approve another plan or be reused.

## Usage examples

```text
請使用 lab_dns_get_forwarders 檢查惡意流量 DNS 目前的 forward 設定，只讀取不要修改。
```

```text
請使用 lab_dns_export_logs 匯出 2026-10-01 14:00–15:00 Asia/Taipei 的實驗 DNS Log，只回報筆數、頁數、batch ID 和 manifest SHA-256。
```

```text
請建立 forward 預覽計畫：將 sample.lab.test 指向 172.16.30.210:53。先不要套用。
```

```text
請建立高熵 DNS 流量預覽計畫：後綴 entropy.lab.test、A query 300 筆、每秒 10 筆、seed 20261001。先不要執行。
```

## Confirmed API mappings

```text
GET    /webApi/recursor/forward
POST   /webApi/recursor/forward
PATCH  /webApi/recursor/forward
DELETE /webApi/recursor/forward
GET    /webApi/recursor/forward/default
POST   /webApi/recursor/forward/default
PATCH  /webApi/recursor/forward/default
GET    /webApi/historylog/proxy/{page}
```

Default-forward writes and delete-all were intentionally not exposed.

## Files

```text
/home/jackie_tsai/Herta-Chat/agent/tools.py
/home/jackie_tsai/Herta-Chat/agent/dns_lab_tools.py
/home/jackie_tsai/Herta-Chat/agent/dns_lab_config.json
/home/jackie_tsai/Herta-Chat/agent/approve_dns_lab_plan.py
/home/jackie_tsai/Herta-Chat/agent/test_dns_lab_tools.py
```

Secret, mode `0600`:

```text
/home/jackie_tsai/.config/herta-chat/lab-dns.secret
```

Protected workspace:

```text
/home/jackie_tsai/Herta-Chat/agent_workspace/dns_lab/
  audit.jsonl
  exports/
  plans/
```

Prior registry backup:

```text
/home/jackie_tsai/Herta-Chat/agent/backups/dns-lab-tools-20261001/tools.py.before
```

## Verification

- five policy tests passed;
- Agent registry loaded all six tools;
- pinned HTTPS login succeeded;
- read-only forward query found seven entries;
- one-minute export returned 50 records and one page;
- forward and five-query traffic preview plans were created but never approved;
- no forward configuration changed;
- no synthetic/malicious traffic was sent;
- Agent health check passed after restart;
- both VLLM services remained running.

## SHA-256

```text
5cceeaef6e10b76da3a537cc1144d8f0c4ea703658f4916f6dbe61368185e73c  agent/tools.py
86dcae168a0d57228c47eaffd0f477a2efdd0cb0b7ff1d00bc528c562fc51199  agent/dns_lab_tools.py
05e3990aac033810ea8c2b3397fca4b229f011306bad1f3557b54d616c195d99  agent/dns_lab_config.json
ec368a5bfc5ab1ec3fd93e24c51dd50ba4e098095333596afa165687965c0648  agent/approve_dns_lab_plan.py
ae5a11795af9625345ceb0bca8c06516007a86f21138b74d2c0ee6d22f289df3  agent/test_dns_lab_tools.py
a24739e287ca3ef34f4665181b8ff3c45148d6af88ccc0281f1001f20ca663bd  tools.py.before
```

## Current limitation

Only reserved testing suffixes are allowed. Before using a real controlled laboratory domain, add its exact suffix to `allowed_forward_suffixes`, review the change, rerun tests, and restart only the Agent Runtime. Do not broaden it to arbitrary domains.
