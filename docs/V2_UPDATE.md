# VLLM Agent DNS Lab Tools V2 Update

**Date:** 2026-10-01 (Asia/Taipei)  
**Status:** Deployed and active

## Removed hard limitations

### Fixed DNS address

The tools are no longer hard-coded to operate only on `172.16.30.209`.

Every DNS operation now accepts a named `dns_profile`. Current configuration:

```text
lab-malicious → https://172.16.30.209:1606
```

Future DNS appliances require only a new entry under `profiles` in:

```text
/home/jackie_tsai/Herta-Chat/agent/dns_lab_config.json
```

No Python tool rewrite is required. Each profile independently defines:

- base URL;
- pinned certificate SHA-256;
- account and secret-file reference;
- whether forward writes are allowed;
- synthetic-traffic DNS address and port.

Unknown profile names are rejected. This preserves endpoint control without tying the implementation to one appliance.

### Two-hour and 100-page Log limit

The tool schema no longer contains `max_pages`, and the two-hour restriction has been removed. Pagination continues until the API returns fewer than 2,500 records.

Remaining resource-integrity guards:

- stop if the API repeats an identical page during pagination;
- maximum 50 GiB output per export;
- preserve at least 10 GiB free disk space;
- query end time must remain at least two minutes in the past;
- actual available history remains subject to Sentry retention, currently documented by the UI as seven days.

These are storage and consistency protections, not time/page limits.

## Server-side Log filters

`lab_dns_export_logs` now supports:

```text
domains
exclude_domains
qtypes
actions
source_ips
categories
result_terms
```

The Sentry filter API requires each rule to be encoded as an array. A scalar string produces an empty result even when matching records exist.

Internal domain filter form:

```json
{
  "qname": {
    "field": "domain",
    "reverse": 0,
    "rule": ["taipeinetworks.com"]
  }
}
```

Action values are translated to the appliance numeric action codes before submission.

## Filter verification

Test query:

```text
DNS profile: lab-malicious
Window: 2026-10-01 14:00–15:00 Asia/Taipei
Domain: taipeinetworks.com
```

Result:

```text
Rows: 1,702
Pages: 1
Raw bytes: 2,720,099
Matching rows: 1,702
Match rate: 100%
Manifest SHA-256: 53b312905cccc838a65320282af75a1f779237d95532695263cbfccd5b37ff18
```

An additional approximately 6.3-day API check returned a full first page of 2,500 records, all matching `taipeinetworks.com`.

No raw domain-query rows were printed in the operational report.

## Example Agent requests

Long-window domain export:

```text
請用 lab_dns_export_logs，dns_profile 設為 lab-malicious，匯出最近六天與 taipeinetworks.com 有關的 Log。完成後只回報 batch ID、筆數、頁數及 manifest SHA-256。
```

Multiple filters:

```text
請匯出 lab-malicious 在指定時段內，domain 為 tunnel.lab.test、QTYPE 為 TXT 或 CNAME、action 為 Allow 的 Log。
```

Exclude domains:

```text
請匯出指定時段 Log，但排除 taipeinetworks.com；只回報統計及輸出 manifest。
```

## Deployed SHA-256

```text
87a65b9f8e8a76df1ac21451b0ee1cf110f082c8701eca5dffc8c3990f56d318  agent/dns_lab_tools.py
c6d6df4e81f6177ad7f9363b916663b0f0f5e6ed9cb299e18d270262bb8444df  agent/dns_lab_config.json
7bd37414d2b1a8c65d9a8a5ed7e6baec20b117f69d83f30a7a22633f20db1be6  agent/test_dns_lab_tools.py
```

Six policy tests passed. Agent Runtime health check passed after reload, and both VLLM services remained running.
