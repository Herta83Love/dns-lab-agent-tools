---
name: dns-lab-agent-tools
description: Operate authorized DNS security lab appliances through guarded lab_dns tools for device load and Top Reports, forward inspection and approved changes, Proxy log export, and reviewed manifest DNS traffic. Use for DNS lab configuration, log collection, reviewed manifest traffic, or recovery of interrupted DNS lab plans; do not use for arbitrary DNS infrastructure or unlabeled data promotion.
metadata:
  short-description: Guarded DNS security lab operations
---

# DNS Lab Agent Tools

Use the registered `lab_dns_*` function tools for authorized DNS security-lab work. This skill supplies workflow and safety guidance; cloning the repository alone does not create device credentials or bypass runtime tool registration.

## When the tools are not registered

Check the function list before doing anything else. If `lab_dns_get_context` is not a callable tool, stop and report `error_code=TOOLS_NOT_REGISTERED`.

Do not read `agent/dns_lab_tools.py`, search for `dns_lab_config.json`, secret files, or certificate pins, install Python, write a platform shim, or contact the appliance. Ask the human to register `DNS_LAB_TOOL_DEFINITIONS` and `execute_dns_lab_tool` on the agent runtime. `tool-manifest.json` records source hashes for review; the runtime does not refuse to import the module because a hash changed.

If a registered tool returns `CONFIG_MISSING`, `CONFIG_INVALID`, `SECRET_UNAVAILABLE`, `retryable=false`, or `action=stop_and_report`, report `error_code` and `next_action`, then stop.

## Start or recover

Call `lab_dns_get_context` first for every new DNS lab task and whenever conversation state was compacted or lost. Follow its current profiles, limits, known limitations, recovery rules, and recent plan states instead of relying on remembered values.

If a plan may already exist, call `lab_dns_get_plan_status`. Do not recreate a live plan, guess a plan ID, or read approval files.

## Choose the workflow

- Inspect current forwarding: call `lab_dns_get_forwarders`.
- Export Proxy DNS logs: call `lab_dns_export_logs` with timezone-aware RFC3339 timestamps and array-valued filters.
- Change forwarding: `lab_dns_get_forwarders` → `lab_dns_plan_forward_change` → human approval → one `lab_dns_apply_forward_plan` call → verify with `lab_dns_get_forwarders`.
- Generate bounded synthetic DNS traffic: `lab_dns_plan_synthetic_traffic` → human approval → one `lab_dns_run_synthetic_traffic_plan` call → export the exact capture window.

For detailed recovery and error behavior, read [docs/V3_AGENT_RECOVERY.md](docs/V3_AGENT_RECOVERY.md). For deployment or runtime registration, read [docs/MANIFEST_TRAFFIC.md](docs/MANIFEST_TRAFFIC.md); v1 deployment documents are archived. For filter behavior, read [docs/V2_UPDATE.md](docs/V2_UPDATE.md) only when exporting logs.

## Hard boundaries

- Use only registered `lab_dns_*` tools for appliance operations. Do not fall back to shell, curl, browser automation, direct HTTP, or legacy `forward_mgr.py`/`lab_client.py` scripts.
- Never request, read, print, transmit, or document device passwords, cookies, CSRF tokens, API keys, or secret-file contents.
- Treat `retryable=false` or `action=stop_and_report` as a hard stop. Report `error_code` and `next_action`; do not vary endpoint, HTTP method, or payload shape.
- Do not reuse expired or consumed plans. Do not apply a plan without the human-provided one-time approval token.
- Treat every `lab_dns_export_logs` result as `lab_unlabeled_staging`. Export success does not prove labels, pairing, deduplication, ownership, contamination, or leakage safety.
- Synthetic traffic completion is not tunneling or exfiltration label evidence. Preserve the separate Dataset governance and training-only restrictions.

## Repository integrity

Read [tool-manifest.json](tool-manifest.json) when verifying the contract version and source SHA-256. The canonical implementation is `agent/dns_lab_tools.py`; `agent/dns_lab_config.example.json` contains placeholders only and must never replace the protected deployment configuration.

## Explicit MCP binding

Chatbox does not register Python functions merely by loading this Skill. Operators can configure the stdio MCP adapter using [setup instructions](docs/CHATBOX_MCP_SETUP.zh-TW.md) and [Windows settings](examples/chatbox-mcp-windows.json). Use the actual runtime tools/list names and schemas; names may have a server prefix. If no corresponding context tool exists, stop with TOOLS_NOT_REGISTERED. The adapter exposes six read-only tools by default; legacy seed-generated synthetic traffic is not exposed; reviewed manifest traffic requires explicit opt-in. Do not install or configure a transport through model-initiated shell fallback.


Top Reports (contract 3.2): use `lab_dns_get_top_report_capabilities`, then `lab_dns_get_top_report` for hardware load or DNS rankings. Respect ready/stale/no_data/pending and delivery_complete; never infer zero from missing data. [Usage / 使用說明](docs/TOP_REPORTS.md).


Contract 3.3 / package 4.1.0: reviewed JSONL manifest traffic is available through explicit MCP `--allow-manifest-traffic` (ten tools). Use plan → exact SHA-bound human approval → run → traffic status → exact Log reconciliation. Default dry-run; no replay after interruption; fixed 172.16.30.222:53 target, ≤0.5 QPS, ≤500 selected queries, ≥300-second cooldown, fresh CPU/memory/Log preflight. Source artifacts stay read-only, class mapping is fixed, training_ready remains false. [Deployment, lineage and recovery / 部署與操作](docs/MANIFEST_TRAFFIC.md).
