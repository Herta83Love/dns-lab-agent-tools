# Reviewed manifest traffic / 已審核清單流量

Package 4.1.0, tool contract 3.3, MCP 1.2.0. Default binding stays six read-only tools. `--allow-manifest-traffic` adds four guarded tools (ten total): plan, run, status, and exact Log reconciliation. The legacy seed-generated traffic functions remain absent from MCP. `--allow-forward-changes` is independent and still requires approval.

## Deployment and recovery

The supported entry point is `/home/jackie_tsai/.local/share/dns-lab-agent-tools/current`, an atomically selected isolated release. Repository/vendor checkouts are reference/development copies, not production runtimes. `scripts/deploy_runtime.py` validates source hashes, installs its own dependency environment, copies the protected production config beside the modules as `agent/dns_lab_config.json` (0600), and accepts MCP context/tools-list before switching `current`. It marks the previous October 7 runtime deprecated. Context reports actual runtime path, commit, config presence/path, non-secret policy fingerprint and registered MCP names. Credential contents and accounts are excluded from the fingerprint.

管理／Log API 固定為 `https://172.16.30.209:1606`，保留既有憑證 pin 與 secret-file provider。Manifest 流量目的地固定為 `172.16.30.222:53`，不由 Agent 指定。部署設定檔只引用既有 secret file，不能拿 example 設定檔代替正式設定，也不能只更新 Python 模組。

Run the deployment script **on the gateway** with a prepared clean bundle and explicit protected `--config-source`. Installation acceptance sends no DNS traffic and performs no device configuration writes. Use [Chatbox configuration](../examples/chatbox-mcp-manifest-windows.json), then reconnect MCP. Six tools means traffic opt-in is missing; ten tools means the manifest binding is present. Use context after conversation compaction; do not search vendor copies or substitute shell commands.

## Import and exact lineage

The reviewed materialized source is read-only. Operator import uses `scripts/import_reviewed_manifest.py --source ... --batch-sha256 ... --catalog-sha256 ... --sums-sha256 ... --config ...`. It copies only validated JSON/JSONL and checksum files into `workspace_root/manifests/reviewed-<batch-hash-prefix>/`, with directories 0700 and files 0600. It validates all sessions before atomic publication; it never modifies the source batch, catalog, session manifest or queries. Agent tools only accept manifests resolved inside this private workspace, rejecting symlinks, traversal, arbitrary files, stdin, environment/command payloads and unchecked hashes.

支援本次已審核格式：batch 的 `lineage.catalog` 與 `lineage.sessions[]`、catalog 的 `params.session_label`／`split_group_id`、session manifest、`planned-queries.jsonl`。核對 batch bytes SHA256、catalog bytes SHA256、session manifest bytes SHA256、完整 query-list **原始 JSONL bytes** SHA256。不能把 JSONL 改成 canonical JSON 後重新計算既有 query-list 雜湊。治理要求為 controlled_candidate、training_ready=false、training_only_candidate；每次只選一個 session。

Fixed mapping `eidolon-controlled-class-map-v1`:

| class_code | tunneling | exfiltration |
|---|---:|---:|
| control_only | 1 | 0 |
| one_way_chunks | 0 | 1 |
| mixed_control_chunks | 1 | 1 |

Labels come only from this reviewed class mapping. Qname, entropy, device scores and frame_role never infer labels. Plans contain exact original qname/qtype, index and intended relative timing. DNS payload labels can contain the reviewed ASCII underscores and edge hyphens; they are not constrained to hostname labels ([RFC 2181 §11](https://www.rfc-editor.org/rfc/rfc2181#section-11)). This client limits accepted characters and byte lengths and never interprets names as commands.

## Agent workflow

1. `lab_dns_get_context`; verify runtime/commit/config/binding.
2. `lab_dns_plan_manifest_traffic` with `batch_manifest_path`, `batch_manifest_sha256`, `session_id`, `planned_queries_sha256`. Default dry_run=true, qps=0.5, queries_per_session=500, cooldown_seconds=300, stop_on_any_loss=true.
3. Inspect protected immutable plan and its `plan_sha256`. Dry-run plans cannot send. For a reviewed execution, create a distinct plan with dry_run=false.
4. Human approval: `python -m agent.approve_dns_lab_plan <plan_id> --plan-sha256 <exact-sha> --token-file <new-private-absolute-path>`. CLI never prints token. Keep the private file and token outside chat, logs and Git; provide it only through the approved caller's secret input channel to the run tool.
5. `lab_dns_run_manifest_traffic_plan` accepts plan_id and one-time approval_token only. It consumes the session claim before starting a detached worker and returns queued promptly. Poll `lab_dns_get_traffic_plan_status`; do not call run again after timeout or restart.
6. Wait at least 300 seconds after send completion, then `lab_dns_reconcile_manifest_logs` with plan_id and an offset-aware start/end covering every attempted query plus response time. End must be at least two minutes old. Raw unfiltered time-bounded pages remain private; exact client intersection produces separate matched, missing, duplicate, ambiguous and pairing artifacts.

`queries_per_session` explicitly selects the **first N reviewed records** (N ≤ 500). It never generates replacement names or edits the reviewed list. Plan `selection` records original session count and separately hashes the selected prefix; original full JSONL SHA stays bound. Three-class warm-up previews select 30 records each and are dry-run. Prefix results cannot be described as completion of the original 500-record session.

## Load, rate, cooldown and restart

Before sends, the worker obtains fresh Top Reports capabilities/report and authenticates a minimal Log API read. Delivery must complete; CPU and memory must both be ready, ≤85% and ≤90%, with age ≤600 seconds. Missing, stale, incomplete, malformed or unknown values reject execution. Reports are historical statistics, not instantaneous measurements. Before/after evidence is hashed and retained, including gate failure evidence. There is no fabricated 0% load.

Only UDP A/AAAA/TXT/CNAME; no ANY, retries, alternate resolver or TCP fallback. Actual sends are spaced at least 1/qps seconds, respecting later reviewed intended offsets. Allowed rate is 0.2–0.5 QPS; max 500 selected queries. Every session claim is single-use and globally locked. Session cooldown is ≥300 seconds, and load is fetched again for the next session. Timeout/error/unknown receipt or unproven reconciliation blocks the next session. Recovery must reference the interrupted/partial plan and select a **new reviewed session** with new human approval; completed or uncertain queries are never auto-replayed.

Plan bytes never change after creation. Each attempted query has a persisted, fsynced intent before network I/O and a separate immutable receipt afterward. Crash between them means uncertain outcome, not permission to retransmit. Receipt index contains exactly one entry per selected query, including not_attempted entries. Receipts include session/split group, label lineage and hashes, exact qname/qtype, intended and rate-limited planned send times, actual send time, transport/source/target, status/rcode/timeout/error/latency, tool/commit, input/output hashes, and shared before/after load evidence hashes. Per-query protected artifacts contain query content; tool responses and sanitized validation reports contain counts/paths/hashes only.

## Log completeness limits

Separate counters: planned, send_attempted, send_succeeded, dns_responses, exported_rows, unique_qname_matches, paired_transactions, duplicates/exact_duplicates, missing, ambiguous, accepted. Exact match lowercases and removes trailing dot, checks full qname/qtype and exact session-marker label. A suffix match alone is insufficient. Multiple rows for one planned query are ambiguous; they are not silently collapsed into a unique transaction.

Export records page/offset/cursor, per-page count and hash, reported total when available, acquired rows, duplicate candidate identity count, first/last timestamp, snapshot token availability, delivery_complete and completeness_verified. Partial pages survive request/storage/page limits. This firmware's observed arrays have no verified total/snapshot and transaction identity remains unverified. Terminal pagination therefore leaves `completeness_verified=false`. `complete` additionally requires all planned sends/responses and unique verified paired transactions, zero duplicates/missing/ambiguity and verified snapshot completeness. Otherwise controlled_partial, accepted=0 and training_ready=false. Even a complete tool result requires external governance before Dataset admission.

工具無法修復設備 Log ingestion 遺失或重複、GUI/API 索引差異或 snapshot 不穩定。降低速率、等待索引、保留部分資料及阻止下一批，是工具能提供的控制；不能以 API 成功掩蓋資料遺失。
