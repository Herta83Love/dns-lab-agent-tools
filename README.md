# DNS Lab Agent Tools

[English](#english) | [繁體中文](#繁體中文)

Chatbox integration: see [CHATBOX_AGENT_INSTRUCTIONS.md](CHATBOX_AGENT_INSTRUCTIONS.md). Machine-readable release information is in [tool-manifest.json](tool-manifest.json).

This repository is installable as a Chatbox/Codex Skill from its GitHub URL. Skill discovery uses the root [SKILL.md](SKILL.md), with UI metadata in [agents/openai.yaml](agents/openai.yaml).

## DNS Security API v4

The new profile-driven API package is in `src/dns_security_api`; legacy tools remain compatible. Install with `python -m pip install .`, then register `DNS_TOOL_DEFINITIONS` and call `Tools.execute`. See [the new Skill](skills/dns-security-api-tools/SKILL.md), [parameter and profile contract](skills/dns-security-api-tools/references/contract.md), and [Traditional Chinese README](README.zh-TW.md).

The new package provides authentication/logout, read-only discovery evidence, strict server-filter queries, page/offset/cursor pagination, checkpoint resume, JSON/JSONL/CSV manifests and approved forward previews/apply/rollback. Normal DNS is read-only; writes require the exact laboratory URL, enabled lab profile and explicit approval of the plan SHA-256. TLS verification is mandatory; self-signed devices require a trusted CA file or a per-client certificate pin from a trusted source. Secrets remain in environment variables or mode-0600 JSON/password-text files; sessions stay in memory.

Completeness requires a vendor-verified stable snapshot and matching total. Unknown filters fail instead of widening a query. Example profiles are deliberately unconfigured. The verified Sentry adapter supports same-origin login redirects, Unix-second time bounds, nested filter encoding and explicit exact client-side filters. Custom filter expressions and streaming export remain unsupported. Normal-device pinned login, multi-page queries and client-side filters have passed read-only checks on the authorized host. Server exact-domain/qtype/rcode guarantees and complete-export guarantees remain unverified. Lab HTTP requires HTTPS; protocol switching awaits authorization. No scheduling, datasets, models or traffic generators are added. Run `python -m unittest discover -v`.

## English

Guarded function tools for a VLLM/OpenAI-compatible Agent operating controlled DNS security laboratories.

The project supports reading forward configuration, exporting paired Proxy DNS logs, approved forward changes, and bounded synthetic high-entropy/DGA-like traffic. It includes certificate pinning, immutable plans, one-time approvals, audit logs, and before-state backups.

No credentials, raw DNS logs, review data, models, or runtime artifacts belong in this repository.

## Tools

```text
lab_dns_get_forwarders
lab_dns_get_context
lab_dns_get_plan_status
lab_dns_export_logs
lab_dns_plan_forward_change
lab_dns_apply_forward_plan
lab_dns_plan_synthetic_traffic
lab_dns_run_synthetic_traffic_plan
```

Start every new or compacted conversation with `lab_dns_get_context`. It returns the active profiles, policy limits, known appliance limitations, recovery rules, and recent plans without exposing credentials. If work was interrupted after creating a plan, use `lab_dns_get_plan_status`; do not recreate the plan or guess API calls.

All appliance errors carry a stable error code, retry guidance, and a next action. When an error says `retryable=false` or `action=stop_and_report`, the Agent must stop. It must never fall back to shell, curl, browser automation, alternate endpoints, HTTP methods, or guessed payload shapes.

## Installation

Copy the module into the Agent package:

```bash
cp agent/dns_lab_tools.py /path/to/agent/dns_lab_tools.py
cp agent/approve_dns_lab_plan.py /path/to/agent/approve_dns_lab_plan.py
cp agent/dns_lab_config.example.json /path/to/agent/dns_lab_config.json
```

Edit the configuration and create its referenced secret file with mode `0600`. On Windows, install CPython 3.10 or newer (the Microsoft Store `python` alias is not an interpreter) and give that secret an owner-only NTFS ACL; POSIX mode bits are not a reliable privacy check there. The module loads without `fcntl`. An optional absolute `workspace_root` in the protected config selects the plan/export directory. None of this registers the tools: the agent runtime still has to load `DNS_LAB_TOOL_DEFINITIONS` and `execute_dns_lab_tool`.

Register the tools in the existing registry:

```python
from agent.dns_lab_tools import DNS_LAB_TOOL_DEFINITIONS, execute_dns_lab_tool

TOOL_DEFINITIONS.extend(DNS_LAB_TOOL_DEFINITIONS)

def execute_tool(name: str, arguments: dict) -> dict:
    if name.startswith("lab_dns_"):
        return execute_dns_lab_tool(name, arguments)
    # Existing tools follow.
```

Restart only the Agent runtime after testing. VLLM itself does not need to restart.

## Adding another DNS

Add a named entry under `profiles`; no Python rewrite is required. Each profile defines its own URL, certificate fingerprint, secret reference, write permission, and traffic endpoint. Unknown profiles are rejected.

## Log filtering

`lab_dns_export_logs` supports `domains`, `exclude_domains`, `qtypes`, `actions`, `source_ips`, `categories`, and `result_terms`.

There is no fixed time-window or page-count limit. Pagination ends when fewer than 2,500 records are returned. Export-size, free-space, and repeated-page guards remain active.

## Human approval

Forward changes and synthetic traffic require preview plus a human-generated token:

```bash
python -m agent.approve_dns_lab_plan <plan_id>
```

The token is bound to one plan, stored only as SHA-256, expires with the plan, and cannot be reused.

## Tests

```bash
python -m unittest -v tests.test_dns_lab_tools
```

## Security boundary

- No arbitrary URL or shell tool.
- TLS certificates are pinned per DNS profile.
- Forward targets remain constrained to configured networks and ports.
- Default/root forward and delete-all are not exposed.
- Synthetic payloads are seeded generated content, never file or user data.
- Sensitive runtime output is excluded by `.gitignore`.

See [deployment documentation](docs/DEPLOYMENT_V1.md) and the [V2 profile/filter update](docs/V2_UPDATE.md).

---

## 繁體中文

這是一套提供給 VLLM／OpenAI 相容 Agent 使用的受控函式工具，專門用於經授權的 DNS 資安實驗環境。

Chatbox 從 Git 取得本專案時，請先讀取 [CHATBOX_AGENT_INSTRUCTIONS.md](CHATBOX_AGENT_INSTRUCTIONS.md)；機器可讀版本資訊位於 [tool-manifest.json](tool-manifest.json)。

本 repository 現在可直接透過 GitHub URL 安裝為 Chatbox／Codex Skill。Skill 掃描入口是根目錄的 [SKILL.md](SKILL.md)，介面資訊位於 [agents/openai.yaml](agents/openai.yaml)。

本專案支援讀取 DNS Forward 設定、匯出已配對的 Proxy DNS Log、經人工核准後調整 Forward，以及產生有範圍限制的高熵／類 DGA 合成流量。安全機制包括 TLS 憑證指紋綁定、不可變更的操作計畫、一次性人工核准、稽核紀錄，以及變更前狀態備份。

請勿把帳號密碼、原始 DNS Log、人工審核資料、模型或執行期產物提交到本專案。

### 可用工具

```text
lab_dns_get_forwarders
lab_dns_get_context
lab_dns_get_plan_status
lab_dns_export_logs
lab_dns_plan_forward_change
lab_dns_apply_forward_plan
lab_dns_plan_synthetic_traffic
lab_dns_run_synthetic_traffic_plan
```

每個新任務或對話壓縮後，都應先呼叫 `lab_dns_get_context`。它會在不暴露帳密的情況下重新提供可用 profile、安全限制、已知設備限制、恢復規則與最近計畫。若工作中斷於建立計畫之後，使用 `lab_dns_get_plan_status` 恢復狀態，不要重新建立計畫或猜測 API。

設備錯誤會包含固定的 error code、是否可重試及下一步。若錯誤標示 `retryable=false` 或 `action=stop_and_report`，Agent 必須停止；不得改用 shell、curl、瀏覽器自動化、其他 endpoint、HTTP method 或猜測 payload 格式。

### 安裝方式

將工具模組複製到現有 Agent 套件：

```bash
cp agent/dns_lab_tools.py /path/to/agent/dns_lab_tools.py
cp agent/approve_dns_lab_plan.py /path/to/agent/approve_dns_lab_plan.py
cp agent/dns_lab_config.example.json /path/to/agent/dns_lab_config.json
```

編輯設定檔，並建立設定檔所引用的機密檔案；機密檔案權限應設為 `0600`。在 Windows 上請安裝 CPython 3.10 以上（Microsoft Store 的 `python` 別名不是直譯器），並把機密檔設成擁有者專用的 NTFS ACL；那裡的 POSIX 權限位不可靠。模組不再在 import 時依賴 `fcntl`。受保護設定可加絕對路徑 `workspace_root` 來指定計畫與匯出目錄。這些都不會自動註冊工具，Agent runtime 仍須載入 `DNS_LAB_TOOL_DEFINITIONS` 與 `execute_dns_lab_tool`。

在既有的工具註冊表中加入：

```python
from agent.dns_lab_tools import DNS_LAB_TOOL_DEFINITIONS, execute_dns_lab_tool

TOOL_DEFINITIONS.extend(DNS_LAB_TOOL_DEFINITIONS)

def execute_tool(name: str, arguments: dict) -> dict:
    if name.startswith("lab_dns_"):
        return execute_dns_lab_tool(name, arguments)
    # 接續既有工具的處理邏輯。
```

測試通過後只需重新啟動 Agent 執行環境，不需要重新啟動 VLLM。

### 新增 DNS 主機

在 `profiles` 下增加一個具名設定即可，不需要修改 Python 程式。每個 profile 都能分別設定 URL、TLS 憑證指紋、機密資料引用、寫入權限及流量端點；未登錄的 profile 會被拒絕。

### Log 篩選與匯出

`lab_dns_export_logs` 支援以下篩選條件：

- `domains`：指定網域
- `exclude_domains`：排除網域
- `qtypes`：DNS Query Type
- `actions`：處置動作
- `source_ips`：來源 IP
- `categories`：分類
- `result_terms`：結果關鍵字

工具沒有固定的查詢時間範圍或頁數上限。當單頁回傳少於 2,500 筆時停止分頁；匯出容量、磁碟剩餘空間及重複頁面等保護機制仍會生效。

### 人工核准

修改 Forward 或產生合成流量時，必須先預覽操作計畫，再由人員產生核准 Token：

```bash
python -m agent.approve_dns_lab_plan <plan_id>
```

Token 只綁定單一操作計畫，系統僅保存其 SHA-256；Token 會隨計畫到期，且不能重複使用。

### 執行測試

```bash
python -m unittest -v tests.test_dns_lab_tools
```

### 安全邊界

- 不提供任意 URL 存取或任意 Shell 指令功能。
- 每個 DNS profile 都必須綁定 TLS 憑證指紋。
- Forward 目標限制在設定允許的網段與連接埠內。
- 不開放預設／根網域 Forward，也不提供全部刪除功能。
- 合成流量只能使用種子生成內容，不得使用檔案內容或使用者資料作為 payload。
- 敏感執行期輸出已由 `.gitignore` 排除。

更完整的設定方式請參閱[部署文件](docs/DEPLOYMENT_V1.md)與 [V2 Profile／篩選功能更新](docs/V2_UPDATE.md)。

## Chatbox MCP binding

A Skill installation does not register function tools. `agent.mcp_server` provides an explicit stdio MCP binding, defaulting to four read-only legacy tools with strict schema validation. Keep credentials on the Linux execution host and connect Windows Chatbox via SSH; no local Python or DNS secrets are required. Install `requirements-mcp.txt` in an isolated environment. See [setup and acceptance checks](docs/CHATBOX_MCP_SETUP.zh-TW.md). No VLLM restart or device write is involved.
