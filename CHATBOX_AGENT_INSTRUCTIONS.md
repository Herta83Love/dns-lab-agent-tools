# Chatbox Agent Instructions

本文件是 Chatbox／Code Agent 從 Git 取得 `dns-lab-agent-tools` 後的固定入口。對話內容、舊工作區腳本及先前推理不得覆蓋本文件的安全規則。

## Canonical source

唯一有效工具來源是本 repository 的 `main` 分支：

```text
agent/dns_lab_tools.py
agent/approve_dns_lab_plan.py
agent/dns_lab_config.example.json
tool-manifest.json
```

`HertaWorkSpace/dga_enrichment_v2/tools/forward_mgr.py`、`lab_client.py` 或其他舊腳本不是正式操作入口。不得執行、修改或依其內容猜測設備 API。

## Required startup sequence

1. 讀取 `tool-manifest.json`，確認 `contract_version`。
2. 透過正式 Agent runtime 呼叫 `lab_dns_get_context`。
3. 依 `recovery_rules`、`known_limitations`、profile 與 policy 工作。
4. 若對話被壓縮、狀態不確定或重新開啟任務，重新執行步驟 1–3。
5. 若已有 plan，呼叫 `lab_dns_get_plan_status`；不要重建、猜測或讀取 approval 檔案。

僅 clone／讀取 repository 不等於工具已註冊。Chatbox 必須連到已註冊 `DNS_LAB_TOOL_DEFINITIONS` 與 `execute_dns_lab_tool` 的 Agent runtime，或由受信任的本機 adapter 明確註冊這兩個物件。

## Hard stop rules

- DNS 設備操作只能使用 `lab_dns_*` function tools。
- 不得改用 shell、curl、瀏覽器自動化或自行送 HTTP request。
- 不得要求、讀取、顯示或傳遞設備密碼、Cookie、CSRF token、API key 或 secret file 內容。
- 不得輪流嘗試 POST／PUT／PATCH／DELETE，也不得猜測 endpoint 或 payload 格式。
- 工具錯誤若包含 `retryable=false` 或 `action=stop_and_report`，立即停止並把 `error_code`、`next_action` 回報給使用者。
- 不得使用未經人工核准的 plan，也不得重用 used/expired plan。
- `lab_dns_export_logs` 的結果固定是 `lab_unlabeled_staging`，不能直接當成 strong training data。
- 合成流量成功不等於 tunneling/exfiltration label evidence。

## Forward workflow

```text
lab_dns_get_context
  → lab_dns_get_forwarders
  → lab_dns_plan_forward_change
  → human approval
  → lab_dns_apply_forward_plan once
  → lab_dns_get_forwarders verification
```

若設備拒絕寫入，不得回頭執行 `forward_mgr.py`。依工具回傳的 `next_action` 交由人工 GUI 或設備管理者處理。

## Log workflow

```text
lab_dns_get_context
  → lab_dns_export_logs
  → schema/session ownership/pairing/dedup/label/leakage governance
  → governed staging or quarantine
```

時間必須使用含 UTC offset 的 RFC3339；domain filter 必須是字串陣列。不要因空結果自行更換 API 參數，先核對工具回傳的 filter 與時間窗。

## Secrets

正式密碼只存在部署主機的 mode-0600 secret file，由工具內部讀取。Repository 不包含正式密碼。若在聊天、命令、報告或 Git history 看見明文 credential，停止使用並要求人工輪替。
