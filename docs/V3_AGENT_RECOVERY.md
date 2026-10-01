# DNS Lab Tools V3 — Agent Recovery Contract

## 目的

V3 將操作知識放進工具 schema 與回傳值，使 Agent 在對話壓縮或換工作階段後，不必依賴聊天記憶、搜尋檔案或重新逆向設備 API。

## 固定起點

任何 DNS lab 任務第一步都是：

```text
lab_dns_get_context
```

它會提供：

- tool contract 版本；
- 可用 DNS profiles 與寫入狀態；
- 允許的 suffix、私網、port、流量及儲存限制；
- 已知設備限制與 operator notes；
- 最近十個 plan 的狀態與下一步；
- 不依賴聊天記憶的 recovery rules。

它不會連線設備，也不會回傳帳號、密碼、Cookie、CSRF token 或憑證內容。

## 中斷恢復

若已知 plan ID：

```text
lab_dns_get_plan_status(plan_id=...)
```

若忘記 plan ID，省略參數即可列出最近計畫。狀態只有：

- `awaiting_human_approval`
- `approved`
- `expired`
- `used`

工具會直接回傳唯一的 `next_action`。Agent 不得自行重建未過期計畫，也不得要求或讀取 approval token 檔案。

## 寫入流程

```text
get_context
  → get_forwarders
  → plan_forward_change
  → human approval
  → apply_forward_plan once
  → get_forwarders verification
```

任何步驟都不得替換成 shell、curl、瀏覽器或自行組 HTTP request。

## 錯誤契約

受控失敗包含：

```json
{
  "error_code": "FORWARD_API_REJECTED",
  "message": "...",
  "retryable": false,
  "action": "stop_and_report",
  "next_action": "...",
  "details": {}
}
```

`retryable=false` 或 `action=stop_and_report` 是硬性停止條件。Agent 不得：

- 改用 POST／PUT／PATCH／DELETE 輪流嘗試；
- 猜測 array/string/null payload；
- 測試未列入工具的 API endpoint；
- 把設備密碼放進 shell、Python snippet、文件或回覆；
- 因工具受限而降低 Dataset/label 治理標準。

## Dataset 邊界

`lab_dns_export_logs` 的輸出永遠是 `lab_unlabeled_staging`。成功匯出只證明資料已保存，不證明標籤、session ownership、request/response pairing、去重、污染或 leakage 已通過。

`lab_dns_run_synthetic_traffic_plan` 成功也不構成 tunneling/exfiltration 標籤證據。Label evidence 與 Dataset lock 必須由專案治理管線另行完成。
