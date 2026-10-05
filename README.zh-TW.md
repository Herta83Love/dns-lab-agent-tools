# DNS Security API Tools

新版 API 介面位於 `src/dns_security_api`，既有 `agent/` 工具保留相容性。新版不包含排程、Dataset 治理、模型工作或流量產生。

安裝：`python -m pip install .`。載入 `Tools` 與 `DNS_TOOL_DEFINITIONS`，以 profile 與精確 target 呼叫各工具。設備設定範本在 `examples/profiles.json`；它尚未配置認證或設備專屬 endpoint，不能直接當成完成的設備設定。

正常 DNS `https://192.168.10.150:1606` 唯讀；實驗 DNS `http://172.16.30.209:1606` 的 forward 修改必須先預覽、明確核准計畫 SHA-256，再以 `dry_run:false` 套用並驗證。新版硬性阻擋正常 DNS 及未知主機的 forward 寫入。

認證支援 HTTP、HTTPS、環境變數、0600 JSON／既有純密碼秘密檔、cookie/token、CSRF、GET 到期重登入及登出。自簽憑證須提供可信 CA 檔，或沿用可信來源的單一 client 憑證指紋綁定；不得全域停用 TLS 驗證。Session 不寫入 state。

查詢要求含時區的起訖時間，未驗證的 filter 會拒絕。分頁支援 page、offset、cursor、next token；必須有經驗證的穩定 snapshot 與一致總數，才能宣告完整。提供可設定的筆數、頁數、時間、容量限制與續傳 checkpoint。JSON/JSONL/CSV 匯出建立新目錄及 SHA-256 manifest，避免覆寫原始資料。

完整設定、錯誤與限制請讀 [工具合約](skills/dns-security-api-tools/references/contract.md)，Agent 操作請讀 [Skill](skills/dns-security-api-tools/SKILL.md)。已在指定驗證主機完成正常 DNS 登入、時間窗、多頁查詢，以及明確標示為 client-side 的精確 domain／qname、qtype、rcode 比對。指定網域搜尋無命中，不能據此證明 server-side 精確語意。舊 rtype filter 不能可靠代替 qtype。完整 snapshot／總數保證仍未知，complete 保持 false。實驗室 HTTP 回傳 HTTPS port 錯誤，切換 HTTPS 待明確授權。

測試：`python -m unittest discover -v`。
