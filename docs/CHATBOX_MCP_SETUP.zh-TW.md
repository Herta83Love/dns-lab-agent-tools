# Chatbox／VLLM 工具接入修正

報告中的 unavailable tool 發生於 Chatbox invocation 層，未觸及 VLLM 推論或 DNS 設備。Skill 是操作文件，不等於 tools/list 註冊。Chatbox 官方支援 MCP：https://docs.chatboxai.app/guides/mcp 。請在設定中新增 stdio MCP server，再確認會話可見工具；部分版本會為工具名稱加 server 前綴，以實際清單為準。

新增 `agent.mcp_server` 把 canonical definitions 綁到 MCP tools/list 及 tools/call。預設只有 context、plan status、forward read、log export 四個唯讀工具。啟動時明確使用 --allow-forward-changes 才會增加兩個 forward 工具，既有人工核准仍必要。此 adapter 不曝露合成流量工具，不新增設備 endpoint，不處理排程或修改 VLLM。

## Linux 執行主機

在獨立 checkout 與 virtualenv 安裝 `requirements-mcp.txt`。不覆寫既有 `/home/jackie_tsai/Herta-Chat/agent`，不移動秘密。啟動：

```text
/path/to/venv/bin/python -m agent.mcp_server --config /home/jackie_tsai/Herta-Chat/agent/dns_lab_config.json
```

執行目錄或 PYTHONPATH 必須指向 repository root。stdout 專供 MCP；adapter 禁止輸出例外內容或 MCP arguments。stdio 程序隨 client 連線啟動及結束，不需要 HTTP port、systemd 或 VLLM 重啟。

## Windows Chatbox

在 MCP 設定選 stdio，命令填 `C:\Windows\System32\OpenSSH\ssh.exe`。參數依序為：

```text
-T
-o
BatchMode=yes
jackie_tsai@192.168.10.32
cd /home/jackie_tsai/.local/share/dns-lab-agent-tools/mcp-binding-20261005-v1 && /home/jackie_tsai/.local/share/dns-lab-agent-tools/mcp-binding-20261005-v1/.venv/bin/python -m agent.mcp_server --config /home/jackie_tsai/Herta-Chat/agent/dns_lab_config.json
```

先由操作者確認 Windows OpenSSH 與 SSH key 登入可用、主機指紋已核對。不要將密碼放入參數，不要停用 StrictHostKeyChecking。此設定只啟動遠端 stdio server；Windows 不需要本機 Python、DNS config 或設備秘密。目前已在指定主機建立上述獨立環境並通過 SSH MCP 測試。可直接採用 `examples/chatbox-mcp-windows.json` 的 name／command／args／env 設定。Windows 端仍須具有可用的 SSH 登入金鑰；本次沒有存取或修改 Windows Chatbox 設定。

## 最小驗收

1. MCP initialize 成功，tools/list 出現四個唯讀工具。
2. 呼叫實際註冊名稱對應的 lab_dns_get_context，參數 `{}`。
3. 沒有工具就回報 TOOLS_NOT_REGISTERED；修正 MCP 設定，不改用 shell／curl 操作設備。
4. log export 的有效參數是 dns_profile、start_time、end_time，以及 schema 列出的選填 filters。報告中的 device、time_window、include_payload 必須移除。無效參數現在會在設備連線前被拒絕。
5. 設備 reachability 另行以正式唯讀工具驗證；adapter transport 測試不代表設備已連通。實驗室 HTTPS 驗證仍待使用者明確授權；不要因報告提及 HTTPS 自動改變前次指定的 HTTP 目標。

舊 lab_dns_export_logs 的 filter 與完整性行為屬 legacy 合約。正常 DNS 的驗證已證實 rtype 不能可靠代替 qtype；需要精確篩選或完整性證據時使用新版 API 合約，不能把 legacy 匯出當成已完成新版驗收。
