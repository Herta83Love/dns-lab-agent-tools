# Top Reports / 設備負載報表

Contract 3.2 adds two read-only tools to the default MCP binding (six tools):

- `lab_dns_get_top_report_capabilities`: local catalog, supported section/report pairs, dependency readiness.
- `lab_dns_get_top_report`: one authenticated query including private WebSocket delivery. Default `section=system` returns CPU utilization, load average, memory, LPS, QPM/RRM, hosts and disk.

Agent 呼叫順序：先取得 context 與 capabilities，再呼叫報表工具。例如：

```json
{"dns_profile":"lab-malicious","section":"system","window_minutes":10,"timeout_seconds":45}
```

These arguments belong to `lab_dns_get_top_report`. Default window is 120 minutes, not a maximum or retention promise. Explicit `start_time` and `end_time` must both have RFC3339 offsets; end is exclusive. Do not combine explicit times with `window_minutes`, request future windows, or guess report/chart pairs. Query epochs are UTC; device naive samples use Asia/Taipei and become explicit UTC timestamps.

報表是歷史彙總，並非即時讀數。每項 `status` 為 ready、stale、no_data 或 pending。`delivery_complete` 必須確認；HTTP 200/202 與工作識別並不代表已收到資料。逾時可能保留已完成項目，其餘 pending；停止並回報結構化錯誤，不改用 shell、curl、瀏覽器或猜測端點。Session 過期最多重新登入一次，所有流程共用同一逾時預算。

`latest_time` and `age_seconds` identify freshness; default stale threshold is 600 seconds. Missing/null samples remain gaps, real zero remains zero. Statistics use all received samples. `include_points=true` returns at most `max_points` (default 300) per series, explicitly indicating truncation. Device LPS/QPM/RRM labels are retained without inferred unit conversions. Ranking summaries return at most ten entries, with no detail pagination or completeness guarantee; placeholder Null rows are removed. Domains/IPs are masked unless `include_identifiers=true`; query-type and response-code labels remain visible.

TLS must use HTTPS and the existing protected profile certificate pin. HTTP on the verified lab redirects/requires HTTPS. Certificate verification is scoped per connection: validate the exact SHA256 pin before sending cookies over the WebSocket. No global certificate bypass. Credentials, CSRF, session cookies, socket/job identifiers and subscription signatures stay internal and never enter logs, capability profiles or error messages. `/broadcasting/auth` POST authenticates a subscription only; scheduled report exports and device configuration writes are not exposed.

Install `requirements-mcp.lock.txt` in the execution host's isolated environment. Copy **both** `agent/dns_lab_tools.py` and adjacent `agent/top_reports.py` when using the standalone canonical module; MCP additionally needs `agent/mcp_server.py`. The websocket-client dependency is mandatory for queries; capabilities reports readiness without contacting the device. Existing agent configuration must point to the new runtime explicitly; installing a Skill alone does not register these tools.

Validated gateway runtime:
`/home/jackie_tsai/.local/share/dns-lab-agent-tools/mcp-binding-20261007-v1`

Capability catalog comes from the device frontend. Live validation covers all seven system panels and the default selections in proxy/firewall/authority; other catalog combinations are frontend-discovered, not individually live-certified. UI offers seven-day windows; actual retention remains unverified. See [masked validation](TOP_REPORT_VALIDATION_20261007.json).
