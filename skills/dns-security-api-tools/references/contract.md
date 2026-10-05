# API contract and device profile

Import `Tools` and `DNS_TOOL_DEFINITIONS` from `dns_security_api`. Construct `Tools(profiles, state_dir)` using a protected local directory. Call `execute(name, arguments)`; no shell tool is exposed. Every tool requires `profile` and exact `target`. The definitions list required fields and defaults. Timeout is profile `timeout`, default 30 seconds per request. Optional overall query timeout is `limits.max_seconds` (checked between requests). Results are `{ok:true,tool_version,result}` or `{ok:false,error:{code,retryable,next_action}}`.

| Tool | Additional parameters | Result |
|---|---|---|
| dns_authenticate | none | authenticated, mode |
| dns_logout | none | logged_out |
| dns_health_check | none | reachable, target, at |
| dns_discover_capabilities | none | sanitized evidence, SHA-256, verified=false |
| dns_query_logs | filters required; limits, checkpoint optional | rows, applied filters, pages, completeness, checkpoint |
| dns_export_logs | filters, directory required; formats default JSON/JSONL/CSV; limits, checkpoint optional | directory, manifest, hashes |
| dns_get_forward_config | none | config, target |
| dns_plan_forward_change | desired required | before snapshot, diff, plan ID and hash |
| dns_apply_forward_change | plan_id required; dry_run=true; approved_sha256 required for writes | preview or verified after hash |
| dns_rollback_forward_change | same as apply | preview or verified rollback hash |

Authentication modes: `none` for genuinely public endpoints, `bearer`, `form`, `json`. `auth.env` maps credential names to environment variable names. Alternatively `auth.secret_file` points to a mode-0600 JSON object. `auth.fields` maps request fields to credential names. `login` is the explicit POST endpoint; `verify` is the required authenticated GET. Form CSRF uses `csrf_page`, `csrf_pattern` (one capturing group) and `csrf_field`; cookie CSRF uses `csrf_cookie` and `csrf_header`. `token_field` extracts a JSON access token. `logout` is optional. Login redirects are deliberately rejected; appliances needing redirect-based login require an adapter before use. Authentication expiry retries GET once; mutations are never replayed.

`capability.logs` requires endpoint, filters and pagination. Each filter maps to `{parameter,verified:true,semantics:"exact",mode:"server"}`. Time strings are sent unchanged; devices requiring epoch times or nested filter JSON need an adapter. Pagination defines kind (`page`, `offset`, `cursor`, `next_token`), parameter, size_parameter, first, max_page_size, rows_field, total_field, next_field, snapshot_field, snapshot_parameter and verified_snapshot. Defaults: page, page_size, first=1, max_page_size=2500, rows, total, next, snapshot. Offset profiles must explicitly set first=0. A cursor endpoint must explicitly set first=null. The snapshot contract must guarantee stable ordering and no gaps. Plain arrays never prove completeness. Result cursors must be non-secret pagination markers, not access/session tokens.

Limits: page_size, max_pages, max_records, max_seconds, max_bytes (all positive). Caller limits stop with incomplete status; duplicate/drift/total mismatch return errors without a complete export. Query presently accumulates rows in memory; max_bytes is recommended. Checkpoint includes accumulated rows and checksums, binds target/profile capability/filter/page size, and requires a snapshot to resume. The checksum detects accidental corruption, not malicious rewriting; protect the state directory.

Forward profile requires read_endpoint, write_endpoint, write_verified=true, method (default PUT), allowed_fields. The current adapter replaces the full list; UUID add/delete vendor APIs need a separate adapter. Do not declare write_verified until a reversible vendor-specific test establishes replacement semantics. Only lab role, exact lab URL and allow_forward_writes=true permit writes. Failure records point to rollback; uncertain or unverified after-state requires operator recovery. No automatic rollback is attempted.

Discovery currently preserves sanitized JSON evidence; it does not infer endpoint capabilities or verify filters automatically. Unknown devices remain unconfigured. Version, timezone, export format and schema fields should come from vendor evidence; absent values are unknown. Client-side filters, arbitrary custom filters, disk-streaming export, certificate pinning and device-specific login redirects are not implemented in this version. Use trusted CA verification for HTTPS.

Do not submit secrets, session data or raw exports to Git. New examples intentionally leave authentication and device endpoints unconfigured. Legacy lab_dns tools remain for compatibility and have a separate contract; the new skill does not invoke legacy traffic tools.
