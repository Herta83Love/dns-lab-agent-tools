---
name: dns-security-api-tools
description: Authenticate, discover, query and export DNS appliance logs, and preview or apply explicitly approved laboratory forward changes through structured Python tools.
---

Use `dns_security_api.Tools` and `DNS_TOOL_DEFINITIONS`; install this repository with `python -m pip install .`. Read [the contract](references/contract.md) before configuring a device. Do not operate schedulers, datasets, model training, traffic generators or VLLM services.

Normal DNS is `https://192.168.10.150:1606`, read-only. Lab DNS is `http://172.16.30.209:1606`. Every call requires both a named profile and its exact target URL. Only this laboratory URL can receive forward writes in the new tools.

Credentials come from environment variables or a JSON secret file with exactly mode 0600. Sessions stay in memory. For self-signed HTTPS supply a trusted CA file or the existing trusted per-client certificate fingerprint. Never disable verification globally. Different appliances require different authentication and capability profiles. Do not guess endpoints. A failed discovery requires vendor documentation or operator-provided evidence.

Configure a declared read-only discovery endpoint, call `dns_discover_capabilities`, and retain its sanitized evidence. Evidence is not automatically a verified capability profile. Test server filter semantics before setting `verified: true`. All requested conditions must be supported; unsupported filters fail. Verified exact client-side fields are allowed only when returned explicitly as mode=client; paginate the raw rows before filtering. Exact domain semantics must be established on the appliance, including the requested domain search, qtype, rcode and time windows. The normal device rtype filter is not a dependable qtype mapping.

Query timestamps require explicit offsets. Pagination supports page, offset, cursor and next token. Only a verified snapshot contract with stable identifier and matching total can produce `complete: true`. Duplicate pages, records, drift and inconsistent totals stop the query. An incomplete export must never be described as complete. Limits are configurable; no fixed two-hour or 100-page cap exists. Keep checkpoints in protected storage and never put authentication tokens into snapshot/cursor fields. Checkpoint rows contain DNS logs: treat them as sensitive data, although they contain no authentication credentials.

JSON, JSONL and CSV exports create a new directory, immutable outputs, checkpoint and manifest with hashes. CSV formula cells are neutralized. Do not overwrite raw exports.

Forward workflow: read → plan → inspect diff and before hash → explicit approval of plan SHA-256 → apply with `dry_run: false` → read/verify → after snapshot. Default apply and rollback are dry-run. Rollback requires the same explicit plan approval and matching verified after snapshot. An uncertain write consumes its claim and requires operator recovery; do not automatically replay it.

After conversation compression reload the named profile and sanitized capability evidence, tool version and checkpoint. Never recover credentials from chat history. Use the preserved plan ID and hash for forward recovery; do not rebuild or replay a consumed plan.

Minimal example: execute `dns_authenticate` with `{"profile":"lab","target":"http://172.16.30.209:1606"}` after configuring authentication. Success returns `{"ok":true,"result":{"authenticated":true,"mode":"json"},"tool_version":"4.0.0"}`. Errors return a code, retryable flag and next action; only retry the same read when instructed. See the contract for all interfaces and current limitations.


Top Reports (contract 3.2): use `lab_dns_get_top_report_capabilities`, then `lab_dns_get_top_report` for hardware load or DNS rankings. Respect ready/stale/no_data/pending and delivery_complete; never infer zero from missing data. [Usage / 使用說明](../../docs/TOP_REPORTS.md).
