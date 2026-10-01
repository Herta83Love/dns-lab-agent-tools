# DNS Lab Agent Tools

Guarded function tools for a VLLM/OpenAI-compatible Agent operating controlled DNS security laboratories.

The project supports reading forward configuration, exporting paired Proxy DNS logs, approved forward changes, and bounded synthetic high-entropy/DGA-like traffic. It includes certificate pinning, immutable plans, one-time approvals, audit logs, and before-state backups.

No credentials, raw DNS logs, review data, models, or runtime artifacts belong in this repository.

## Tools

```text
lab_dns_get_forwarders
lab_dns_export_logs
lab_dns_plan_forward_change
lab_dns_apply_forward_plan
lab_dns_plan_synthetic_traffic
lab_dns_run_synthetic_traffic_plan
```

## Installation

Copy the module into the Agent package:

```bash
cp agent/dns_lab_tools.py /path/to/agent/dns_lab_tools.py
cp agent/approve_dns_lab_plan.py /path/to/agent/approve_dns_lab_plan.py
cp agent/dns_lab_config.example.json /path/to/agent/dns_lab_config.json
```

Edit the configuration and create its referenced secret file with mode `0600`.

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
