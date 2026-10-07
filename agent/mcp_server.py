"""Explicit stdio binding for Chatbox. Run on the host owning the DNS config."""
from __future__ import annotations
import argparse
import asyncio
import copy
import json
import logging
from pathlib import Path

READ_ONLY = {'lab_dns_get_context','lab_dns_get_plan_status','lab_dns_get_forwarders','lab_dns_export_logs','lab_dns_get_top_report','lab_dns_get_top_report_capabilities'}
TRAFFIC = {'lab_dns_plan_manifest_traffic','lab_dns_run_manifest_traffic_plan','lab_dns_get_traffic_plan_status','lab_dns_reconcile_manifest_logs'}
FORWARD = {'lab_dns_plan_forward_change','lab_dns_apply_forward_plan'}

def definitions(legacy, allow_forward=False, allow_traffic=False):
    permitted=READ_ONLY | (FORWARD if allow_forward else set()) | (TRAFFIC if allow_traffic else set())
    result=[]
    for item in legacy.DNS_LAB_TOOL_DEFINITIONS:
        f=copy.deepcopy(item['function'])
        if f['name'] not in permitted: continue
        f['parameters']['additionalProperties']=False
        result.append(f)
    return result

def dispatch(legacy, schemas, name, arguments):
    from jsonschema import Draft202012Validator
    if name not in schemas: return {'error_code':'TOOL_NOT_ENABLED','retryable':False,'action':'stop_and_report'}
    if not isinstance(arguments,dict) or not Draft202012Validator(schemas[name]).is_valid(arguments):
        return {'error_code':'INVALID_ARGUMENTS','retryable':False,'action':'stop_and_report','next_action':'Use tools/list inputSchema and the capability tool for valid section/report pairs; do not guess arguments.'}
    try: return legacy.execute_dns_lab_tool(name,arguments)
    except legacy.DNSLabToolError as error:
        return {'error_code':error.payload['error_code'],'retryable':bool(error.payload.get('retryable',False)),'action':error.payload.get('action','stop_and_report'),'next_action':'Stop and report the error code; do not probe alternate APIs.'}
    except Exception:
        return {'error_code':'ADAPTER_EXECUTION_FAILED','retryable':False,'action':'stop_and_report'}

async def serve(config, allow_forward=False, allow_traffic=False):
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent, CallToolResult, ToolAnnotations
    from . import dns_lab_tools as legacy
    # Explicit path binding; credentials remain entirely on the execution host.
    legacy.CONFIG_PATH=Path(config)
    funcs=definitions(legacy,allow_forward,allow_traffic);legacy._MCP_ENABLED_TOOLS=[f['name'] for f in funcs]; schemas={f['name']:f['parameters'] for f in funcs}
    server=Server('dns-lab-api-tools',version='1.2.0')
    lock=asyncio.Lock() # Legacy workspace/config bindings are process-global.
    @server.list_tools()
    async def list_tools():
        return [Tool(name=f['name'],description=f['description'],inputSchema=f['parameters'],annotations=ToolAnnotations(readOnlyHint=f['name'] in READ_ONLY or f['name'] in {'lab_dns_get_traffic_plan_status','lab_dns_reconcile_manifest_logs'},destructiveHint=f['name'] not in READ_ONLY and f['name'] not in {'lab_dns_get_traffic_plan_status','lab_dns_reconcile_manifest_logs'},openWorldHint=True)) for f in funcs]
    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        async with lock:
            result=await asyncio.to_thread(dispatch,legacy,schemas,name,arguments)
        failed=isinstance(result,dict) and bool(result.get('error_code'))
        return CallToolResult(content=[TextContent(type='text',text=json.dumps(result,ensure_ascii=False))],isError=failed)
    async with stdio_server() as (read,write):
        await server.run(read,write,server.create_initialization_options())

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',default=Path(__file__).with_name('dns_lab_config.json'),type=Path)
    parser.add_argument('--allow-forward-changes',action='store_true',help='Expose approval-guarded forward tools; does not authorize a device write.')
    parser.add_argument('--allow-manifest-traffic',action='store_true',help='Expose manifest plan/run/status/reconcile; sends still require SHA-bound human approval.')
    options=parser.parse_args()
    logging.disable(logging.CRITICAL) # Never log MCP request arguments or device exceptions.
    try: asyncio.run(serve(options.config,options.allow_forward_changes,options.allow_manifest_traffic))
    except Exception:
        # No traceback, exception contents or config values on stderr.
        import sys
        sys.stderr.write('DNS_MCP_STARTUP_FAILED: check runtime dependencies and protected config path.\n')
        raise SystemExit(1) from None
if __name__=='__main__':main()
