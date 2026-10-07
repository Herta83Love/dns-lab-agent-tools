"""Read-only MCP registration acceptance for an isolated installed release."""
import asyncio
import json
from pathlib import Path
import sys
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
async def main(root):
 params=StdioServerParameters(command=str(root/'.venv/bin/python'),args=['-m','agent.mcp_server','--allow-manifest-traffic'],cwd=str(root))
 async with stdio_client(params) as (read,write):
  async with ClientSession(read,write) as session:
   await session.initialize();names={t.name for t in (await session.list_tools()).tools}
   assert len(names)==10 and {'lab_dns_plan_manifest_traffic','lab_dns_run_manifest_traffic_plan','lab_dns_get_traffic_plan_status','lab_dns_reconcile_manifest_logs'}<=names
   result=await session.call_tool('lab_dns_get_context',{});assert not result.isError
   context=json.loads(result.content[0].text);assert context['tool_contract_version']=='3.3' and context['runtime']['config_presence']
   print('MCP deployed config/context/tools-list acceptance: PASS (no DNS traffic)')
if __name__=='__main__':
 try:asyncio.run(main(Path(sys.argv[1]).resolve()))
 except Exception:raise SystemExit('MCP_DEPLOYMENT_ACCEPTANCE_FAILED') from None
