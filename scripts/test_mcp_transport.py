"""Official SDK client smoke test: handshake, discovery and invalid-argument rejection."""
import asyncio,json,sys
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
async def main():
    for flags,expected in [([],6),(['--allow-manifest-traffic'],10)]:
        params=StdioServerParameters(command=sys.executable,args=['-m','agent.mcp_server','--config','/nonexistent/dns-config.json',*flags])
        async with stdio_client(params) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize()
                tools=await session.list_tools()
                assert len(tools.tools)==expected
                if flags:
                    names={t.name for t in tools.tools}
                    assert 'lab_dns_run_manifest_traffic_plan' in names
                    rejected=await session.call_tool('lab_dns_plan_manifest_traffic',{'payload_file':'forbidden'})
                    assert rejected.isError and json.loads(rejected.content[0].text)['error_code']=='INVALID_ARGUMENTS'
                rejected=await session.call_tool('lab_dns_export_logs',{'device':'dns-lab','time_window':60,'include_payload':False,'start_time':'2026-10-05T04:04:00Z','end_time':'2026-10-05T04:05:00Z'})
                assert rejected.isError and json.loads(rejected.content[0].text)['error_code']=='INVALID_ARGUMENTS'
                config=await session.call_tool('lab_dns_get_context',{})
                assert config.isError and json.loads(config.content[0].text)['error_code']=='CONFIG_MISSING'
    print('MCP handshake/list/call/schema/error smoke: PASS; readonly=6 manifest=10; device requests=0')
asyncio.run(main())
