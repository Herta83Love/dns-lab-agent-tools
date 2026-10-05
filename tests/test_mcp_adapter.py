import unittest
from unittest.mock import Mock
from agent import dns_lab_tools as legacy
from agent.mcp_server import definitions,dispatch
try: import jsonschema
except ImportError: jsonschema=None
class Tests(unittest.TestCase):
    def test_default_readonly_and_no_traffic(self):
        self.assertEqual({f['name'] for f in definitions(legacy)},{'lab_dns_get_context','lab_dns_get_plan_status','lab_dns_get_forwarders','lab_dns_export_logs'})
        self.assertFalse(any('traffic' in f['name'] for f in definitions(legacy,True)))
    @unittest.skipUnless(jsonschema,'MCP optional dependency not installed')
    def test_report_arguments_rejected_before_execution(self):
        fake=Mock();schemas={f['name']:f['parameters'] for f in definitions(legacy)}
        r=dispatch(fake,schemas,'lab_dns_export_logs',{'time_window':60,'device':'dns-lab','include_payload':False,'start_time':'2026-10-05T04:04:00Z','end_time':'2026-10-05T04:05:00Z'})
        self.assertEqual(r['error_code'],'INVALID_ARGUMENTS');fake.execute_dns_lab_tool.assert_not_called()
    @unittest.skipUnless(jsonschema,'MCP optional dependency not installed')
    def test_error_does_not_echo_arguments_or_exceptions(self):
        fake=Mock();fake.DNSLabToolError=legacy.DNSLabToolError
        fake.execute_dns_lab_tool.side_effect=RuntimeError('fixture-sensitive-value')
        r=dispatch(fake,{'test':{'type':'object'}},'test',{})
        self.assertNotIn('fixture-sensitive-value',str(r))
