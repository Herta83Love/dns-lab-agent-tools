import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import agent.dns_lab_tools as tools
from agent.dns_lab_tools import DNSLabToolError, _domain, _split_target, _profile

CFG={"allowed_forward_suffixes":["test","example","invalid"],"allowed_forward_networks":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"],"allowed_forward_ports":[53,5353]}
class Tests(unittest.TestCase):
    def test_domain(self): self.assertEqual(_domain("x.lab.test",CFG),"x.lab.test")
    def test_domain_rejects_public(self):
        with self.assertRaises(ValueError): _domain("example.com",CFG)
    def test_private_target(self): self.assertEqual(_split_target("172.16.30.10:53",CFG),"172.16.30.10:53")
    def test_public_target_rejected(self):
        with self.assertRaises(ValueError): _split_target("8.8.8.8:53",CFG)
    def test_port_rejected(self):
        with self.assertRaises(ValueError): _split_target("172.16.30.10:443",CFG)
    def test_unknown_profile_rejected(self):
        with patch("agent.dns_lab_tools._config", return_value={"default_profile":"lab","profiles":{"lab":{}}}):
            with self.assertRaises(ValueError): _profile("does-not-exist")

    def test_tool_names_are_unique(self):
        names=[item["function"]["name"] for item in tools.DNS_LAB_TOOL_DEFINITIONS]
        self.assertEqual(len(names),len(set(names)))
        self.assertIn("lab_dns_get_context",names)
        self.assertIn("lab_dns_get_plan_status",names)

    def test_context_is_secret_free_and_recovers_policy(self):
        cfg={
            "default_profile":"lab",
            "profiles":{"lab":{"base_url":"https://private.invalid","account":"admin","secret_file":"/secret","allow_forward_writes":False,"traffic_dns_server":"10.0.0.2","traffic_dns_port":53}},
            "allowed_forward_suffixes":["lab.test"],
            "allowed_forward_networks":["10.0.0.0/8"],
            "allowed_forward_ports":[53],
            "max_export_bytes":1000,
            "min_free_bytes":100,
            "max_traffic_queries":10,
            "max_traffic_qps":2,
            "plan_ttl_seconds":60,
        }
        with tempfile.TemporaryDirectory() as directory, patch.object(tools,"PLANS",Path(directory)), patch.object(tools,"_config",return_value=cfg):
            result=tools._context()
        encoded=json.dumps(result)
        self.assertNotIn("secret_file",encoded)
        self.assertNotIn('"account"',encoded)
        self.assertNotIn("base_url",encoded)
        self.assertEqual(result["policy"]["allowed_forward_suffixes"],["lab.test"])

    def test_invalid_plan_id_gives_recovery_action(self):
        cfg={"default_profile":"lab","profiles":{"lab":{}}}
        with patch.object(tools,"_config",return_value=cfg):
            with self.assertRaises(DNSLabToolError) as caught:
                tools.execute_dns_lab_tool("lab_dns_get_plan_status",{"plan_id":"../../secret"})
        self.assertIn("INVALID_PLAN_ID",str(caught.exception))
        self.assertIn("lab_dns_get_context",str(caught.exception))

    def test_add_requires_primary_before_plan_creation(self):
        cfg={
            "default_profile":"lab",
            "profiles":{"lab":{"allow_forward_writes":True}},
            "allowed_forward_suffixes":["lab.test"],
        }
        with patch.object(tools,"_config",return_value=cfg), patch.object(tools,"_forwarders",return_value=[]):
            with self.assertRaises(ValueError) as caught:
                tools.execute_dns_lab_tool("lab_dns_plan_forward_change",{"operation":"add","domain":"x.lab.test"})
        self.assertIn("primary is required",str(caught.exception))
if __name__=="__main__": unittest.main()
