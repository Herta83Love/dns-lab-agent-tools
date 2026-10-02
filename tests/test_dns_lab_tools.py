import ast
import hashlib
import json
import os
import tempfile
import unittest
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
            with self.assertRaises(DNSLabToolError) as caught:
                tools.execute_dns_lab_tool("lab_dns_plan_forward_change",{"operation":"add","domain":"x.lab.test"})
        self.assertEqual(caught.exception.payload["error_code"],"INVALID_ARGUMENT")
        self.assertIn("primary is required",caught.exception.payload["message"])
        self.assertEqual(caught.exception.payload["action"],"stop_and_report")

    def test_missing_config_stops_without_connecting(self):
        with tempfile.TemporaryDirectory() as directory:
            missing=Path(directory)/"dns_lab_config.json"
            with patch.object(tools,"CONFIG_PATH",missing), patch.object(tools,"LabClient",side_effect=AssertionError("client constructed")):
                with self.assertRaises(DNSLabToolError) as caught:
                    tools.execute_dns_lab_tool("lab_dns_get_forwarders",{})
        self.assertEqual(caught.exception.payload["error_code"],"CONFIG_MISSING")
        self.assertFalse(caught.exception.payload["retryable"])
        self.assertNotIn("password",json.dumps(caught.exception.payload).lower())

    def test_invalid_config_does_not_echo_body(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"dns_lab_config.json"
            path.write_text("{not-json secret-marker",encoding="utf-8")
            with patch.object(tools,"CONFIG_PATH",path):
                with self.assertRaises(DNSLabToolError) as caught:
                    tools.execute_dns_lab_tool("lab_dns_get_context",{})
        self.assertEqual(caught.exception.payload["error_code"],"CONFIG_INVALID")
        self.assertNotIn("secret-marker",json.dumps(caught.exception.payload))

    def test_secret_mode_rejects_group_readable_without_echoing_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            secret=Path(directory)/"lab-dns.secret"
            secret.write_text("synthetic-secret-value\n",encoding="utf-8")
            os.chmod(secret,0o640)
            with self.assertRaises(DNSLabToolError) as caught:
                tools._read_private_secret(secret)
        self.assertEqual(caught.exception.payload["error_code"],"SECRET_UNAVAILABLE")
        self.assertNotIn("synthetic-secret-value",json.dumps(caught.exception.payload))

    def test_secret_mode_accepts_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            secret=Path(directory)/"lab-dns.secret"
            secret.write_text("synthetic-secret-value\n",encoding="utf-8")
            os.chmod(secret,0o600)
            self.assertEqual(tools._read_private_secret(secret),"synthetic-secret-value")

    def test_windows_secret_check_uses_owner_acl(self):
        with tempfile.TemporaryDirectory() as directory:
            secret=Path(directory)/"lab-dns.secret"
            secret.write_text("synthetic-secret-value\n",encoding="utf-8")
            os.chmod(secret,0o666)
            with patch.object(tools,"_is_windows",return_value=True), patch.object(tools,"_nt_owner_only",return_value=True) as acl:
                self.assertEqual(tools._read_private_secret(secret),"synthetic-secret-value")
                acl.assert_called_once()
            with patch.object(tools,"_is_windows",return_value=True), patch.object(tools,"_nt_owner_only",return_value=False):
                with self.assertRaises(DNSLabToolError) as caught:
                    tools._read_private_secret(secret)
            self.assertEqual(caught.exception.payload["error_code"],"SECRET_UNAVAILABLE")
            self.assertNotIn("synthetic-secret-value",json.dumps(caught.exception.payload))

    def test_workspace_root_must_be_absolute(self):
        saved=(tools.ROOT,tools.AUDIT,tools.PLANS,tools.EXPORTS)
        try:
            with self.assertRaises(DNSLabToolError) as caught:
                tools._bind_workspace({"workspace_root":"relative/dns_lab"})
            self.assertEqual(caught.exception.payload["error_code"],"CONFIG_INVALID")
            with tempfile.TemporaryDirectory() as directory:
                tools._bind_workspace({"workspace_root":directory})
                self.assertEqual(tools.ROOT,Path(directory))
                self.assertEqual(tools.PLANS,Path(directory)/"plans")
            tools._bind_workspace({})
            self.assertEqual(tools.ROOT,tools.DEFAULT_ROOT)
        finally:
            tools.ROOT,tools.AUDIT,tools.PLANS,tools.EXPORTS=saved

    def test_audit_lock_appends_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            audit=root/"audit.jsonl"
            with patch.object(tools,"ROOT",root), patch.object(tools,"AUDIT",audit), patch.object(tools,"PLANS",root/"plans"), patch.object(tools,"EXPORTS",root/"exports"):
                tools._audit("unit",step=1)
                tools._audit("unit",step=2)
            rows=[json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([row["step"] for row in rows],[1,2])
            self.assertEqual(audit.stat().st_mode & 0o077,0)

    def test_fcntl_is_not_imported_at_module_level(self):
        tree=ast.parse(Path(tools.__file__).read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node,ast.Import):
                self.assertFalse(any(alias.name=="fcntl" for alias in node.names))
            if isinstance(node,ast.ImportFrom):
                self.assertNotEqual(node.module,"fcntl")

    def test_free_bytes_uses_disk_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertGreaterEqual(tools._free_bytes(directory),0)

    def test_missing_dig_is_structured(self):
        with patch.object(Path,"is_file",return_value=False):
            with self.assertRaises(DNSLabToolError) as caught:
                tools._dig_executable()
        self.assertEqual(caught.exception.payload["error_code"],"DIG_UNAVAILABLE")
        self.assertIn("curl",caught.exception.payload["next_action"])

    def test_unknown_tool_stops(self):
        cfg={"default_profile":"lab","profiles":{"lab":{}}}
        with patch.object(tools,"_config",return_value=cfg):
            with self.assertRaises(DNSLabToolError) as caught:
                tools.execute_dns_lab_tool("lab_dns_not_a_tool",{})
        self.assertEqual(caught.exception.payload["error_code"],"UNKNOWN_TOOL")

    def test_published_source_hashes_match_files(self):
        repo=Path(__file__).resolve().parents[1]
        manifest=json.loads((repo/"tool-manifest.json").read_text(encoding="utf-8"))
        for rel,expected in manifest["source_sha256"].items():
            digest=hashlib.sha256((repo/rel).read_bytes()).hexdigest()
            self.assertEqual(digest,expected,rel)
if __name__=="__main__": unittest.main()
