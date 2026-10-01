import unittest
from unittest.mock import patch
from agent.dns_lab_tools import _domain, _split_target, _profile

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
if __name__=="__main__": unittest.main()
