import os
import unittest
from unittest.mock import patch

import msf_bridge_mcp as server


class McpPolicyTests(unittest.TestCase):
    def test_target_validation_accepts_ip_cidr_and_fqdn(self):
        self.assertEqual(server._validate_target("192.0.2.10"), "192.0.2.10")
        self.assertEqual(server._validate_target("192.0.2.0/24"), "192.0.2.0/24")
        self.assertEqual(server._validate_target("Host.Example.COM."), "host.example.com")

    def test_target_validation_rejects_shell_syntax(self):
        with self.assertRaises(ValueError):
            server._validate_target("192.0.2.10; whoami")
        with self.assertRaises(ValueError):
            server._validate_target("$(id)")

    def test_allowlist_supports_ip_cidr_and_subdomain(self):
        with patch.dict(
            os.environ,
            {"MSF_MCP_ALLOWED_TARGETS": "192.0.2.0/24,example.com"},
            clear=False,
        ):
            self.assertTrue(server._target_in_allowlist("192.0.2.10"))
            self.assertTrue(server._target_in_allowlist("sub.example.com"))
            self.assertFalse(server._target_in_allowlist("198.51.100.10"))
            self.assertFalse(server._target_in_allowlist("example.com.evil"))

    def test_nmap_policy_allows_small_safe_subset(self):
        self.assertEqual(
            server._validate_nmap_args("-sV -T2 --top-ports 100"),
            "-sV -T2 --top-ports 100",
        )
        self.assertEqual(server._validate_nmap_args(""), "-sV")

    def test_nmap_policy_rejects_scripts_and_arbitrary_output(self):
        for value in ("--script vuln", "-oX /tmp/out.xml", "-p-", "--datadir /tmp"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    server._validate_nmap_args(value)

    def test_authorization_requires_ack_allowlist_and_active_flag(self):
        env = {
            "MSF_MCP_ALLOWED_TARGETS": "192.0.2.0/24",
            "MSF_MCP_ENABLE_ACTIVE": "1",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(PermissionError):
                server._require_authorized(
                    "192.0.2.10", "passive", "wrong-ack"
                )
            with self.assertRaises(PermissionError):
                server._require_authorized(
                    "198.51.100.10",
                    "passive",
                    server.AUTHORIZATION_ACK,
                )
            self.assertEqual(
                server._require_authorized(
                    "192.0.2.10",
                    "passive",
                    server.AUTHORIZATION_ACK,
                ),
                "192.0.2.10",
            )

    def test_capabilities_report_safe_defaults(self):
        with patch.dict(
            os.environ,
            {
                "MSF_MCP_ALLOWED_TARGETS": "",
                "MSF_MCP_ENABLE_ACTIVE": "0",
                "MSF_MCP_ENABLE_CRED_TESTS": "0",
                "MSF_MCP_ENABLE_EXPLOITS": "0",
            },
            clear=False,
        ):
            capabilities = server.get_capabilities()
        self.assertFalse(capabilities["active_operations_enabled"])
        self.assertFalse(capabilities["credential_tests_enabled"])
        self.assertFalse(capabilities["exploits_enabled"])
        self.assertTrue(capabilities["policy"]["target_operations_require_allowlist"])


if __name__ == "__main__":
    unittest.main()
