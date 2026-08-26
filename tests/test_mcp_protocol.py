import asyncio
import os
import sys
import unittest
from pathlib import Path

from mcp import Client, StdioServerParameters


REPO_ROOT = Path(__file__).resolve().parents[1]


class McpProtocolTests(unittest.TestCase):
    def test_stdio_server_lists_tools_and_safe_capabilities(self):
        async def exercise():
            params = StdioServerParameters(
                command=sys.executable,
                args=[str(REPO_ROOT / "msf_bridge_mcp.py")],
                env={
                    "PYTHONPATH": str(REPO_ROOT),
                    "MSF_MCP_ALLOWED_TARGETS": "",
                    "MSF_MCP_ENABLE_ACTIVE": "0",
                    "MSF_MCP_ENABLE_CRED_TESTS": "0",
                    "MSF_MCP_ENABLE_EXPLOITS": "0",
                },
            )
            async with Client(params, raise_exceptions=True) as client:
                tools = await client.list_tools()
                names = {tool.name for tool in tools.tools}
                result = await client.call_tool("get_capabilities", {})
                return names, result

        names, result = asyncio.run(exercise())
        self.assertIn("get_capabilities", names)
        self.assertIn("scan_target", names)
        self.assertIn("execute_mapped_module", names)
        self.assertFalse(result.is_error)
        payload = result.structured_content.get("result", result.structured_content)
        self.assertEqual(payload["active_operations_enabled"], False)
        self.assertEqual(payload["exploits_enabled"], False)


if __name__ == "__main__":
    unittest.main()
