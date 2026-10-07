import os
import unittest
from unittest.mock import patch

from interfaces.tui import default_scope, render_lines


class TuiTests(unittest.TestCase):
    def test_snapshot_contains_safe_status_and_actions(self):
        with patch.dict(
            os.environ,
            {
                "MSF_MCP_DEFAULT_SCOPE": "passive",
                "MSF_MCP_ENABLE_ACTIVE": "0",
                "MSF_MCP_ALLOWED_TARGETS": "",
            },
            clear=False,
        ):
            output = "\n".join(render_lines())
        self.assertIn("ACTIVE DISABLED", output)
        self.assertIn("SCOPE passive", output)
        self.assertIn("Scan target", output)
        self.assertIn("Execute mapped module", output)

    def test_invalid_scope_is_visible_without_enabling_actions(self):
        with patch.dict(os.environ, {"MSF_MCP_DEFAULT_SCOPE": "invalid"}, clear=False):
            self.assertEqual(default_scope(), "INVALID")


if __name__ == "__main__":
    unittest.main()
