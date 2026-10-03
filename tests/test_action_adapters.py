import json
import tempfile
import unittest
from pathlib import Path

from runner_core.registry import ActionRegistry, load_registry
from runner_core.action_model import ActionSpec


class RegistryTests(unittest.TestCase):
    def test_active_action_requires_confirmation(self):
        registry = ActionRegistry([ActionSpec("active", "Active", "", ["python3", "-c", "print('should not run')"], requires_confirmation=True)])
        result = registry.execute("active")
        self.assertEqual(result.status, "ATTENTION")
        self.assertEqual(result.verification, "not_run")

    def test_loads_json_compatible_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tool-runner.yaml"
            path.write_text(json.dumps({"actions": [{"id": "x", "label": "X", "command": ["python3", "--version"]}]}))
            registry = load_registry(path, Path(directory))
            self.assertEqual(registry.get("x").cwd, str(Path(directory)))


if __name__ == "__main__":
    unittest.main()
