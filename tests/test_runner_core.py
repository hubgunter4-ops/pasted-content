import tempfile
import time
import unittest
import sys
from pathlib import Path

from runner_core.action_model import ActionSpec
from runner_core.process_runner import ProcessRunner


class RunnerCoreTests(unittest.TestCase):
    def test_zero_exit_requires_valid_json(self):
        spec = ActionSpec("json", "JSON", "", ["python3", "-c", "print('not json')"], verifier="json_payload")
        result = ProcessRunner().run(spec)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.status, "ATTENTION")
        self.assertEqual(result.verification, "json_payload")

    def test_unhealthy_rpc_is_attention(self):
        spec = ActionSpec("rpc", "RPC", "", ["python3", "-c", "import json; print(json.dumps({'rpc_alive': False}))"], verifier="rpc_health")
        result = ProcessRunner().run(spec)
        self.assertEqual(result.status, "ATTENTION")
        self.assertEqual(result.verification, "rpc_health")

    def test_success_requires_postcondition(self):
        spec = ActionSpec("report", "Report", "", ["python3", "-c", "from pathlib import Path; print('/definitely/missing')"], verifier="report_file")
        result = ProcessRunner().run(spec)
        self.assertEqual(result.status, "ATTENTION")
        self.assertIn("missing", result.error)

    def test_timeout_is_reported(self):
        spec = ActionSpec("slow", "Slow", "", ["python3", "-c", "import time; time.sleep(2)"], timeout_seconds=1)
        result = ProcessRunner().run(spec)
        self.assertEqual(result.status, "TIMEOUT")
        self.assertIsNotNone(result.exit_code)

    def test_python_adapter_uses_active_interpreter(self):
        spec = ActionSpec("python", "Python", "", ["python3", "-c", "import sys; print(sys.executable)"])
        result = ProcessRunner().run(spec)
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(result.stdout.strip(), sys.executable)

    def test_dry_run_does_not_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "marker"
            spec = ActionSpec("dry", "Dry", "", ["python3", "-c", f"open({str(output)!r}, 'w').write('x')"], cwd=directory)
            result = ProcessRunner().run(spec, dry_run=True)
            self.assertEqual(result.verification, "dry_run")
            self.assertFalse(output.exists())

    def test_report_file_verifier_accepts_real_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.md"
            spec = ActionSpec("report", "Report", "", ["python3", "-c", f"from pathlib import Path; p=Path({str(output)!r}); p.write_text('ok'); print(p)"], cwd=directory, verifier="report_file")
            result = ProcessRunner().run(spec)
            self.assertEqual(result.status, "COMPLETED")
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
