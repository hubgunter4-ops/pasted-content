import os
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication
    from interfaces.gui.main_window import MainWindow
    from runner_core.registry import load_registry
except ImportError:
    QApplication = None


@unittest.skipIf(QApplication is None, "PySide6 unavailable")
class GuiModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_main_window_contains_action_queue(self):
        root = Path(__file__).resolve().parents[1]
        registry = load_registry(root / "config" / "tool-runner.yaml", root)
        window = MainWindow(registry)
        self.assertGreater(window.actions.count(), 0)
        window.close()


if __name__ == "__main__":
    unittest.main()
