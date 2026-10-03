from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from runner_core.registry import load_registry
from .main_window import MainWindow
from .widgets import apply_ops_mono


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    app = QApplication(sys.argv)
    apply_ops_mono(app)
    registry = load_registry(repo_root / "config" / "tool-runner.yaml", repo_root)
    window = MainWindow(registry); window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
