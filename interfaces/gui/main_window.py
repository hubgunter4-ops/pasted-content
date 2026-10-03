from __future__ import annotations

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMainWindow, QPlainTextEdit, QPushButton, QSplitter, QStatusBar, QToolBar, QVBoxLayout, QWidget

from runner_core.registry import ActionRegistry
from .widgets import PALETTE, panel, status_label


class ActionSignals(QObject):
    finished = Signal(object)


class ActionTask(QRunnable):
    def __init__(self, registry: ActionRegistry, action_id: str, confirmed: bool = False) -> None:
        super().__init__(); self.registry, self.action_id, self.confirmed = registry, action_id, confirmed; self.signals = ActionSignals()

    @Slot()
    def run(self) -> None:
        self.signals.finished.emit(self.registry.execute(self.action_id, confirmed=self.confirmed))


class MainWindow(QMainWindow):
    def __init__(self, registry: ActionRegistry) -> None:
        super().__init__(); self.registry = registry; self.pool = QThreadPool.globalInstance(); self.current_id = None
        self.setWindowTitle("MSF Bridge Orchestrator · Ops Mono")
        self.resize(1440, 900)
        self._build()

    def _build(self) -> None:
        menu = self.menuBar()
        for name in ("File", "Edit", "View", "Run", "Tools", "Help"):
            menu.addMenu(name)
        toolbar = QToolBar("Actions", self); toolbar.setMovable(False); toolbar.setFloatable(False); toolbar.setToolButtonStyle(Qt.ToolButtonTextOnly)
        for label in ("Detect", "Health", "Map", "Scan", "Run"):
            action = toolbar.addAction(label)
            action.setData(label.lower())
            action.triggered.connect(lambda checked=False, name=label: self._toolbar_run(name))
        self.addToolBar(toolbar)
        root = QWidget(); outer = QVBoxLayout(root); outer.setContentsMargins(12, 10, 12, 8); outer.setSpacing(8)
        header = QHBoxLayout(); title = QLabel("MSF Bridge Orchestrator"); title.setStyleSheet("font-size: 20px; font-weight: bold;")
        header.addWidget(title); header.addStretch(); header.addWidget(status_label("● RPC HEALTHY", PALETTE["success"])); header.addWidget(QLabel("OPS MONO · stdio MCP")); outer.addLayout(header)
        splitter = QSplitter(); outer.addWidget(splitter, 1)
        # navigation
        nav, nav_l = panel("Project Explorer"); self.nav = QListWidget();
        for label in ["● Overview", "○ Capabilities", "○ Services & Map", "○ Sessions", "○ Jobs", "○ Reports"]: self.nav.addItem(label)
        nav_l.addWidget(self.nav); nav_l.addWidget(QLabel("Runbook"));
        for label in ["1  Detect environment", "2  Health check", "3  Map services", "4  Scan target", "5  Execute module"]: nav_l.addWidget(QLabel(label))
        nav_l.addStretch(); nav_l.addWidget(status_label("● Active operations disabled", PALETTE["warn"])); splitter.addWidget(nav)
        # center
        center = QWidget(); cl = QVBoxLayout(center); cl.setContentsMargins(0,0,0,0)
        overview, ol = panel("Overview · Guardrails-first execution workspace"); cards = QHBoxLayout()
        for label, value, color in [("RPC", "HEALTHY", PALETTE["success"]), ("POLICY", "LOCKED", PALETTE["warn"]), ("TRANSPORT", "STDIO", PALETTE["accent"])]:
            card, card_l = panel(label); card.setObjectName("card"); card_l.addWidget(status_label(value, color)); cards.addWidget(card)
        ol.addLayout(cards); cl.addWidget(overview)
        queue, ql = panel("Action queue · completion requires postcondition verification")
        self.actions = QListWidget(); self.actions.currentRowChanged.connect(self._select_action)
        for spec in self.registry.specs.values():
            state = "LOCKED" if spec.requires_confirmation else "AVAILABLE"
            item = QListWidgetItem(f"{state}  ·  {spec.label}  ·  risk={spec.risk}")
            item.setData(Qt.UserRole, spec.id)
            item.setForeground(QColor(PALETTE["danger"] if state == "LOCKED" else PALETTE["success"]))
            self.actions.addItem(item)
        ql.addWidget(self.actions); cl.addWidget(queue, 2)
        console, con_l = panel("Console · stdout / stderr · verified result")
        self.console = QPlainTextEdit(); self.console.setReadOnly(True); self.console.setPlaceholderText("No action executed. Select an action and run it."); con_l.addWidget(self.console); cl.addWidget(console, 2)
        splitter.addWidget(center)
        # inspector
        inspector, il = panel("Inspector"); self.detail = QLabel("Select an action"); self.detail.setWordWrap(True); il.addWidget(self.detail); il.addStretch()
        self.run_btn = QPushButton("RUN SELECTED ACTION"); self.run_btn.clicked.connect(self._run_selected); il.addWidget(self.run_btn)
        self.cancel_btn = QPushButton("CANCEL"); self.cancel_btn.clicked.connect(self._cancel_selected); self.cancel_btn.setEnabled(False); il.addWidget(self.cancel_btn); splitter.addWidget(inspector)
        splitter.setSizes([240, 900, 300]); self.setCentralWidget(root)
        status = QStatusBar(self)
        status.addWidget(status_label("Ready", PALETTE["success"]))
        status.addWidget(QLabel("Project: pasted-content"))
        status.addPermanentWidget(QLabel("UTF-8   Linux   OPS MONO"))
        self.setStatusBar(status)

    def _select_action(self, row: int) -> None:
        if row < 0: return
        spec = list(self.registry.specs.values())[row]; self.current_id = spec.id
        self.detail.setText(f"{spec.label}\n\n{spec.description}\n\nRISK  {spec.risk.upper()}\nTIMEOUT  {spec.timeout_seconds}s\nVERIFIER  {spec.verifier or 'exit_code'}\n\nCommand:\n{' '.join(spec.command)}")

    def _toolbar_run(self, name: str) -> None:
        mapping = {"Detect": "detect", "Health": "health-check", "Map": "map-services", "Scan": "scan-target"}
        if name in mapping and mapping[name] in self.registry.specs:
            target = mapping[name]
            for row, spec in enumerate(self.registry.specs.values()):
                if spec.id == target:
                    self.actions.setCurrentRow(row); break
        self._run_selected()

    def _run_selected(self) -> None:
        if not self.current_id: return
        self.run_btn.setEnabled(False); self.cancel_btn.setEnabled(True); self.console.appendPlainText(f"[RUNNING] {self.current_id}")
        task = ActionTask(self.registry, self.current_id, confirmed=False); task.signals.finished.connect(self._finished); self.pool.start(task)

    def _cancel_selected(self) -> None:
        if self.current_id: self.registry.cancel(self.current_id); self.console.appendPlainText(f"[CANCEL REQUESTED] {self.current_id}")

    def _finished(self, result) -> None:
        self.run_btn.setEnabled(True); self.cancel_btn.setEnabled(False)
        self.console.appendPlainText(f"[{result.status}] exit={result.exit_code} verification={result.verification} duration={result.duration_s:.2f}s")
        if result.stdout: self.console.appendPlainText(result.stdout.rstrip())
        if result.stderr: self.console.appendPlainText("[stderr] " + result.stderr.rstrip())
        if result.error: self.console.appendPlainText("[attention] " + result.error)
        for i in range(self.actions.count()):
            if self.actions.item(i).data(Qt.UserRole) == result.action_id:
                self.actions.item(i).setText(f"{result.status}  ·  {self.registry.get(result.action_id).label}  ·  verify={result.verification}")
                colors = {"COMPLETED": PALETTE["success"], "ATTENTION": PALETTE["warn"], "FAILED": PALETTE["danger"], "TIMEOUT": PALETTE["danger"], "CANCELLED": PALETTE["warn"]}
                self.actions.item(i).setForeground(QColor(colors.get(result.status, PALETTE["text"])))
                break
