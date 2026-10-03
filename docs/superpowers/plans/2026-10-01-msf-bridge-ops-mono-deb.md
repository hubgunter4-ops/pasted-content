# MSF Bridge Ops Mono Implementation Plan

> **For agentic workers:** Implement task-by-task and verify each task before proceeding.

**Goal:** Build a PySide6 Ops Mono desktop interface for MSF Bridge with observable, postcondition-verified actions and a reproducible Debian package.

**Architecture:** Keep `msf_bridge.py` and `msf_bridge_mcp.py` as the existing operational adapters. Add a small declarative action model and process runner that emits lifecycle events and verifies postconditions, then consume it from the GUI. Package the GUI and CLI entry points through a Debian layout without embedding secrets or development paths.

**Tech Stack:** Python >=3.10, PySide6, subprocess/process groups, YAML or JSON-compatible declarative configuration, unittest, `dpkg-deb`.

**Spec:** `PROPOSAL.md`, confirmed Ops Mono scope, `tool-runner-schema.md`, `command-spec.md`, `packaging.md`.

## Global Constraints

- Preserve the existing CLI commands, MCP stdio transport, policy gates, and safety defaults.
- Never mark an action complete from a button click alone; require `exit_code == 0` and an action-specific postcondition.
- Keep active target operations behind the existing allowlist, acknowledgement, and environment flags.
- Use a local `.venv` for development dependencies; do not use `sudo` during build.
- Do not run Nmap, Metasploit modules, sessions, or real targets during validation.
- Redact secret environment values and sensitive command arguments in logs.
- Build a Debian package for the current `amd64` environment and document installation/removal permissions.

## Review Focus

- A command exits zero but produces an invalid/missing result: test postcondition failure.
- Timeout or cancellation leaves child processes alive: test process-group cleanup.
- A path contains spaces: test argv-based execution and report outputs.
- RPC/network actions are accidentally enabled by the GUI: test safe defaults and policy lock.
- Package contains absolute sandbox paths or secrets: inspect package contents and metadata.

---

### Task 1: Action model and observable process runner

**Files:**
- Create: `runner_core/action_model.py`
- Create: `runner_core/process_runner.py`
- Create: `runner_core/verifiers.py`
- Create: `config/tool-runner.yaml`
- Test: `tests/test_runner_core.py`

**Interfaces:**
- `ActionSpec.from_mapping(mapping) -> ActionSpec`
- `ActionResult(status, exit_code, started_at, finished_at, duration_s, pid, stdout, stderr, verification, error)`
- `ProcessRunner.run(spec, *, dry_run=False, env=None) -> ActionResult`
- `ProcessRunner.cancel(run_id) -> None`
- `verify_postcondition(name, context) -> VerificationResult`

- [ ] Add failing tests for success requiring exit code and verifier, failed verification after exit 0, timeout, cancellation, redaction, and paths with spaces.
- [ ] Implement argv-first process execution with cwd validation, timestamps, PID, separate stdout/stderr, timeout, SIGINT/SIGTERM then SIGKILL process-group cleanup.
- [ ] Implement named verifiers for executable detection, RPC health, structured payloads, XML/import evidence, job/session evidence, resource disappearance, and report file validity.
- [ ] Define safe action metadata in `config/tool-runner.yaml`; active actions retain `requires_confirmation: true` and policy dependencies.
- [ ] Run `python -m unittest tests.test_runner_core -v`.

### Task 2: Adapter actions and compatibility layer

**Files:**
- Create: `runner_core/adapters.py`
- Modify: `pyproject.toml`
- Modify: `msf_bridge.py`
- Modify: `msf_bridge_mcp.py`
- Test: `tests/test_action_adapters.py`

**Interfaces:**
- `build_action_registry(repo_root) -> ActionRegistry`
- `ActionRegistry.execute(action_id, inputs, *, dry_run=False) -> ActionResult`
- Existing `main()` and MCP tool signatures remain compatible.

- [ ] Add tests that registry actions invoke safe local commands only in tests and verify returned evidence.
- [ ] Route read-only preflight/report actions through the shared runner without changing legacy CLI behavior.
- [ ] Keep scan/module/session actions delegated to existing guarded functions and require their evidence verifiers.
- [ ] Add a CLI-compatible `tool-runner` entry point or documented subcommand without removing `msf-bridge`/`msf-bridge-mcp`.
- [ ] Run existing policy/protocol tests after dependencies are available; do not contact external endpoints.

### Task 3: PySide6 Ops Mono interface

**Files:**
- Create: `interfaces/gui/main_window.py`
- Create: `interfaces/gui/theme.py`
- Create: `interfaces/gui/widgets.py`
- Create: `interfaces/gui/app.py`
- Test: `tests/test_gui_model.py`

**Interfaces:**
- `create_app(action_registry) -> QApplication`
- `MainWindow(action_registry)`
- `OpsMonoTheme.apply(app) -> None`

- [ ] Add model tests for action state transitions and disabled active actions under safe defaults.
- [ ] Implement dark Ops Mono theme: monospaced typography, black/deep graphite surfaces, teal accent, green success, amber warning, red failure.
- [ ] Implement project explorer, action queue, inspector, console, status bar, and keyboard-accessible controls.
- [ ] Run actions off the UI thread and map runner events to `AVAILABLE`, `RUNNING`, `COMPLETED`, `FAILED`, `TIMEOUT`, `CANCELLED`, and `ATTENTION`.
- [ ] Show command, risk, dependencies, verification result, exit code, duration, and redacted logs for every action.
- [ ] Generate `previews/final.png` from the implemented layout or a clearly labeled functional capture.

### Task 4: Tests and safe validation

**Files:**
- Modify: `tests/test_runner_core.py`
- Modify: `tests/test_action_adapters.py`
- Modify: `tests/test_gui_model.py`
- Create: `tests/test_packaging.py`

- [ ] Test detection, healthcheck mocks, valid/invalid payloads, missing XML, missing job/session evidence, report validation, timeout, cancellation, malformed config, and permissions.
- [ ] Test MCP safe defaults and exact authorization gates without RPC/Nmap.
- [ ] Run `py_compile`, unit tests, GUI import/instantiation in offscreen mode, and package-content inspection.
- [ ] Record any unavailable dependency or environment limitation rather than bypassing it.

### Task 5: Installer and Debian package

**Files:**
- Create: `packaging/debian/DEBIAN/control`
- Create: `packaging/debian/usr/bin/msf-bridge-ops`
- Create: `packaging/debian/usr/share/applications/msf-bridge-ops.desktop`
- Create: `packaging/build-deb.sh`
- Create: `packaging/install.sh`
- Create: `packaging/uninstall.sh`
- Create: `packaging/SHA256SUMS`
- Modify: `README.md`

- [ ] Define package metadata, runtime dependencies, launcher, desktop entry, and versioned output `dist/msf-bridge-ops_<version>_amd64.deb`.
- [ ] Build with `dpkg-deb --build` without privileged scripts or absolute development paths.
- [ ] Inspect package with `dpkg-deb --info` and `dpkg-deb --contents`; verify no secrets or sandbox paths.
- [ ] Provide install/uninstall commands; do not execute privileged installation automatically.
- [ ] Generate checksum and document rollback, configuration paths, logs, and limitations.

### Task 6: Final validation and delivery

- [ ] Run all safe tests and compile checks.
- [ ] Verify `dist/*.deb`, installer scripts, checksum, documentation, and `previews/final.png` exist and are non-empty.
- [ ] Compare final preview against the approved Ops Mono direction.
- [ ] Report exact commands run, tests passed/blocked, package path, checksum, and safe installation instructions.
