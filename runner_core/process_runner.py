from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from .action_model import ActionResult, ActionSpec
from .verifiers import verify_postcondition


_SECRET_KEYS = {"MSF_PASS", "PASSWORD", "TOKEN", "SECRET", "API_KEY"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(text: str) -> str:
    return text if not text else "[REDACTED]" if any(key in text.upper() for key in _SECRET_KEYS) else text


class ProcessRunner:
    def __init__(self) -> None:
        self._processes: Dict[str, subprocess.Popen[str]] = {}
        self._lock = threading.Lock()

    def run(self, spec: ActionSpec, *, dry_run: bool = False, env: Optional[Dict[str, str]] = None) -> ActionResult:
        started = time.monotonic()
        result = ActionResult(action_id=spec.id, status="RUNNING", started_at=_now())
        if dry_run:
            result.status = "COMPLETED"
            result.exit_code = 0
            result.finished_at = _now()
            result.verification = "dry_run"
            result.evidence = {"argv": spec.command, "cwd": str(Path(spec.cwd).resolve())}
            return result
        cwd = Path(spec.cwd).resolve()
        if not cwd.exists() or not cwd.is_dir():
            result.status, result.error = "FAILED", f"cwd does not exist: {cwd}"
            result.finished_at, result.duration_s = _now(), time.monotonic() - started
            return result
        process_env = os.environ.copy()
        process_env.update(spec.env)
        if env:
            process_env.update(env)
        command = list(spec.command)
        if command and command[0] in {"python", "python3"}:
            command[0] = sys.executable
        try:
            proc = subprocess.Popen(
                command, cwd=str(cwd), env=process_env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
            )
            result.pid = proc.pid
            with self._lock:
                self._processes[spec.id] = proc
            try:
                stdout, stderr = proc.communicate(timeout=spec.timeout_seconds)
            except subprocess.TimeoutExpired:
                self._terminate(spec.id, proc)
                stdout, stderr = proc.communicate()
                result.status = "TIMEOUT"
                result.error = f"timeout after {spec.timeout_seconds}s"
            else:
                result.status = "COMPLETED" if proc.returncode == 0 else "FAILED"
            result.exit_code = proc.returncode
            result.stdout = _redact(stdout or "")
            result.stderr = _redact(stderr or "")
            if result.status == "COMPLETED":
                verification = verify_postcondition(spec.verifier, result)
                result.verification = verification.name
                result.evidence = verification.evidence
                if not verification.ok:
                    result.status, result.error = "ATTENTION", verification.message
        except OSError as exc:
            result.status, result.error = "FAILED", str(exc)
        finally:
            with self._lock:
                self._processes.pop(spec.id, None)
            result.finished_at, result.duration_s = _now(), time.monotonic() - started
        return result

    def cancel(self, action_id: str) -> None:
        with self._lock:
            proc = self._processes.get(action_id)
        if proc:
            self._terminate(action_id, proc)

    def _terminate(self, action_id: str, proc: subprocess.Popen[str]) -> None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
