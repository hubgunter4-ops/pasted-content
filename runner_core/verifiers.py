from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    name: str
    message: str
    evidence: Dict[str, Any]


def verify_postcondition(name: Optional[str], result: Any) -> VerificationResult:
    if not name or name == "exit_code":
        return VerificationResult(result.exit_code == 0, "exit_code", "process exited successfully" if result.exit_code == 0 else "non-zero exit code", {})
    if name == "binaries":
        missing = [item for item in ("python3",) if shutil.which(item) is None]
        return VerificationResult(not missing, name, "required binaries detected" if not missing else f"missing binaries: {missing}", {"missing": missing})
    if name == "json_payload":
        try:
            payload = json.loads(result.stdout)
            ok = isinstance(payload, (dict, list))
        except json.JSONDecodeError:
            ok, payload = False, None
        return VerificationResult(ok, name, "valid JSON payload" if ok else "invalid JSON payload", {"payload_type": type(payload).__name__})
    if name == "rpc_health":
        try:
            payload = json.loads(result.stdout)
            ok = isinstance(payload, dict) and payload.get("rpc_alive") is True
        except json.JSONDecodeError:
            payload, ok = None, False
        return VerificationResult(ok, name, "RPC is healthy" if ok else "RPC did not report healthy", {"payload": payload})
    if name == "report_file":
        path = Path(result.stdout.strip())
        ok = path.is_file() and path.stat().st_size > 0
        return VerificationResult(ok, name, "report exists" if ok else "report file missing or empty", {"path": str(path)})
    if name == "xml_import":
        ok = "xml_path" in result.stdout.lower() or "import" in result.stdout.lower()
        return VerificationResult(ok, name, "scan evidence detected" if ok else "scan evidence missing", {})
    if name in {"rpc_health", "job_confirmed", "session_closed"}:
        ok = bool(result.stdout.strip())
        return VerificationResult(ok, name, "response evidence detected" if ok else "expected response evidence missing", {})
    return VerificationResult(False, "unknown_verifier", f"unknown verifier: {name}", {})
