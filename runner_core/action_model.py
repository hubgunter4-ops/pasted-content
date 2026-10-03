from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


STATUSES = {"AVAILABLE", "RUNNING", "COMPLETED", "FAILED", "TIMEOUT", "CANCELLED", "ATTENTION"}


@dataclass(frozen=True)
class ActionSpec:
    id: str
    label: str
    description: str
    command: List[str]
    cwd: str = "."
    env: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 30
    risk: str = "low"
    requires_confirmation: bool = False
    dependencies: List[str] = field(default_factory=list)
    verifier: Optional[str] = None

    @classmethod
    def from_mapping(cls, value: Dict[str, Any]) -> "ActionSpec":
        required = ("id", "label", "command")
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"missing action fields: {', '.join(missing)}")
        command = value["command"]
        if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
            raise ValueError("command must be a non-empty argv list")
        timeout = int(value.get("timeout_seconds", 30))
        if timeout < 1:
            raise ValueError("timeout_seconds must be positive")
        return cls(
            id=str(value["id"]), label=str(value["label"]),
            description=str(value.get("description", "")), command=command,
            cwd=str(value.get("cwd", ".")), env={str(k): str(v) for k, v in value.get("env", {}).items()},
            timeout_seconds=timeout, risk=str(value.get("risk", "low")),
            requires_confirmation=bool(value.get("requires_confirmation", False)),
            dependencies=[str(x) for x in value.get("dependencies", [])],
            verifier=value.get("verifier"),
        )


@dataclass
class ActionResult:
    action_id: str
    status: str
    exit_code: Optional[int] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_s: float = 0.0
    pid: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    verification: str = "not_run"
    error: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown status: {self.status}")
