from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Iterable, Optional

from .action_model import ActionResult, ActionSpec
from .process_runner import ProcessRunner


class ActionRegistry:
    def __init__(self, specs: Iterable[ActionSpec], runner: Optional[ProcessRunner] = None) -> None:
        self.specs: Dict[str, ActionSpec] = {spec.id: spec for spec in specs}
        self.runner = runner or ProcessRunner()

    def get(self, action_id: str) -> ActionSpec:
        return self.specs[action_id]

    def execute(self, action_id: str, *, dry_run: bool = False, confirmed: bool = False) -> ActionResult:
        spec = self.get(action_id)
        if spec.requires_confirmation and not confirmed:
            return ActionResult(action_id, "ATTENTION", error="explicit confirmation required", verification="not_run")
        return self.runner.run(spec, dry_run=dry_run)

    def cancel(self, action_id: str) -> None:
        self.runner.cancel(action_id)


def load_registry(config_path: Path, repo_root: Path) -> ActionRegistry:
    # The checked-in .yaml is intentionally JSON-compatible to avoid a mandatory parser dependency.
    raw = json.loads(config_path.read_text())
    specs = []
    for item in raw.get("actions", []):
        item = dict(item)
        item["cwd"] = str(repo_root)
        specs.append(ActionSpec.from_mapping(item))
    return ActionRegistry(specs)
