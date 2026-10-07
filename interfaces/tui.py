#!/usr/bin/env python3
"""Terminal UI local para MSF Bridge.

La TUI no habilita operaciones activas. Las acciones con riesgo requieren
parámetros y confirmación explícita desde el adaptador CLI o un host MCP.
"""

from __future__ import annotations

import argparse
import curses
import json
import os
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class TuiAction:
    action_id: str
    label: str
    group: str
    risk: str
    description: str
    status: str = "READY"


ACTIONS = (
    TuiAction("get-capabilities", "Get capabilities", "Prepare", "LOW", "Inspect the effective MCP policy without contacting Metasploit."),
    TuiAction("guided-preflight", "Guided preflight", "Prepare", "LOW", "Show the safe operator checklist."),
    TuiAction("health-check", "Health check", "Observe", "LOW", "Check the configured RPC endpoint."),
    TuiAction("list-services", "List services", "Observe", "LOW", "Read services already stored in the Metasploit database."),
    TuiAction("map-services", "Map services", "Observe", "LOW", "Map stored services to authorized modules without launching them."),
    TuiAction("scan-target", "Scan target", "Operate", "HIGH", "Requires target, allowlist, acknowledgement and active flag."),
    TuiAction("execute-mapped-module", "Execute mapped module", "Operate", "HIGH", "Requires mapped module, scope, acknowledgement and risk flags."),
    TuiAction("list-sessions", "List sessions", "Maintain", "LOW", "Review session metadata without returning command output."),
    TuiAction("list-jobs", "List jobs", "Maintain", "LOW", "Review running jobs for cleanup."),
    TuiAction("stop-session", "Stop session", "Maintain", "HIGH", "Cleanup action requiring explicit acknowledgement."),
    TuiAction("kill-job", "Kill job", "Maintain", "HIGH", "Cleanup action requiring explicit acknowledgement."),
)


def default_scope() -> str:
    value = os.environ.get("MSF_MCP_DEFAULT_SCOPE", "passive").strip().lower()
    return value if value in {"passive", "cred", "full"} else "INVALID"


def policy_state() -> tuple[str, str, str]:
    active = os.environ.get("MSF_MCP_ENABLE_ACTIVE", "0").strip().lower()
    active_label = "ENABLED" if active in {"1", "true", "yes", "on"} else "DISABLED"
    targets = "CONFIGURED" if os.environ.get("MSF_MCP_ALLOWED_TARGETS", "").strip() else "EMPTY"
    return active_label, targets, default_scope()


def _clip(value: str, width: int) -> str:
    if width <= 1:
        return ""
    return value if len(value) <= width else value[: width - 1] + "…"


def render_lines(
    width: int = 118,
    height: int = 34,
    selected: int = 0,
    status: str = "Ready. Select an action; Enter opens a safe detail view.",
) -> list[str]:
    """Render a deterministic text frame for curses and snapshot mode."""
    active, allowlist, scope = policy_state()
    lines: list[str] = []
    inner = max(60, width - 4)
    lines.append("╔" + "═" * inner + "╗")
    lines.append("║ " + _clip("MSF BRIDGE  /  PURPLE TEAM OPERATIONS", inner - 1).ljust(inner - 1) + "║")
    lines.append("║ " + _clip("LOCAL TUI  •  MCP stdio  •  SAFE DEFAULTS", inner - 1).ljust(inner - 1) + "║")
    lines.append("╠" + "═" * inner + "╣")
    summary = f" TRANSPORT stdio | RPC 127.0.0.1:55553 | ACTIVE {active} | ALLOWLIST {allowlist} | SCOPE {scope}"
    lines.append("║" + _clip(summary, inner).ljust(inner) + "║")
    lines.append("╠" + "═" * inner + "╣")
    lines.append("║ " + _clip("RUNBOOK", 27).ljust(27) + "│ " + _clip("DETAIL", inner - 31).ljust(inner - 31) + "║")
    lines.append("║ " + "─" * 27 + "┼" + "─" * (inner - 31) + "║")

    detail = ACTIONS[selected]
    for index, action in enumerate(ACTIONS):
        marker = "▶" if index == selected else " "
        risk = "!" if action.risk == "HIGH" else "·"
        item = f"{marker} {risk} {action.label}"
        left = _clip(item, 25).ljust(25)
        lines.append("║ " + left + "  │" + " " * (inner - 29) + "║")
        if index == selected:
            detail_lines = [
                f" {detail.group.upper()} / {detail.risk} RISK",
                f" {detail.label}",
                "",
                *textwrap.wrap(detail.description, width=max(20, inner - 37)),
                "",
                f" Status: {detail.status}",
                "",
                " Enter  inspect     ↑/↓  navigate     r  refresh     q  quit",
            ]
            for dline in detail_lines:
                lines[-1] = lines[-1][:-1] + "║"
                lines.append("║ " + " " * 28 + "│" + _clip(dline, inner - 31).ljust(inner - 31) + "║")
    lines.append("╠" + "═" * inner + "╣")
    lines.append("║ " + _clip("STATUS  " + status, inner - 1).ljust(inner - 1) + "║")
    lines.append("╚" + "═" * inner + "╝")
    return lines[: max(1, height)]


def _safe_detail(action: TuiAction) -> str:
    if action.action_id == "get-capabilities":
        try:
            import msf_bridge_mcp as server

            return json.dumps(server.get_capabilities(), indent=2, sort_keys=True)
        except Exception as exc:  # pragma: no cover - depends on local install
            return f"Capabilities unavailable: {exc}"
    if action.action_id == "guided-preflight":
        try:
            import msf_bridge_mcp as server

            return server.guided_flow()
        except Exception as exc:  # pragma: no cover
            return f"Preflight unavailable: {exc}"
    if action.risk == "HIGH":
        return (
            f"{action.label}\n\nThis action is intentionally not launched from the TUI.\n"
            "Provide target, scope and acknowledgement through the verified CLI/MCP flow.\n"
            "Active operations remain disabled unless explicitly enabled in the environment."
        )
    return f"{action.label}\n\n{action.description}\n\nUse the verified CLI/MCP adapter to execute this action."


def run_snapshot(width: int = 118, height: int = 34) -> int:
    print("\n".join(render_lines(width=width, height=height)))
    return 0


def run_curses(stdscr: object) -> int:
    curses.curs_set(0)
    stdscr.keypad(True)
    try:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)
    except curses.error:
        pass

    selected = 0
    status = "Ready. Select an action; Enter opens a safe detail view."
    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        lines = render_lines(width=max(80, width), height=max(10, height - 1), selected=selected, status=status)
        for row, line in enumerate(lines):
            if row >= height - 1:
                break
            try:
                stdscr.addnstr(row, 0, line, max(1, width - 1), curses.color_pair(1) if row < 4 else 0)
            except curses.error:
                pass
        stdscr.refresh()
        key = stdscr.getch()
        if key in (ord("q"), ord("Q"), 27):
            return 0
        if key in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(ACTIONS)
        elif key in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(ACTIONS)
        elif key in (ord("r"), ord("R")):
            status = f"Refreshed. Active={policy_state()[0]}, allowlist={policy_state()[1]}, scope={policy_state()[2]}"
        elif key in (curses.KEY_ENTER, 10, 13):
            detail = _safe_detail(ACTIONS[selected])
            status = detail.replace("\n", " ")[: max(20, width - 14)]


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MSF Bridge local terminal UI")
    parser.add_argument("--snapshot", action="store_true", help="print a deterministic frame and exit")
    parser.add_argument("--width", type=int, default=118)
    parser.add_argument("--height", type=int, default=34)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.snapshot:
        return run_snapshot(args.width, args.height)
    return curses.wrapper(run_curses)


if __name__ == "__main__":
    raise SystemExit(main())
