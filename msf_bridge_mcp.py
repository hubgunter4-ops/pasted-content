#!/usr/bin/env python3
"""MCP server for the authorized MSF Bridge Purple Team workflow.

The server deliberately uses stdio and keeps active operations disabled unless
both an environment policy and an explicit authorization acknowledgement are
present. Never write diagnostic output to stdout: MCP messages use stdout.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shlex
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from mcp.server import MCPServer

from msf_bridge import (
    MODULE_MAP,
    SCOPE_LEVELS,
    MsfConsole,
    MsfRpcError,
    allowed_for_scope,
    run_nmap,
    suggest_modules,
)

LOGGER = logging.getLogger("msf_bridge_mcp")
SERVER_VERSION = "0.1.0"
AUTHORIZATION_ACK = "I_CONFIRM_AUTHORIZED_SCOPE"

mcp = MCPServer("msf-bridge")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _allowed_targets() -> List[str]:
    raw = os.environ.get("MSF_MCP_ALLOWED_TARGETS", "")
    return [item.strip() for item in re.split(r"[,;]", raw) if item.strip()]


def _validate_target(target: str) -> str:
    """Validate one host, FQDN, or CIDR without accepting shell syntax."""
    value = target.strip()
    if not value or len(value) > 253:
        raise ValueError("target debe ser un host, FQDN, IP o CIDR válido")
    if any(char.isspace() for char in value) or any(
        char in value for char in ";&|`$()<>\\\"'"
    ):
        raise ValueError("target contiene caracteres no permitidos")
    value = value.rstrip(".")
    if not value:
        raise ValueError("target debe ser un host, FQDN, IP o CIDR válido")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    if not re.fullmatch(
        r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
        value,
    ):
        raise ValueError("target no es una IP, CIDR o FQDN válido")
    return value.lower().rstrip(".")


def _target_in_allowlist(target: str) -> bool:
    """Return whether target is covered by MSF_MCP_ALLOWED_TARGETS."""
    normalized = _validate_target(target)
    rules = _allowed_targets()
    if not rules:
        return False

    try:
        requested_ip = ipaddress.ip_address(normalized)
    except ValueError:
        requested_ip = None

    try:
        requested_network = ipaddress.ip_network(normalized, strict=False)
    except ValueError:
        requested_network = None

    for rule in rules:
        try:
            rule_network = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            rule_name = rule.lower().lstrip("*.").rstrip(".")
            if requested_ip is None and (
                normalized == rule_name or normalized.endswith("." + rule_name)
            ):
                return True
            continue

        if requested_ip is not None and requested_ip in rule_network:
            return True
        if requested_network is not None and requested_network.subnet_of(rule_network):
            return True
    return False


def _require_authorized(
    target: str,
    scope: str,
    authorization_ack: str,
    *,
    allow_credential_tests: bool = False,
    allow_exploits: bool = False,
) -> str:
    if scope not in SCOPE_LEVELS:
        raise ValueError(f"scope debe ser uno de: {', '.join(SCOPE_LEVELS)}")
    normalized = _validate_target(target)
    if authorization_ack != AUTHORIZATION_ACK:
        raise PermissionError(
            "Se requiere authorization_ack=I_CONFIRM_AUTHORIZED_SCOPE"
        )
    if not _target_in_allowlist(normalized):
        raise PermissionError(
            "El target no está cubierto por MSF_MCP_ALLOWED_TARGETS"
        )
    if not _env_bool("MSF_MCP_ENABLE_ACTIVE", False):
        raise PermissionError(
            "Operaciones activas deshabilitadas; establezca MSF_MCP_ENABLE_ACTIVE=1 "
            "solo durante una ventana autorizada"
        )
    if allow_credential_tests and not _env_bool(
        "MSF_MCP_ENABLE_CRED_TESTS", False
    ):
        raise PermissionError(
            "Las pruebas de credenciales requieren MSF_MCP_ENABLE_CRED_TESTS=1"
        )
    if allow_exploits and not _env_bool("MSF_MCP_ENABLE_EXPLOITS", False):
        raise PermissionError(
            "Los exploits requieren MSF_MCP_ENABLE_EXPLOITS=1 y scope=full"
        )
    return normalized


def _validate_nmap_args(nmap_args: str) -> str:
    """Allow a small, non-scripted Nmap argument subset."""
    try:
        tokens = shlex.split(nmap_args or "-sV")
    except ValueError as exc:
        raise ValueError(f"nmap_args inválido: {exc}") from exc
    if not tokens:
        tokens = ["-sV"]

    allowed_flags = {"-sV", "--version-light", "-Pn", "-T2", "-T3"}
    validated: List[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in allowed_flags:
            validated.append(token)
        elif token == "--top-ports":
            if index + 1 >= len(tokens) or not tokens[index + 1].isdigit():
                raise ValueError("--top-ports requiere un entero")
            ports = int(tokens[index + 1])
            if not 1 <= ports <= 1000:
                raise ValueError("--top-ports debe estar entre 1 y 1000")
            validated.extend([token, str(ports)])
            index += 1
        elif re.fullmatch(r"--top-ports=[0-9]{1,4}", token):
            ports = int(token.split("=", 1)[1])
            if not 1 <= ports <= 1000:
                raise ValueError("--top-ports debe estar entre 1 y 1000")
            validated.append(token)
        else:
            raise ValueError(
                f"Argumento Nmap no permitido por la política MCP: {token}"
            )
        index += 1
    return " ".join(shlex.quote(item) for item in validated)


def _module_metadata(module: str) -> Optional[Dict[str, Any]]:
    for services, port_hint, version_hint, modules in MODULE_MAP:
        for module_name, module_type, priority in modules:
            if module_name == module:
                return {
                    "module": module_name,
                    "type": module_type,
                    "prio": priority,
                    "services": services,
                    "port_hint": port_hint,
                    "version_hint": version_hint,
                }
    return None


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


def _connect() -> MsfConsole:
    """Construct the RPC client; callers own the context manager."""
    return MsfConsole()


@mcp.tool()
def get_capabilities() -> Dict[str, Any]:
    """Describe available MCP tools and the current safety policy.

    This is a local, read-only capability check and does not contact Metasploit.
    """
    return {
        "server": "msf-bridge",
        "version": SERVER_VERSION,
        "transport": "stdio",
        "scopes": SCOPE_LEVELS,
        "authorization_ack_value": AUTHORIZATION_ACK,
        "allowed_targets_configured": bool(_allowed_targets()),
        "active_operations_enabled": _env_bool("MSF_MCP_ENABLE_ACTIVE", False),
        "credential_tests_enabled": _env_bool(
            "MSF_MCP_ENABLE_CRED_TESTS", False
        ),
        "exploits_enabled": _env_bool("MSF_MCP_ENABLE_EXPLOITS", False),
        "policy": {
            "target_operations_require_allowlist": True,
            "target_operations_require_explicit_ack": True,
            "arbitrary_modules_are_rejected": True,
            "stdio_stdout_is_reserved_for_mcp": True,
        },
    }


@mcp.tool()
def health_check() -> Dict[str, Any]:
    """Check whether the configured Metasploit RPC endpoint responds."""
    client = _connect()
    alive = client.is_alive()
    return {
        "rpc_alive": alive,
        "host": client.host,
        "port": client.port,
        "ssl": client.base_url.startswith("https://"),
    }


@mcp.tool()
def list_hosts() -> Dict[str, Any]:
    """List hosts already present in the Metasploit database (read-only)."""
    try:
        with _connect() as client:
            hosts = client.db_hosts()
        return {"hosts": _json_safe(hosts), "count": len(hosts)}
    except MsfRpcError as exc:
        raise RuntimeError(f"Metasploit RPC error: {exc}") from exc


@mcp.tool()
def list_services(host_id: Optional[int] = None) -> Dict[str, Any]:
    """List services in the Metasploit database without scanning or executing."""
    try:
        with _connect() as client:
            services = client.db_services(host_id=host_id)
        return {"services": _json_safe(services), "count": len(services)}
    except MsfRpcError as exc:
        raise RuntimeError(f"Metasploit RPC error: {exc}") from exc


@mcp.tool()
def map_services(scope: str = "passive") -> Dict[str, Any]:
    """Map stored services to candidate Metasploit modules without launching them."""
    if scope not in SCOPE_LEVELS:
        raise ValueError(f"scope debe ser uno de: {', '.join(SCOPE_LEVELS)}")
    try:
        with _connect() as client:
            services = client.db_services()
    except MsfRpcError as exc:
        raise RuntimeError(f"Metasploit RPC error: {exc}") from exc

    plan: List[Dict[str, Any]] = []
    for service in services:
        for candidate in suggest_modules(service):
            if allowed_for_scope(candidate["prio"], scope):
                plan.append(
                    {
                        **candidate,
                        "host": service.get("host") or service.get("address"),
                        "port": service.get("port"),
                        "service": service.get("name", "?"),
                    }
                )
    return {"scope": scope, "plan": _json_safe(plan), "count": len(plan)}


@mcp.tool()
def scan_target(
    target: str,
    authorization_ack: str,
    scope: str = "passive",
    nmap_args: str = "-sV",
    timeout_s: int = 300,
) -> Dict[str, Any]:
    """Run an allowlisted Nmap scan and import its XML into Metasploit.

    This is active network activity even for the passive scope. It requires an
    exact authorization acknowledgement, an environment target allowlist, and
    MSF_MCP_ENABLE_ACTIVE=1. The Nmap argument set excludes scripts, arbitrary
    output paths, NSE execution, and shell syntax.
    """
    normalized = _require_authorized(target, scope, authorization_ack)
    if not 5 <= timeout_s <= 3600:
        raise ValueError("timeout_s debe estar entre 5 y 3600")
    safe_args = _validate_nmap_args(nmap_args)

    xml_path = run_nmap(normalized, extra_args=safe_args, timeout_s=timeout_s)
    if not xml_path:
        return {
            "target": normalized,
            "scope": scope,
            "scan_completed": False,
            "message": "Nmap no generó un XML; revise la telemetría del proceso.",
        }

    try:
        with _connect() as client:
            import_result = client.db_import_nmap_xml(xml_path)
            services = client.db_services()
    except MsfRpcError as exc:
        raise RuntimeError(f"Metasploit RPC error: {exc}") from exc

    return {
        "target": normalized,
        "scope": scope,
        "scan_completed": True,
        "xml_path": xml_path,
        "import_result": _json_safe(import_result),
        "services_count": len(services),
    }


@mcp.tool()
def execute_mapped_module(
    target: str,
    module: str,
    authorization_ack: str,
    scope: str = "cred",
    port: Optional[int] = None,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute one module from the built-in map under explicit policy gates.

    Arbitrary module names are rejected. Credential-testing modules require
    scope=cred or full plus MSF_MCP_ENABLE_CRED_TESTS=1. Exploit modules require
    scope=full plus MSF_MCP_ENABLE_EXPLOITS=1. Every invocation also requires
    the target allowlist, active-operation flag, and exact authorization ack.
    """
    metadata = _module_metadata(module)
    if metadata is None:
        raise ValueError("module no está en el mapa autorizado del proyecto")
    if not allowed_for_scope(metadata["prio"], scope):
        raise PermissionError(f"module no permitido para scope={scope}")

    normalized = _require_authorized(
        target,
        scope,
        authorization_ack,
        allow_credential_tests=metadata["prio"] >= 2,
        allow_exploits=metadata["type"] == "exploit",
    )
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("port debe estar entre 1 y 65535")

    safe_options: Dict[str, Any] = {}
    allowed_options = {
        "RPORT",
        "THREADS",
        "USERNAME",
        "PASSWORD",
        "USER_FILE",
        "PASS_FILE",
        "TARGETURI",
        "SSL",
    }
    for key, value in (options or {}).items():
        key_name = str(key).upper()
        if key_name not in allowed_options:
            raise ValueError(f"opción no permitida: {key}")
        if not isinstance(value, (str, int, float, bool)):
            raise ValueError(f"valor no escalar para opción: {key}")
        if isinstance(value, str) and len(value) > 4096:
            raise ValueError(f"valor demasiado largo para opción: {key}")
        safe_options[key_name] = value

    safe_options["RHOSTS"] = normalized
    if port is not None:
        safe_options["RPORT"] = port
    threads = int(safe_options.get("THREADS", 1))
    if not 1 <= threads <= 10:
        raise ValueError("THREADS debe estar entre 1 y 10")
    safe_options["THREADS"] = threads

    try:
        with _connect() as client:
            result = client.execute_module(metadata["type"], module, safe_options)
    except MsfRpcError as exc:
        raise RuntimeError(f"Metasploit RPC error: {exc}") from exc

    return {
        "target": normalized,
        "scope": scope,
        "module": module,
        "module_type": metadata["type"],
        "priority": metadata["prio"],
        "result": _json_safe(result),
    }


@mcp.tool()
def list_sessions() -> Dict[str, Any]:
    """List session metadata for hygiene review; command output is not returned."""
    try:
        with _connect() as client:
            sessions = client.sessions_list()
        records = [asdict(session) for session in sessions]
        return {"sessions": _json_safe(records), "count": len(records)}
    except MsfRpcError as exc:
        raise RuntimeError(f"Metasploit RPC error: {exc}") from exc


@mcp.tool()
def stop_session(session_id: int, authorization_ack: str) -> Dict[str, Any]:
    """Stop one session after verifying it belongs to an allowlisted target."""
    if authorization_ack != AUTHORIZATION_ACK:
        raise PermissionError(
            "Se requiere authorization_ack=I_CONFIRM_AUTHORIZED_SCOPE"
        )
    try:
        with _connect() as client:
            sessions = client.sessions_list()
            session = next((item for item in sessions if item.id == session_id), None)
            if session is None:
                raise ValueError(f"No existe la sesión {session_id}")
            if not session.target_host or not _target_in_allowlist(session.target_host):
                raise PermissionError(
                    "La sesión no pertenece a un target cubierto por la allowlist"
                )
            stopped = client.session_stop(session_id)
        return {"session_id": session_id, "stopped": stopped}
    except MsfRpcError as exc:
        raise RuntimeError(f"Metasploit RPC error: {exc}") from exc


@mcp.tool()
def list_jobs() -> Dict[str, Any]:
    """List Metasploit jobs for defensive monitoring and cleanup."""
    try:
        with _connect() as client:
            jobs = client.jobs()
        return {"jobs": _json_safe(jobs), "count": len(jobs)}
    except MsfRpcError as exc:
        raise RuntimeError(f"Metasploit RPC error: {exc}") from exc


@mcp.tool()
def kill_job(job_id: int, authorization_ack: str) -> Dict[str, Any]:
    """Stop one Metasploit job after an explicit operator acknowledgement."""
    if authorization_ack != AUTHORIZATION_ACK:
        raise PermissionError(
            "Se requiere authorization_ack=I_CONFIRM_AUTHORIZED_SCOPE"
        )
    if job_id < 0:
        raise ValueError("job_id debe ser un entero no negativo")
    try:
        with _connect() as client:
            killed = client.kill_job(job_id)
        return {"job_id": job_id, "killed": killed}
    except MsfRpcError as exc:
        raise RuntimeError(f"Metasploit RPC error: {exc}") from exc


def main() -> None:
    """Run the MCP server over stdio; diagnostics go to stderr only."""
    logging.basicConfig(
        level=os.environ.get("MSF_MCP_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    LOGGER.info("MSF Bridge MCP server %s starting on stdio", SERVER_VERSION)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
