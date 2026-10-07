import asyncio
import os
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

from mcp import Client, StdioServerParameters


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ProtocolSnapshot:
    """Datos observados durante una sesión MCP para validar el protocolo."""

    tools: tuple[Any, ...]
    capabilities: dict[str, Any]
    capabilities_result: Any


Validator = Callable[[ProtocolSnapshot], None]


# Se ejecutan varios validadores por defecto. Para seleccionar un subconjunto:
# MSF_MCP_PROTOCOL_VALIDATORS=tool_inventory,schema_integrity
DEFAULT_VALIDATORS = (
    "tool_inventory",
    "schema_integrity",
    "safe_capabilities",
)


def _tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", ""))


def _input_schema(tool: Any) -> dict[str, Any]:
    """Admite la forma Python del SDK y la forma JSON del protocolo."""
    schema = getattr(tool, "input_schema", None)
    if schema is None:
        schema = getattr(tool, "inputSchema", None)
    return schema if isinstance(schema, dict) else {}


def validate_tool_inventory(snapshot: ProtocolSnapshot) -> None:
    """Comprueba que el servidor publique las herramientas MCP esperadas."""
    names = {_tool_name(tool) for tool in snapshot.tools}
    required = {
        "get_capabilities",
        "health_check",
        "list_hosts",
        "list_services",
        "map_services",
        "scan_target",
        "execute_mapped_module",
        "list_sessions",
        "stop_session",
        "list_jobs",
        "kill_job",
    }
    missing = required - names
    if missing:
        raise AssertionError(f"Faltan herramientas MCP publicadas: {sorted(missing)}")


def validate_schema_integrity(snapshot: ProtocolSnapshot) -> None:
    """Comprueba que cada herramienta exponga un esquema de entrada válido."""
    names: set[str] = set()
    for tool in snapshot.tools:
        name = _tool_name(tool)
        names.add(name)
        schema = _input_schema(tool)
        if not schema:
            raise AssertionError(f"{name} no expone inputSchema como objeto")
        if schema.get("type") != "object":
            raise AssertionError(f"{name} debe declarar inputSchema.type=object")

    if "scan_target" in names:
        scan = next(tool for tool in snapshot.tools if _tool_name(tool) == "scan_target")
        required = set(_input_schema(scan).get("required", []))
        expected = {"target", "authorization_ack"}
        if not expected <= required:
            raise AssertionError(
                "scan_target debe exigir target y authorization_ack en su esquema"
            )

    if "execute_mapped_module" in names:
        execute = next(
            tool
            for tool in snapshot.tools
            if _tool_name(tool) == "execute_mapped_module"
        )
        required = set(_input_schema(execute).get("required", []))
        expected = {"target", "module", "authorization_ack"}
        if not expected <= required:
            raise AssertionError(
                "execute_mapped_module debe exigir target, module y authorization_ack"
            )


def validate_safe_capabilities(snapshot: ProtocolSnapshot) -> None:
    """Comprueba que las capacidades MCP comiencen con operaciones activas desactivadas."""
    payload = snapshot.capabilities
    if payload.get("transport") != "stdio":
        raise AssertionError("El servidor MCP debe anunciar transporte stdio")
    if payload.get("active_operations_enabled") is not False:
        raise AssertionError("Las operaciones activas deben estar desactivadas por defecto")
    if payload.get("credential_tests_enabled") is not False:
        raise AssertionError("Las pruebas de credenciales deben estar desactivadas por defecto")
    if payload.get("exploits_enabled") is not False:
        raise AssertionError("Los exploits deben estar desactivados por defecto")

    policy = payload.get("policy")
    if not isinstance(policy, dict):
        raise AssertionError("get_capabilities debe incluir una política estructurada")
    for key in (
        "target_operations_require_allowlist",
        "target_operations_require_explicit_ack",
        "arbitrary_modules_are_rejected",
        "stdio_stdout_is_reserved_for_mcp",
    ):
        if policy.get(key) is not True:
            raise AssertionError(f"La política MCP debe activar {key}")


def validate_capabilities_result(snapshot: ProtocolSnapshot) -> None:
    """Comprueba el envoltorio estructurado devuelto por tools/call."""
    result = snapshot.capabilities_result
    if getattr(result, "is_error", True):
        raise AssertionError("get_capabilities no debe devolver un error")
    structured = getattr(result, "structured_content", None)
    if not isinstance(structured, dict):
        raise AssertionError("La respuesta MCP debe incluir structured_content")
    payload = structured.get("result", structured)
    if not isinstance(payload, dict) or payload.get("server") != "msf-bridge":
        raise AssertionError("La respuesta de capacidades no identifica msf-bridge")


VALIDATORS: dict[str, Validator] = {
    "tool_inventory": validate_tool_inventory,
    "schema_integrity": validate_schema_integrity,
    "safe_capabilities": validate_safe_capabilities,
    "capabilities_result": validate_capabilities_result,
}


def selected_validators() -> tuple[str, ...]:
    """Devuelve los validadores seleccionados por entorno o los defaults seguros."""
    raw = os.environ.get("MSF_MCP_PROTOCOL_VALIDATORS", "").strip()
    selected = tuple(item.strip() for item in raw.split(",") if item.strip()) if raw else DEFAULT_VALIDATORS
    unknown = sorted(set(selected) - set(VALIDATORS))
    if unknown:
        raise ValueError(
            "Validadores MCP desconocidos: "
            + ", ".join(unknown)
            + ". Disponibles: "
            + ", ".join(VALIDATORS)
        )
    if not selected:
        raise ValueError("Debe seleccionarse al menos un validador MCP")
    return selected


class McpProtocolTests(unittest.TestCase):
    def test_stdio_server_protocol_validators(self):
        async def exercise() -> ProtocolSnapshot:
            params = StdioServerParameters(
                command=sys.executable,
                args=[str(REPO_ROOT / "msf_bridge_mcp.py")],
                env={
                    "PYTHONPATH": str(REPO_ROOT),
                    "MSF_MCP_ALLOWED_TARGETS": "",
                    "MSF_MCP_ENABLE_ACTIVE": "0",
                    "MSF_MCP_ENABLE_CRED_TESTS": "0",
                    "MSF_MCP_ENABLE_EXPLOITS": "0",
                },
            )
            async with Client(params, raise_exceptions=True) as client:
                tools_result = await client.list_tools()
                capabilities_result = await client.call_tool("get_capabilities", {})
                structured = capabilities_result.structured_content or {}
                capabilities = structured.get("result", structured)
                return ProtocolSnapshot(
                    tools=tuple(tools_result.tools),
                    capabilities=capabilities,
                    capabilities_result=capabilities_result,
                )

        snapshot = asyncio.run(exercise())
        for validator_name in selected_validators():
            with self.subTest(validator=validator_name):
                VALIDATORS[validator_name](snapshot)

    def test_validator_selection_rejects_unknown_names(self):
        with patch.dict(
            os.environ,
            {"MSF_MCP_PROTOCOL_VALIDATORS": "tool_inventory,no_such_validator"},
            clear=False,
        ):
            with self.assertRaises(ValueError):
                selected_validators()


if __name__ == "__main__":
    unittest.main()
