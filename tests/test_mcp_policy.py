import os
import unittest
from typing import Callable
from unittest.mock import patch

import msf_bridge_mcp as server


# Todos se ejecutan por defecto. Para una comprobación rápida se puede usar:
# MSF_MCP_POLICY_VALIDATORS=allowlist,flags
DEFAULT_VALIDATORS = (
    "allowlist",
    "scope",
    "flags",
    "default_scope",
)

PolicyValidator = Callable[[], None]


def validate_allowlist() -> None:
    """Valida targets, límites de la allowlist y separación de subdominios."""
    if server._validate_target("192.0.2.10") != "192.0.2.10":
        raise AssertionError("No se aceptó una IP válida")
    if server._validate_target("192.0.2.0/24") != "192.0.2.0/24":
        raise AssertionError("No se aceptó un CIDR válido")
    if server._validate_target("Host.Example.COM.") != "host.example.com":
        raise AssertionError("No se normalizó el FQDN")

    for value in ("192.0.2.10; whoami", "$(id)", "", "host with spaces"):
        try:
            server._validate_target(value)
        except ValueError:
            continue
        raise AssertionError(f"Se aceptó un target inválido: {value!r}")

    with patch.dict(
        os.environ,
        {"MSF_MCP_ALLOWED_TARGETS": "192.0.2.0/24,example.com"},
        clear=False,
    ):
        expected = {
            "192.0.2.10": True,
            "192.0.2.0/25": True,
            "sub.example.com": True,
            "198.51.100.10": False,
            "example.com.evil": False,
        }
        for target, allowed in expected.items():
            if server._target_in_allowlist(target) is not allowed:
                raise AssertionError(
                    f"Resultado inesperado de allowlist para {target}: {allowed}"
                )


def validate_scope() -> None:
    """Valida scopes admitidos y los niveles de módulos permitidos."""
    if set(server.SCOPE_LEVELS) != {"passive", "cred", "full"}:
        raise AssertionError("El catálogo de scopes MCP cambió inesperadamente")

    cases = (
        (1, "passive", True),
        (2, "passive", False),
        (1, "cred", True),
        (2, "cred", True),
        (3, "cred", False),
        (1, "full", True),
        (2, "full", True),
        (3, "full", True),
    )
    for priority, scope, expected in cases:
        actual = server.allowed_for_scope(priority, scope)
        if actual is not expected:
            raise AssertionError(
                f"allowed_for_scope({priority}, {scope!r}) = {actual}; "
                f"se esperaba {expected}"
            )

    with patch.dict(os.environ, {"MSF_MCP_ALLOWED_TARGETS": "192.0.2.0/24"}, clear=False):
        try:
            server._require_authorized(
                "192.0.2.10", "unknown", server.AUTHORIZATION_ACK
            )
        except ValueError:
            pass
        else:
            raise AssertionError("Se aceptó un scope desconocido")


def validate_flags() -> None:
    """Valida defaults seguros y los gates de autorización de operaciones activas."""
    safe_env = {
        "MSF_MCP_ALLOWED_TARGETS": "",
        "MSF_MCP_ENABLE_ACTIVE": "0",
        "MSF_MCP_ENABLE_CRED_TESTS": "0",
        "MSF_MCP_ENABLE_EXPLOITS": "0",
    }
    with patch.dict(os.environ, safe_env, clear=False):
        capabilities = server.get_capabilities()
        for key in (
            "active_operations_enabled",
            "credential_tests_enabled",
            "exploits_enabled",
        ):
            if capabilities[key] is not False:
                raise AssertionError(f"El flag seguro {key} no está desactivado")
        policy = capabilities["policy"]
        if not all(
            policy.get(key) is True
            for key in (
                "target_operations_require_allowlist",
                "target_operations_require_explicit_ack",
                "arbitrary_modules_are_rejected",
            )
        ):
            raise AssertionError("La política no expone todos sus gates obligatorios")

        try:
            server._require_authorized(
                "192.0.2.10", "passive", server.AUTHORIZATION_ACK
            )
        except PermissionError:
            pass
        else:
            raise AssertionError("Una operación activa pasó con ACTIVE=0")

    active_env = {
        "MSF_MCP_ALLOWED_TARGETS": "192.0.2.0/24",
        "MSF_MCP_ENABLE_ACTIVE": "1",
        "MSF_MCP_ENABLE_CRED_TESTS": "0",
        "MSF_MCP_ENABLE_EXPLOITS": "0",
    }
    with patch.dict(os.environ, active_env, clear=False):
        for ack in ("", "wrong-ack"):
            try:
                server._require_authorized("192.0.2.10", "passive", ack)
            except PermissionError:
                continue
            raise AssertionError("Se aceptó una autorización incorrecta")

        try:
            server._require_authorized(
                "198.51.100.10", "passive", server.AUTHORIZATION_ACK
            )
        except PermissionError:
            pass
        else:
            raise AssertionError("Se aceptó un target fuera de allowlist")

        normalized = server._require_authorized(
            "192.0.2.10", "passive", server.AUTHORIZATION_ACK
        )
        if normalized != "192.0.2.10":
            raise AssertionError("No se devolvió el target normalizado")


def validate_default_scope() -> None:
    """Valida el scope configurable y su fallback seguro a passive."""
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("MSF_MCP_DEFAULT_SCOPE", None)
        if server._default_scope() != "passive":
            raise AssertionError("El scope predeterminado debe ser passive")

    for configured in ("passive", "cred", "full"):
        with patch.dict(
            os.environ,
            {"MSF_MCP_DEFAULT_SCOPE": configured},
            clear=False,
        ):
            if server._default_scope() != configured:
                raise AssertionError(f"No se aplicó el scope configurado: {configured}")
            if server._resolve_scope(None) != configured:
                raise AssertionError(f"No se resolvió el scope omitido: {configured}")

    with patch.dict(
        os.environ,
        {"MSF_MCP_DEFAULT_SCOPE": "invalid"},
        clear=False,
    ):
        with unittest.TestCase().assertRaises(ValueError):
            server._default_scope()


VALIDATORS: dict[str, PolicyValidator] = {
    "allowlist": validate_allowlist,
    "scope": validate_scope,
    "flags": validate_flags,
    "default_scope": validate_default_scope,
}


def selected_validators() -> tuple[str, ...]:
    """Selecciona validadores desde entorno o devuelve todos los defaults."""
    raw = os.environ.get("MSF_MCP_POLICY_VALIDATORS", "").strip()
    selected = (
        tuple(item.strip() for item in raw.split(",") if item.strip())
        if raw
        else DEFAULT_VALIDATORS
    )
    unknown = sorted(set(selected) - set(VALIDATORS))
    if unknown:
        raise ValueError(
            "Validadores de política desconocidos: "
            + ", ".join(unknown)
            + ". Disponibles: "
            + ", ".join(VALIDATORS)
        )
    if not selected:
        raise ValueError("Debe seleccionarse al menos un validador de política")
    return selected


class McpPolicyTests(unittest.TestCase):
    def test_policy_validators(self):
        for validator_name in selected_validators():
            with self.subTest(validator=validator_name):
                VALIDATORS[validator_name]()

    def test_validator_selection_rejects_unknown_names(self):
        with patch.dict(
            os.environ,
            {"MSF_MCP_POLICY_VALIDATORS": "allowlist,no_such_validator"},
            clear=False,
        ):
            with self.assertRaises(ValueError):
                selected_validators()

    def test_nmap_policy_allows_small_safe_subset(self):
        self.assertEqual(
            server._validate_nmap_args("-sV -T2 --top-ports 100"),
            "-sV -T2 --top-ports 100",
        )
        self.assertEqual(server._validate_nmap_args(""), "-sV")

    def test_nmap_policy_rejects_scripts_and_arbitrary_output(self):
        for value in ("--script vuln", "-oX /tmp/out.xml", "-p-", "--datadir /tmp"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    server._validate_nmap_args(value)


if __name__ == "__main__":
    unittest.main()
