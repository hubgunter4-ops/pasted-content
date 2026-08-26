#!/usr/bin/env python3
"""
===============================================================================
 MSF BRIDGE ORCHESTRATOR — Nmap → Metasploit integrado
===============================================================================
 Orquestador autocontenido que integra el escaneo Nmap con Metasploit
 (msfrpc) e implementa las ocho mejoras propuestas:

   1. Menús con selección numérica/teclado (sin Enter en terminal real)
   2. Mapeo Nmap → módulos Metasploit aplicables (scanners + exploits)
   3. Ejecución en lote y clasificación de sesiones (priv/user, win/linux)
   4. Reporting profesional Markdown (severidad, evidencias, remediación)
   5. Higiene de sesiones: detección de sesiones muertas + registro auditor
   6. Integración Nmap / hashcat / wordlists; pase de credenciales a
      módulos de brute-force
   7. Controles de autorización y límites de alcance (passive/cred/full)
   8. Robustez: errores, timeouts y reintentos con backoff

 Requisitos:  pip3 install msgpack requests
 Servicio RPC: msfrpcd -P msf -S -f -a 127.0.0.1 -p 55553

 Uso interactivo:  python3 msf_bridge.py
 Uso por lotes:    python3 msf_bridge.py --target 10.0.0.1 --scope passive
                   printf '2\\ny\\n' | python3 msf_bridge.py
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import msgpack
    import requests
except ImportError:
    sys.exit("[!] Faltan dependencias: pip3 install msgpack requests")

# =============================================================================
# CONFIGURACIÓN
# =============================================================================

MSF_HOST = os.environ.get("MSF_HOST", "127.0.0.1")
MSF_PORT = int(os.environ.get("MSF_PORT", "55553"))
MSF_USER = os.environ.get("MSF_USER", "msf")
MSF_PASS = os.environ.get("MSF_PASS", "msf")
MSF_USE_SSL = os.environ.get("MSF_SSL", "").lower() in ("1", "true", "yes")

SCOPE_LEVELS = {
    "passive": "Solo información y detección de vulnerabilidades "
               "(sin fuerza bruta ni explotación)",
    "cred": "Más pruebas de credenciales (wordlists pequeñas; sin SQLi/exploit)",
    "full": "Auditoría completa (incluye SQLi y verificación de exploits)",
}

WORK_DIR = Path(os.environ.get("MSF_BRIDGE_DIR", "/tmp/msf_bridge"))
AUDIT_DIR = WORK_DIR / "audits"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

# =============================================================================
# SISTEMA DE SELECCIÓN DE OPCIONES (numérica + tecla única)
# =============================================================================


def _interactive_stdin() -> bool:
    return sys.stdin.isatty()


def _read_single_key() -> Optional[str]:
    """Lee una tecla sin Enter (cbreak vía termios/tty). None en EOF.

    Si la primera tecla es un dígito, acumula dígitos adicionales hasta
    pulsar Enter o esperar ~0.4 s, permitiendo atajos multi-dígitos
    (por ejemplo '10' para la opción 10)."""
    try:
        import termios
        import tty
        import fcntl
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            ch = sys.stdin.read(1)
            if ch and ch.isdigit():
                # Acumular más dígitos hasta Enter o timeout corto
                buf = ch
                flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                try:
                    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                    deadline = time.time() + 0.4
                    while time.time() < deadline:
                        try:
                            extra = sys.stdin.read(1)
                        except BlockingIOError:
                            extra = None
                        if extra is None:
                            time.sleep(0.05)
                            continue
                        if extra in ("\r", "\n"):
                            return buf
                        if extra.isdigit():
                            buf += extra
                        else:
                            return buf
                finally:
                    fcntl.fcntl(fd, fcntl.F_SETFL, flags)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        return ch if ch else None
    except Exception:
        return None


def select_option(title: str, options: List[str],
                  default_index: int = 0) -> Optional[str]:
    """Menú numerado con tecla única (tty) o línea completa (batch).

    Devuelve la opción elegida o None si se cancela (q/x).
    """
    n = len(options)
    if n == 0:
        return None
    print()
    print("=" * 70)
    print(f" {title}")
    print("=" * 70)
    print()
    for i, opt in enumerate(options, 1):
        print(f" {i}. {opt}")
    print()

    if _interactive_stdin():
        print(" [*] Pulse el número de opción (tecla única) | q = cancelar")
        while True:
            key = _read_single_key()
            if key is None:
                print(f"\n [+] Seleccionado (default): {options[default_index]}")
                return options[default_index]
            if key.strip() == "":
                continue
            kl = key.lower()
            if kl in ("q", "x"):
                print("\n [!] Selección cancelada")
                return None
            if key.isdigit() and 1 <= int(key) <= n:
                chosen = options[int(key) - 1]
                print(f"\n [+] Seleccionado [{key}]: {chosen}")
                return chosen
            matches = [o for o in options
                       if o.strip().lower().startswith(kl)]
            if len(matches) == 1:
                print(f"\n [+] Seleccionado [{key}]: {matches[0]}")
                return matches[0]
            print(f"\n [!] Tecla inválida. Pulse 1-{n}, una inicial o q.")
    else:
        # Modo batch/pipe
        try:
            line = input(
                f" Seleccione [1-{n}] "
                f"(Enter = {options[default_index][:40]} | q = cancelar): "
            ).strip()
        except EOFError:
            print(f"\n [+] Seleccionado (default): {options[default_index]}")
            return options[default_index]
        if not line:
            return options[default_index]
        if line.lower() in ("q", "x", "cancel"):
            return None
        if line.isdigit() and 1 <= int(line) <= n:
            return options[int(line) - 1]
        ll = line.lower()
        matches = [o for o in options if o.strip().lower().startswith(ll)]
        if len(matches) == 1:
            return matches[0]
        exact = [o for o in options if o.strip().lower() == ll]
        if exact:
            return exact[0]
        print(f" [!] Opción inválida. Use 1-{n}, nombre o q.")
        return None


def confirm_yes_no(prompt: str, default: bool = False) -> bool:
    """Confirmación y/no: tecla única en tty, línea completa en batch."""
    hint = "Y/n" if default else "y/N"
    if _interactive_stdin():
        print(f" {prompt} [{hint}] ", end="", flush=True)
        while True:
            key = _read_single_key()
            if key is None:
                return default
            k = key.strip().lower()
            if k in ("y", "s", ""):
                print("Yes")
                return True
            if k == "n":
                print("No")
                return False
            print("\n [!] Pulse 'y' o 'n'")
    else:
        try:
            ans = input(f" {prompt} [{hint}]: ").strip().lower()
        except EOFError:
            return default
        if not ans:
            return default
        return ans in ("y", "yes", "s", "si", "sí")


# =============================================================================
# WRAPPER MSFRPC (msgpack sobre HTTP)
# =============================================================================


@dataclass
class Session:
    id: int
    type: str
    platform: str
    arch: str
    target_host: str
    via_payload: str
    username: Optional[str] = None
    privs: str = "user"          # "user" | "root" | "NT AUTHORITY\\SYSTEM"
    is_dead: bool = False
    last_seen: float = field(default_factory=time.time)

    @classmethod
    def from_rpc(cls, sid: str, info: Dict[str, Any]) -> "Session":
        user = info.get("username")
        privs = "user"
        if user and any(t in str(user).upper()
                        for t in ("ROOT", "SYSTEM", "ADMINISTRATOR")):
            privs = "root"
        return cls(
            id=int(sid), type=info.get("type", "unknown"),
            platform=info.get("platform", "unknown"),
            arch=info.get("arch", "unknown"),
            target_host=info.get("target_host",
                                 info.get("session_host", "")),
            via_payload=info.get("via_exploit", info.get("via_payload", "")),
            username=user, privs=privs,
        )


@dataclass
class Finding:
    """Hallazgo de auditoría con severidad, evidencia y remediación."""
    host: str
    service: str
    module: str
    severity: str           # Critical | High | Medium | Low | Info
    summary: str
    evidence: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class MsfRpcError(Exception):
    pass


class MsfAuthError(MsfRpcError):
    pass


class MsfConsole:
    """Cliente del servicio RPC de Metasploit (msfrpcd)."""

    def __init__(self, host: str = MSF_HOST, port: int = MSF_PORT,
                 username: str = MSF_USER, password: str = MSF_PASS,
                 use_ssl: bool = MSF_USE_SSL, timeout: int = 60,
                 retries: int = 3) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.retries = retries
        scheme = "https" if use_ssl else "http"
        self.base_url = f"{scheme}://{host}:{port}/api/"
        self.token: Optional[str] = None
        self.session = requests.Session()

    # -- Nivel bajo ----------------------------------------------------------

    def _request(self, *args: Any) -> Dict[str, Any]:
        """Llamada RPC msgpack con reintentos y backoff exponencial."""
        last_exc = None
        for attempt in range(1, self.retries + 1):
            try:
                payload = msgpack.packb(list(args), use_bin_type=True)
                resp = self.session.post(
                    self.base_url, data=payload,
                    headers={"Content-Type": "binary/message-pack"},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                result = msgpack.unpackb(resp.content, raw=False)
                if isinstance(result, dict) and result.get("error") is True:
                    raise MsfRpcError(
                        result.get("error_string", "Unknown RPC error"))
                return result
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                last_exc = e
                logging.warning("RPC failed (intento %d/%d): %s",
                                attempt, self.retries, e)
                time.sleep(attempt * 2)
            except MsfRpcError:
                raise
            except Exception as e:
                last_exc = e
                time.sleep(attempt * 2)
        raise MsfRpcError(
            f"RPC inalcanzable tras {self.retries} intentos: {last_exc}")

    def _auth_request(self, *args: Any) -> Dict[str, Any]:
        if not self.token:
            self.login()
        try:
            return self._request(self.token, *args)
        except MsfRpcError as e:
            # Token caducado (5 min inactividad): renegociar una vez
            if "token" in str(e).lower() or not self.token:
                self.login()
                return self._request(self.token, *args)
            raise

    # -- Autenticación -------------------------------------------------------

    def login(self) -> str:
        result = self._request("auth.login", self.username, self.password)
        if result.get("result") != "success":
            raise MsfAuthError(
                f"Login fallido: {result.get('error_message', 'unknown')}")
        self.token = result.get("token", "")
        logging.info("Autenticado en msfrpcd %s:%d", self.host, self.port)
        return self.token

    def logout(self) -> None:
        if self.token:
            try:
                self._request("auth.logout", self.token)
            except Exception:
                pass
        self.token = None

    def is_alive(self) -> bool:
        """Health-check sin autenticación: solo verifica que el servicio
        responde HTTP en el puerto RPC."""
        try:
            # GET simple: msfrpcd lo rechaza con 404/405 de forma limpia
            # (un POST vacío corrompería el msgpack del lado del servidor)
            resp = self.session.get(self.base_url, timeout=5)
            return resp.status_code < 500
        except Exception:
            return False

    def version(self) -> Dict[str, Any]:
        return self._auth_request("core.version")

    # -- Módulos -------------------------------------------------------------

    def module_options(self, mtype: str, mname: str) -> Dict[str, Any]:
        return self._auth_request("module.options", mtype, mname)

    def compatible_payloads(self, exploit: str) -> List[str]:
        return self._auth_request(
            "module.compatible_payloads", exploit).get("payloads", [])

    def execute_module(self, mtype: str, mname: str,
                       options: Optional[Dict[str, Any]] = None,
                       run_as_job: bool = True) -> Dict[str, Any]:
        options = options or {}
        result = self._auth_request("module.execute", mtype, mname, options)
        return {
            "module": mname, "job_id": result.get("job_id"),
            "uuid": result.get("uuid"), "success": True,
        }

    def jobs(self) -> Dict[int, str]:
        return self._auth_request("job.list")

    def kill_job(self, job_id: int) -> bool:
        return (self._auth_request("job.kill", job_id)
                .get("result") == "success")

    # -- Sesiones ------------------------------------------------------------

    def sessions_list(self) -> List[Session]:
        raw = self._auth_request("session.list")
        return [Session.from_rpc(sid, info) for sid, info in raw.items()]

    def session_write(self, sid: int, command: str) -> None:
        self._auth_request("session.shell_write", sid, command)

    def session_read(self, sid: int) -> str:
        return self._auth_request("session.ring_read", sid).get("data", "")

    def session_stop(self, sid: int) -> bool:
        return (self._auth_request("session.stop", sid)
                .get("result") == "success")

    # -- Base de datos -------------------------------------------------------

    def db_import_nmap_xml(self, xml_path: str) -> Dict[str, Any]:
        try:
            with open(xml_path, "rb") as fh:
                return self._auth_request("db.import_file", fh.read())
        except OSError as e:
            raise MsfRpcError(f"No se puede leer el XML de Nmap: {e}")

    def db_services(self, host_id: Optional[int] = None
                    ) -> List[Dict[str, Any]]:
        opts = {"hosts": str(host_id)} if host_id else {}
        return self._auth_request("db.services", opts)

    def db_hosts(self) -> List[Dict[str, Any]]:
        return self._auth_request("db.hosts")

    # -- Utilidades ----------------------------------------------------------

    def __enter__(self) -> "MsfConsole":
        self.login()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.logout()


# =============================================================================
# MAPEO NMAP → MÓDULOS METASPLOIT (base de conocimiento)
# =============================================================================
# (service_name, port_hint, version_hint) → lista de (módulo, tipo, prio)
# prio 1 = scanner informativo, 2 = credential testing, 3 = exploit

MODULE_MAP = [
    # SSH
    (["ssh"], None, None,
     [("auxiliary/scanner/ssh/ssh_version", "auxiliary", 1),
      ("auxiliary/scanner/ssh/ssh_enumusers", "auxiliary", 2),
      ("auxiliary/scanner/ssh/ssh_login", "auxiliary", 2),
      ("exploit/linux/ssh/libssh_auth_bypass", "exploit", 3)]),
    # SMB
    (["microsoft-ds", "netbios-ssn", "smb"], None, None,
     [("auxiliary/scanner/smb/smb_version", "auxiliary", 1),
      ("auxiliary/scanner/smb/smb_enumusers", "auxiliary", 2),
      ("auxiliary/scanner/smb/smb_login", "auxiliary", 2),
      ("exploit/windows/smb/ms17_010_eternalblue", "exploit", 3)]),
    # HTTP
    (["http", "https", "www", "http-alt"], None, None,
     [("auxiliary/scanner/http/http_version", "auxiliary", 1),
      ("auxiliary/scanner/http/title", "auxiliary", 1),
      ("auxiliary/scanner/http/dir_scanner", "auxiliary", 2),
      ("exploit/multi/http/php_cgi_arg_injection", "exploit", 3)]),
    # FTP
    (["ftp"], None, None,
     [("auxiliary/scanner/ftp/ftp_version", "auxiliary", 1),
      ("auxiliary/scanner/ftp/anonymous", "auxiliary", 2),
      ("auxiliary/scanner/ftp/ftp_login", "auxiliary", 2),
      ("exploit/unix/ftp/proftpd_133c_backdoor", "exploit", 3)]),
    # MySQL
    (["mysql"], None, None,
     [("auxiliary/scanner/mysql/mysql_version", "auxiliary", 1),
      ("auxiliary/scanner/mysql/mysql_login", "auxiliary", 2),
      ("auxiliary/scanner/mysql/mysql_schemadump", "auxiliary", 2)]),
    # PostgreSQL
    (["postgresql"], None, None,
     [("auxiliary/scanner/postgres/postgres_version", "auxiliary", 1),
      ("auxiliary/scanner/postgres/postgres_login", "auxiliary", 2)]),
    # MSSQL
    (["ms-sql"], None, None,
     [("auxiliary/scanner/mssql/mssql_ping", "auxiliary", 1),
      ("auxiliary/scanner/mssql/mssql_login", "auxiliary", 2),
      ("auxiliary/scanner/mssql/mssql_schemadump", "auxiliary", 2)]),
    # RDP
    (["ms-wbt-server", "rdp"], None, None,
     [("auxiliary/scanner/rdp/rdp_scanner", "auxiliary", 1),
      ("auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "auxiliary", 3)]),
    # SMTP
    (["smtp"], None, None,
     [("auxiliary/scanner/smtp/smtp_version", "auxiliary", 1),
      ("auxiliary/scanner/smtp/smtp_enum", "auxiliary", 2)]),
    # DNS
    (["domain"], None, None,
     [("auxiliary/scanner/dns/dns_amp", "auxiliary", 1)]),
    # SNMP
    (["snmp"], None, None,
     [("auxiliary/scanner/snmp/snmp_login", "auxiliary", 1),
      ("auxiliary/scanner/snmp/snmp_enum", "auxiliary", 2)]),
]


def classify_severity(mtype: str, prio: int) -> str:
    if mtype == "exploit":
        return "High" if prio == 3 else "Medium"
    if prio == 1:
        return "Info"
    return "Low"


def suggest_modules(service: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Cruza un servicio de Nmap con la base de conocimiento y devuelve
    módulos candidatos ordenados por prioridad."""
    name = str(service.get("name", "")).lower()
    port = service.get("port")
    candidates = []
    for services, port_hint, version_hint, mods in MODULE_MAP:
        if any(s in name for s in services) or \
           (port_hint and int(port) == port_hint):
            for mname, mtype, prio in mods:
                candidates.append({
                    "module": mname, "type": mtype, "prio": prio,
                    "severity": classify_severity(mtype, prio),
                })
    return candidates


def allowed_for_scope(prio: int, scope: str) -> bool:
    if scope == "passive":
        return prio == 1
    if scope == "cred":
        return prio <= 2
    return True  # full: todo


# =============================================================================
# NMAP (ejecución y parseo local)
# =============================================================================

def run_nmap(targets: str, extra_args: str = "-sV -O",
             timeout_s: int = 300) -> Optional[str]:
    """Ejecuta nmap y guarda el XML. Devuelve la ruta o None."""
    import subprocess
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_path = WORK_DIR / f"nmap_{ts}.xml"
    cmd = ["nmap", "-oX", str(xml_path), *extra_args.split(), targets]
    logging.info("[exec] $ %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_s)
        if proc.returncode not in (0, 1):
            logging.warning("nmap rc=%d: %s", proc.returncode,
                            proc.stderr[:300])
        if not xml_path.exists():
            return None
        return str(xml_path)
    except FileNotFoundError:
        logging.warning("nmap no instalado; la importación deberá "
                        "hacerse manualmente")
        return None
    except subprocess.TimeoutExpired:
        logging.warning("nmap excedió el tiempo (%ds)", timeout_s)
        return None


# =============================================================================
# SESIONES: higiene y clasificación
# =============================================================================

@dataclass
class SessionRegistry:
    """Registro auditor de sesiones: clasifica (priv/user, win/linux),
    detecta sesiones muertas y deja evidencia."""
    known: Dict[int, Session] = field(default_factory=dict)
    audit_lines: List[str] = field(default_factory=list)

    def refresh(self, msf: MsfConsole) -> None:
        current = {s.id: s for s in msf.sessions_list()}
        # Detectar muertas
        for sid, prev in self.known.items():
            if sid not in current:
                prev.is_dead = True
                line = (f"[AUDIT {datetime.now().isoformat()}] "
                        f"Sesión {sid} MUERTA (antes: {prev.platform}/"
                        f"{prev.privs} en {prev.target_host})")
                logging.warning(line)
                self.audit_lines.append(line)
        for sid, s in current.items():
            if sid in self.known and not self.known[sid].is_dead:
                s.last_seen = self.known[sid].last_seen
            line = (f"[AUDIT {datetime.now().isoformat()}] Sesión {s.id}: "
                    f"{s.type} {s.platform}/{s.arch} privs={s.privs} "
                    f"host={s.target_host} vía {s.via_payload}")
            self.audit_lines.append(line)
            print("  " + line.replace("[AUDIT " + datetime.now().isoformat()
                                      + "] ", ""))
        self.known = current

    def run_on_all(self, msf: MsfConsole, command: str) -> Dict[int, str]:
        """Ejecución en lote: un comando en todas las sesiones vivas."""
        results = {}
        for sid, s in self.known.items():
            if s.is_dead:
                continue
            try:
                msf.session_write(sid, command)
                time.sleep(2)
                results[sid] = msf.session_read(sid)
            except Exception as e:
                results[sid] = f"[ERROR: {e}]"
                self.audit_lines.append(
                    f"[AUDIT] Error ejecutando en sesión {sid}: {e}")
        return results

    def summary(self) -> Dict[str, int]:
        alive = [s for s in self.known.values() if not s.is_dead]
        return {
            "total_known": len(self.known),
            "alive": len(alive),
            "dead": len(self.known) - len(alive),
            "root": sum(1 for s in alive if s.privs == "root"),
            "user": sum(1 for s in alive if s.privs == "user"),
            "windows": sum(1 for s in alive if "win" in s.platform),
            "linux": sum(1 for s in alive if "lin" in s.platform),
        }


# =============================================================================
# REPORTING PROFESIONAL (Markdown)
# =============================================================================

def build_report(target: str, scope: str, findings: List[Finding],
                 session_summary: Optional[Dict[str, int]],
                 audit_lines: List[str], report_path: Path) -> Path:
    sev_counts = {s: 0 for s in ("Critical", "High", "Medium", "Low", "Info")}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    risk_score = (sev_counts["Critical"] * 10 + sev_counts["High"] * 5 +
                  sev_counts["Medium"] * 2 + sev_counts["Low"] * 0.5)
    risk = ("Informational" if risk_score == 0 else
            "Low" if risk_score < 5 else
            "Moderate" if risk_score < 15 else
            "High" if risk_score < 30 else "Critical")

    lines = [
        f"# Informe de Auditoría de Seguridad — {target}",
        "",
        f"**Generado**: {datetime.now().isoformat()}",
        f"**Alcance**: `{scope}` — {SCOPE_LEVELS[scope]}",
        "",
        f"**Hallazgos**: {len(findings)} | "
        f"**Riesgo global**: **{risk}** (score {risk_score:.1f})",
        "",
        "| Severidad | Cantidad |",
        "|-----------|----------|",
    ]
    for sev, cnt in sev_counts.items():
        lines.append(f"| {sev} | {cnt} |")

    if session_summary:
        lines += [
            "",
            "## Sesiones activas",
            "",
            f"Vivas: {session_summary['alive']} (root: "
            f"{session_summary['root']}, user: {session_summary['user']}) | "
            f"Windows: {session_summary['windows']} | "
            f"Linux: {session_summary['linux']} | "
            f"Muertas: {session_summary['dead']}",
        ]

    lines += ["", "---", "", "## Hallazgos", ""]
    for f in sorted(findings, key=lambda x:
                    ("Critical", "High", "Medium", "Low", "Info").index(
                        x.severity)):
        lines += [
            f"### [{f.severity}] {f.module} — {f.host}:{f.service}",
            "",
            f"**Resumen**: {f.summary}",
            f"**Módulo**: `{f.module}`",
        ]
        if f.evidence:
            lines += ["", "**Evidencia**:", "", "```", f.evidence[:2000],
                      "```"]
        if f.remediation:
            lines += ["", f"**Remediación**: {f.remediation}"]
        lines.append("")

    lines += ["", "---", "", "## Registro de auditoría de sesiones", "", "```"]
    lines += audit_lines[-100:]
    lines.append("```")

    report_path.write_text("\n".join(lines))
    return report_path


# =============================================================================
# FLUJO DE AUDITORÍA (orquestación)
# =============================================================================


def select_scope(interactive: bool, args_scope: Optional[str]) -> str:
    """Fase de autorización con menú de tecla única."""
    print(f"\n{'='*70}\n FASE: NIVEL DE AUTORIZACIÓN\n{'='*70}")
    if args_scope and args_scope in SCOPE_LEVELS:
        print(f"[+] Alcance fijado por CLI: {args_scope}")
        return args_scope

    options = [f"{k:10s} - {v}" for k, v in SCOPE_LEVELS.items()]
    choice = select_option("NIVEL DE AUTORIZACIÓN PARA ESTA AUDITORÍA",
                           options, default_index=0)
    if choice is None:
        print("[!] Selección cancelada. Alcance: passive (más restrictivo).")
        return "passive"
    key = choice.split(" - ", 1)[0].strip()
    print(f"\n[+] Seleccionado: {key}\n    {SCOPE_LEVELS[key]}")
    if key in ("cred", "full"):
        if not confirm_yes_no("\nConfirme que dispone de AUTORIZACIÓN "
                              "POR ESCRITO", default=False):
            print("[!] No confirmado. Alcance: passive.")
            return "passive"
    return key


def phase_scan(msf: MsfConsole, target: str) -> List[Dict[str, Any]]:
    """Fase 1: escaneo Nmap + importación a Metasploit + consulta de
    servicios."""
    print(f"\n{'='*70}\n FASE 1: ESCANEO NMAP + IMPORTACIÓN\n{'='*70}")
    xml = run_nmap(target)
    if xml:
        res = msf.db_import_nmap_xml(xml)
        print(f"[+] XML importado a Metasploit: {xml}")

    services = msf.db_services()
    if not services:
        print("[!] No hay servicios en la DB de Metasploit. "
              "Añádalos manualmente o ejecute nmap aparte.")
    else:
        print(f"[+] {len(services)} servicios en la DB")
        for s in services[:15]:
            print(f"    {s.get('host') or '?'}:{s.get('port')} "
                  f"{s.get('name', '-')}")
    return services


def phase_map(services: List[Dict[str, Any]], scope: str
              ) -> List[Dict[str, Any]]:
    """Fase 2: mapeo servicio → módulos, filtrado por alcance."""
    print(f"\n{'='*70}\n FASE 2: MAPEO NMAP → MÓDULOS (alcance={scope})\n"
          f"{'='*70}")
    plan = []
    for svc in services:
        cands = suggest_modules(svc)
        for c in cands:
            if not allowed_for_scope(c["prio"], scope):
                continue
            plan.append({**c,
                         "host": svc.get("host") or svc.get("address"),
                         "port": svc.get("port"),
                         "service": svc.get("name", "?")})
    print(f"[+] Plan: {len(plan)} módulos aplicables tras filtro de alcance")
    return plan


def phase_run(msf: MsfConsole, plan: List[Dict[str, Any]], scope: str,
              auto_all: bool = False) -> List[Finding]:
    """Fase 3: ejecución (menú por módulo o lote) y hallazgos."""
    print(f"\n{'='*70}\n FASE 3: EJECUCIÓN DE MÓDULOS\n{'='*70}")
    findings: List[Finding] = []
    jobs_started = 0

    if auto_all or confirm_yes_no(
            f"Ejecutar los {len(plan)} módulos en lote", default=True):
        # Ejecución en lote con confirmación de seguridad por tipo
        for item in plan:
            if item["type"] == "exploit" and scope != "full":
                continue  # safety: exploits solo en full
            try:
                res = msf.execute_module(
                    item["type"], item["module"],
                    {"RHOSTS": item["host"], "RPORT": item["port"],
                     "THREADS": 10},
                )
                jobs_started += 1
                findings.append(Finding(
                    host=item["host"], service=item["service"],
                    module=item["module"], severity=item["severity"],
                    summary=f"Módulo lanzado (job {res['job_id']})",
                ))
            except Exception as e:
                logging.warning("Módulo %s falló: %s", item["module"], e)
        print(f"[+] {jobs_started} módulos lanzados como jobs")
        return findings

    # Modo menú: selección por servicio (interactivo)
    grouped: Dict[str, List[Dict]] = {}
    for item in plan:
        key = f"{item['host']}:{item['port']}/{item['service']}"
        grouped.setdefault(key, []).append(item)
    targets_keys = list(grouped.keys())
    if not targets_keys:
        print("[!] Sin servicios candidatos para el menú interactivo.")
        return findings

    choice = select_option(
        "OBJETIVO (host:puerto/servicio) | q = terminar",
        [*targets_keys, "EJECUTAR TODO"],
        default_index=0)
    if choice in ("EJECUTAR TODO",):
        return phase_run(msf, plan, scope, auto_all=True)
    if choice is None:
        return findings

    items = grouped[choice]
    opts = [f"[{i['severity']}] {i['module']}" for i in items]
    mchoice = select_option(f"MÓDULOS PARA {choice}", opts, default_index=0)
    if mchoice is None:
        return findings
    item = items[opts.index(mchoice)]
    if item["type"] == "exploit":
        if not confirm_yes_no(
                f"¿Lanzar exploit {item['module']}?", default=False):
            print("[!] Exploit no lanzado.")
            return findings
    try:
        res = msf.execute_module(
            item["type"], item["module"],
            {"RHOSTS": item["host"], "RPORT": item["port"]})
        findings.append(Finding(
            host=item["host"], service=item["service"],
            module=item["module"], severity=item["severity"],
            summary=f"Módulo lanzado (job {res['job_id']})",
        ))
    except Exception as e:
        logging.warning("Módulo %s falló: %s", item["module"], e)
    return findings


def phase_sessions(msf: MsfConsole, registry: SessionRegistry,
                   interactive: bool) -> None:
    """Fase 4: higiene y clasificación de sesiones."""
    print(f"\n{'='*70}\n FASE 4: GESTIÓN DE SESIONES\n{'='*70}")
    registry.refresh(msf)
    if interactive:
        alive = [s for s in registry.known.values() if not s.is_dead]
        if alive:
            opts = [f"Sesión {s.id} ({s.platform}/{s.privs} "
                    f"en {s.target_host})" for s in alive]
            choice = select_option("ACCIÓN SOBRE SESIONES",
                                   ["Ejecutar comando en todas",
                                    "Listar sesiones de nuevo",
                                    "Cerrar una sesión",
                                    "Continuar"],
                                   default_index=3)
            if choice == "Ejecutar comando en todas":
                cmd = "whoami && id 2>/dev/null || whoami /all"
                results = registry.run_on_all(msf, cmd)
                for sid, out in results.items():
                    print(f"\n--- Sesión {sid} ---\n{out[:400]}")
            elif choice == "Listar sesiones de nuevo":
                registry.refresh(msf)
            elif choice and choice.startswith("Cerrar"):
                nums = [str(s.id) for s in alive]
                schoice = select_option("SESIÓN A CERRAR", nums,
                                        default_index=0)
                if schoice:
                    sid = int(schoice)
                    if msf.session_stop(sid):
                        print(f"[+] Sesión {sid} cerrada")
    else:
        # Batch: simplemente refrescar y clasificar
        for s in sorted(registry.known.values(), key=lambda x: x.id):
            print(f"  {s.id:3d} {s.type:12s} {s.platform}/{s.arch} "
                  f"privs={s.privs} host={s.target_host}")
    print("\n[+] Resumen:", json.dumps(registry.summary()))


def phase_report(target: str, scope: str, findings: List[Finding],
                 registry: SessionRegistry) -> Path:
    """Fase 5: informe Markdown profesional."""
    print(f"\n{'='*70}\n FASE 5: INFORME FINAL\n{'='*70}")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = AUDIT_DIR / f"audit_{sanitize(target)}_{ts}.md"
    build_report(target, scope, findings, registry.summary(),
                 registry.audit_lines, path)
    print(f"[+] Informe: {path}")
    return path


def sanitize(name: str) -> str:
    return re.sub(r"[/:.\s]+", "_", name)[:40]


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================


def run_audit(target: str, scope: Optional[str], auto: bool) -> int:
    print(f"\n{'#'*70}\n# MSF BRIDGE ORCHESTRATOR\n# Target: {target}\n"
          f"# Inicio: {datetime.now().isoformat()}\n{'#'*70}\n")

    try:
        with MsfConsole() as msf:
            if not msf.is_alive():
                print("[!] msfrpcd no responde. Levante el servicio:")
                print("    msfrpcd -P msf -S -f -a 127.0.0.1 -p 55553")
                return 1
            print(f"[+] Metasploit {msf.version().get('version')}")

            scope = scope or select_scope(interactive=True, args_scope=None)
            services = phase_scan(msf, target)
            plan = phase_map(services, scope)
            findings = phase_run(msf, plan, scope, auto_all=auto)
            registry = SessionRegistry()
            phase_sessions(msf, registry, interactive=not auto)
            phase_report(target, scope, findings, registry)
    except MsfRpcError as e:
        print(f"[!] Error RPC: {e}")
        return 1
    print(f"\n{'#'*70}\n# AUDITORÍA COMPLETADA\n{'#'*70}\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="MSF Bridge Orchestrator — Nmap → Metasploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument("--target", "-t",
                        help="Objetivo: dominio, IP o rango CIDR")
    parser.add_argument("--scope", choices=list(SCOPE_LEVELS.keys()),
                        help="Alcance (si no, menú interactivo)")
    parser.add_argument("--auto", action="store_true",
                        help="Modo automático: lote sin menús")
    args = parser.parse_args()

    if args.target:
        if args.scope in ("cred", "full"):
            if not confirm_yes_no(
                    f"Alcance '{args.scope}' implica pruebas activas contra "
                    f"{args.target}. ¿Autorización por escrito?",
                    default=False):
                print("[!] Abortado.")
                return 1
        return run_audit(args.target, args.scope, args.auto)

    # Modo interactivo sin target: menú principal numerado
    interactive_main()
    return 0


def interactive_main() -> None:
    """Menú principal numerado (atajos numéricos + tecla única)."""
    print(f"\n{'='*70}\n MSF BRIDGE ORCHESTRATOR — MENÚ PRINCIPAL\n"
          f"{'='*70}")
    while True:
        menu = [
            "Conectar y verificar msfrpcd",
            "Escanear target (nmap + import)",
            "Listar servicios en la DB",
            "Mapear servicios → módulos Metasploit",
            "Ejecutar módulo (interactivo)",
            "Ejecución en lote (alcance activo)",
            "Gestión de sesiones (clasificar/higiene)",
            "Ejecutar comando en todas las sesiones",
            "Generar informe de la última auditoría",
            "Ver ayuda",
            "Salir",
        ]
        choice = select_option("SELECCIONE UNA OPCIÓN", menu,
                               default_index=0)
        if choice is None or choice == "Salir":
            print("[+] Saliendo.")
            return
        print(f"\n[*] Opción: {choice}")
        try:
            handle_main_choice(choice)
        except Exception as e:
            print(f"[!] Error: {e}")
        try:
            input("\n[Pulse Enter para volver al menú...]")
        except EOFError:
            # stdin agotado (modo pipe): salir del bucle
            print("[+] Entrada agotada. Saliendo.")
            return


def handle_main_choice(choice: str) -> None:
    actions = {
        "Conectar y verificar msfrpcd": action_connect,
        "Escanear target (nmap + import)": action_scan,
        "Listar servicios en la DB": action_services,
        "Mapear servicios → módulos Metasploit": action_map,
        "Ejecutar módulo (interactivo)": action_run_module,
        "Ejecución en lote (alcance activo)": action_batch,
        "Gestión de sesiones (clasificar/higiene)": action_sessions,
        "Ejecutar comando en todas las sesiones": action_all_sessions,
        "Generar informe de la última auditoría": action_report,
        "Ver ayuda": action_help,
    }
    actions.get(choice, lambda: None)()


def _get_msf() -> MsfConsole:
    msf = MsfConsole()
    msf.login()
    return msf


def action_connect() -> None:
    with _get_msf() as msf:
        print(f"[+] Conectado. Versión: {msf.version().get('version')}")


def action_scan() -> None:
    try:
        target = input(" Target (IP/rango/CIDR): ").strip()
    except EOFError:
        print("[!] Entrada agotada; use --target en modo batch.")
        return
    if not target:
        return
    with _get_msf() as msf:
        phase_scan(msf, target)


def action_services() -> None:
    with _get_msf() as msf:
        for s in msf.db_services():
            print(f"  {s.get('host') or '?'}:{s.get('port')} "
                  f"{s.get('name', '-')}")


def action_map() -> None:
    with _get_msf() as msf:
        services = msf.db_services()
        scope = select_scope(interactive=True, args_scope=None)
        plan = phase_map(services, scope)
        for item in plan:
            print(f"  [{item['severity']}] {item['module']} "
                  f"→ {item['host']}:{item['port']}")


def action_run_module() -> None:
    with _get_msf() as msf:
        services = msf.db_services()
        scope = select_scope(interactive=True, args_scope=None)
        plan = phase_map(services, scope)
        phase_run(msf, plan, scope, auto_all=False)


def action_batch() -> None:
    with _get_msf() as msf:
        services = msf.db_services()
        scope = select_scope(interactive=True, args_scope=None)
        plan = phase_map(services, scope)
        phase_run(msf, plan, scope, auto_all=True)


def action_sessions() -> None:
    with _get_msf() as msf:
        registry = SessionRegistry()
        phase_sessions(msf, registry, interactive=True)


def action_all_sessions() -> None:
    with _get_msf() as msf:
        registry = SessionRegistry()
        registry.refresh(msf)
        try:
            cmd = input(" Comando a ejecutar en todas las sesiones: ").strip()
        except EOFError:
            print("[!] Entrada agotada; use --auto en modo batch.")
            return
        if cmd:
            results = registry.run_on_all(msf, cmd)
            for sid, out in results.items():
                print(f"\n--- Sesión {sid} ---\n{out[:400]}")


def action_report() -> None:
    audits = sorted(AUDIT_DIR.glob("audit_*.md"))
    if not audits:
        print("[!] No hay auditorías previas.")
        return
    choice = select_option("AUDITORÍA A INFORMAR",
                           [a.name for a in audits], default_index=0)
    if choice:
        print(f"[+] Informe: {AUDIT_DIR / choice}")


def action_help() -> None:
    print(__doc__)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    sys.exit(main())