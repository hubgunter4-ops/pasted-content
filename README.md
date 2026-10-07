# MSF Bridge Orchestrator — MCP Server

Servidor **Model Context Protocol (MCP)** para integrar un flujo autorizado de Purple Team con Nmap y Metasploit RPC. Expone operaciones de descubrimiento, consulta de la base de datos, mapeo de servicios, ejecución controlada de módulos y limpieza de jobs/sesiones. El transporte implementado es **stdio**, por lo que el proceso se ejecuta localmente bajo el control del host MCP y reserva `stdout` exclusivamente para mensajes JSON-RPC, conforme a la guía oficial del SDK.[1] [2]

> **Uso autorizado únicamente.** Este proyecto puede realizar reconocimiento de red, pruebas de credenciales y explotación mediante Metasploit. Utilízalo solo sobre activos cuyo propietario haya aprobado por escrito el alcance, las técnicas, las ventanas de prueba y los límites operativos. El hecho de que un target esté en una allowlist local no constituye autorización legal ni sustituye la aprobación del propietario.

## Objetivo operativo

El servidor está diseñado para cerrar el ciclo **prueba → detección → ajuste → nueva validación**. La perspectiva ofensiva se limita mediante controles explícitos; la perspectiva defensiva debe correlacionar cada actividad con telemetría de red, autenticación, endpoint y Metasploit para comprobar la cobertura de detección y la eficacia de las mitigaciones.

La arquitectura mantiene el cliente RPC existente en `msf_bridge.py` y añade `msf_bridge_mcp.py` como adaptador MCP. El adaptador no acepta módulos arbitrarios, valida targets y argumentos Nmap, aplica una allowlist de objetivos, separa los flags de reconocimiento/credenciales/exploits y devuelve resultados estructurados al host MCP.

| Componente | Responsabilidad | Exposición |
|---|---|---|
| `msf_bridge.py` | Cliente Metasploit RPC, mapeo de servicios, sesiones, jobs e informes | CLI heredada y biblioteca local |
| `msf_bridge_mcp.py` | Herramientas MCP, validación, controles de autorización y serialización | Servidor MCP sobre stdio |
| `tests/test_mcp_policy.py` | Pruebas de allowlist, validación de target, argumentos y flags | No realiza red ni RPC |
| `runner_core/` | Runner observable, verificadores, registry y adaptadores RPC | Acciones verificadas y estados operativos |
| `interfaces/gui/` | Interfaz PySide6 Ops Mono | Consola desktop colorida |
| `config/tool-runner.yaml` | Definición declarativa de acciones | GUI, CLI y pruebas |
| `packaging/` | Instalador, build Debian y desinstalador | `.deb` amd64 |
| `pyproject.toml` | Dependencias y comandos instalables | `msf-bridge`, `msf-bridge-mcp` y `msf-bridge-ops` |

## Requisitos

Se requiere **Python 3.10 o superior** y un servicio Metasploit `msfrpcd` accesible desde el mismo entorno donde se ejecuta el servidor. El SDK oficial de Python para MCP declara Python 3.10+ y proporciona soporte para stdio, Streamable HTTP y SSE; esta implementación selecciona stdio para evitar exponer un endpoint de administración de Metasploit a la red.[1]

Instala el paquete en un entorno virtual:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

El proyecto instala `mcp>=2,<3`, `msgpack>=1.0`, `requests>=2.31` y `PySide6>=6.7,<7`. Para verificar la versión instalada del SDK:

```bash
python -c "import mcp; print(mcp.__version__)"
```

También debes disponer de `nmap` y de Metasploit Framework. Un ejemplo de inicio local de `msfrpcd` es:

```bash
msfrpcd -P 'CAMBIA_ESTA_CLAVE' -S -f -a 127.0.0.1 -p 55553
```

No uses la contraseña de ejemplo en un entorno real. Mantén el servicio RPC ligado a loopback o a una interfaz de administración protegida, y usa TLS y controles de red cuando la arquitectura requiera acceso remoto.

## Configuración de seguridad

El servidor aplica **denegación por defecto** a las operaciones activas. Para que `scan_target` o `execute_mapped_module` puedan operar deben cumplirse simultáneamente cuatro condiciones: el target debe estar cubierto por `MSF_MCP_ALLOWED_TARGETS`, la llamada debe incluir el valor exacto de `authorization_ack`, `MSF_MCP_ENABLE_ACTIVE` debe estar habilitado y el scope debe permitir la técnica solicitada. Las pruebas de credenciales y los exploits añaden sus propios flags de habilitación.

Configura las variables fuera del repositorio. La siguiente plantilla es ilustrativa y no contiene credenciales válidas:

```bash
export MSF_HOST=127.0.0.1
export MSF_PORT=55553
export MSF_USER=msf
export MSF_PASS='REEMPLAZAR_CON_UN_SECRETO_LOCAL'
export MSF_SSL=0

# IP, CIDR o FQDN separados por coma o punto y coma.
export MSF_MCP_ALLOWED_TARGETS='192.0.2.0/24,lab.example.com'

# Scope usado cuando una herramienta no lo recibe explícitamente.
# Valores válidos: passive, cred, full. passive es el fallback seguro.
export MSF_MCP_DEFAULT_SCOPE=passive

# Mantener deshabilitados hasta el inicio de una ventana autorizada.
export MSF_MCP_ENABLE_ACTIVE=0
export MSF_MCP_ENABLE_CRED_TESTS=0
export MSF_MCP_ENABLE_EXPLOITS=0
export MSF_MCP_LOG_LEVEL=INFO
```

| Variable | Predeterminado | Función | Recomendación |
|---|---:|---|---|
| `MSF_HOST` | `127.0.0.1` | Host del RPC | Mantener loopback cuando sea posible |
| `MSF_PORT` | `55553` | Puerto del RPC | Filtrar mediante firewall |
| `MSF_USER` | `msf` | Usuario RPC | Usar una cuenta dedicada |
| `MSF_PASS` | `msf` | Secreto RPC | Sobrescribir siempre; nunca confirmarlo en Git |
| `MSF_SSL` | `0` | HTTPS para RPC | Activar cuando el RPC no sea local |
| `MSF_MCP_ALLOWED_TARGETS` | vacío | Allowlist obligatoria para operaciones sobre targets | Limitar a IPs, CIDR y FQDN aprobados |
| `MSF_MCP_DEFAULT_SCOPE` | `passive` | Scope aplicado cuando la llamada omite `scope` | Mantener `passive`; usar `cred` o `full` solo con alcance aprobado |
| `MSF_MCP_ENABLE_ACTIVE` | `0` | Habilita escaneo y ejecución de módulos | Activar solo durante la ventana aprobada |
| `MSF_MCP_ENABLE_CRED_TESTS` | `0` | Habilita módulos de prioridad 2 | Requiere autorización específica |
| `MSF_MCP_ENABLE_EXPLOITS` | `0` | Habilita módulos de tipo exploit | Reservar para laboratorio o alcance `full` |
| `MSF_MCP_LOG_LEVEL` | `INFO` | Nivel de logging a stderr | Usar `DEBUG` solo para diagnóstico controlado |
| `MSF_BRIDGE_DIR` | `/tmp/msf_bridge` | Directorio local de XML e informes del cliente heredado | Usar un directorio aislado y con permisos restrictivos |

El reconocimiento `passive` del proyecto significa que no se ejecutan exploits ni pruebas de credenciales, pero un escaneo Nmap sigue siendo **actividad de red observable**. Trátalo como actividad activa desde el punto de vista de autorización, IDS/NDR y coordinación con el SOC.

## Herramientas MCP expuestas

El host MCP obtiene los esquemas a partir de las anotaciones de tipo y docstrings del servidor. Las herramientas de lectura de la base de datos requieren autenticación RPC porque consultan Metasploit; no lanzan Nmap, módulos ni comandos de sesión.

| Herramienta | Tipo | Controles principales |
|---|---|---|
| `get_capabilities` | Lectura local | No contacta Metasploit; muestra flags y política efectiva |
| `health_check` | Lectura RPC | Comprueba respuesta HTTP del endpoint configurado |
| `list_hosts` | Lectura RPC | Lista hosts ya presentes en la base de datos |
| `list_services` | Lectura RPC | Lista servicios; admite `host_id` opcional |
| `map_services` | Lectura RPC | Mapea servicios almacenados según `scope`; no ejecuta módulos |
| `scan_target` | Activa | Allowlist, ack, `MSF_MCP_ENABLE_ACTIVE`, argumentos Nmap restringidos y timeout |
| `execute_mapped_module` | Activa | Solo módulos del mapa; scope, allowlist, flags por riesgo, opciones permitidas y `THREADS` 1–10 |
| `list_sessions` | Lectura RPC | Devuelve metadatos; no devuelve salida de comandos |
| `stop_session` | Limpieza | Ack, sesión existente y target de la sesión cubierto por allowlist |
| `list_jobs` | Lectura RPC | Lista jobs para monitorización y limpieza defensiva |
| `kill_job` | Limpieza | Ack y `job_id` no negativo |

Todas las operaciones que usan la red o Metasploit deben considerarse potencialmente disruptivas. El ack `I_CONFIRM_AUTHORIZED_SCOPE` es una barrera contra llamadas accidentales; **no es una prueba de identidad, consentimiento legal ni control de acceso independiente**.

## Scopes y gating

El scope controla qué prioridades del mapa se pueden seleccionar. Los módulos de prioridad 1 son scanners informativos; los de prioridad 2 incluyen enumeración y pruebas de credenciales; los de prioridad 3 son exploits o verificaciones de explotación.

| Scope | Permitido por el mapa | Requisito adicional |
|---|---|---|
| `passive` | Prioridad 1 | Sigue requiriendo ack, allowlist y `MSF_MCP_ENABLE_ACTIVE=1` para `scan_target` |
| `cred` | Prioridades 1–2 | `MSF_MCP_ENABLE_CRED_TESTS=1` para módulos de prioridad 2 |
| `full` | Prioridades 1–3 | `MSF_MCP_ENABLE_CRED_TESTS=1` y, para exploits, `MSF_MCP_ENABLE_EXPLOITS=1` |

El servidor rechaza módulos que no estén en `MODULE_MAP`. También rechaza argumentos Nmap fuera de un subconjunto pequeño: `-sV`, `--version-light`, `-Pn`, `-T2`, `-T3` y `--top-ports` entre 1 y 1000. Se excluyen scripts NSE, rutas de salida arbitrarias, opciones de ejecución y sintaxis de shell.

## Ejecución del servidor

Desde el directorio del repositorio, ejecuta el entry point instalado:

```bash
. .venv/bin/activate
msf-bridge-mcp
```

Para una ejecución guiada local, usa el preflight antes de iniciar el transporte MCP:

```bash
. .venv/bin/activate
python msf_bridge_mcp.py --guided
```

El modo guiado solo imprime pasos en `stderr`; no inicia MCP, no contacta Metasploit y no ejecuta acciones sobre objetivos. Para un diagnóstico básico, usa el comando de capacidades a través de un host MCP o del inspector compatible con el SDK. No escribas banners ni mensajes de diagnóstico en `stdout`: el servidor envía logs a `stderr` para no corromper el canal stdio JSON-RPC.[2]

El comando CLI heredado sigue disponible:

```bash
msf-bridge --help
msf-bridge --target 192.0.2.10 --scope passive
```

La CLI heredada y el MCP comparten el cliente RPC y la base de conocimiento, pero el MCP añade los gates de política en su propia capa. Revisa ambos caminos antes de usar el proyecto en una ventana operativa.

## Configuración de un host MCP por stdio

Los clientes MCP suelen iniciar el servidor como un subproceso con un comando y argumentos absolutos. Ejemplo genérico de configuración:

```json
{
  "mcpServers": {
    "msf-bridge": {
      "command": "/ABSOLUTE/PATH/msf-bridge/.venv/bin/msf-bridge-mcp",
      "env": {
        "MSF_HOST": "127.0.0.1",
        "MSF_PORT": "55553",
        "MSF_USER": "msf",
        "MSF_PASS": "CARGAR_DESDE_UN_GESTOR_DE_SECRETOS",
        "MSF_MCP_ALLOWED_TARGETS": "192.0.2.0/24",
        "MSF_MCP_DEFAULT_SCOPE": "passive",
        "MSF_MCP_ENABLE_ACTIVE": "0",
        "MSF_MCP_ENABLE_CRED_TESTS": "0",
        "MSF_MCP_ENABLE_EXPLOITS": "0"
      }
    }
  }
}
```

Sustituye la ruta por una ruta absoluta del host MCP. Evita guardar secretos en archivos de configuración sincronizados, logs, prompts o repositorios. Cuando el cliente no proporcione integración con un gestor de secretos, inyecta las variables mediante el entorno del proceso con permisos restrictivos.

## Flujo Purple Team recomendado

### Preparación y autorización

Define propietarios, targets exactos, CIDR permitidos, técnicas autorizadas, límites de velocidad, condiciones de parada y contactos del SOC. Documenta si la actividad puede incluir credenciales, explotación, creación de sesiones o pruebas en producción. Configura primero la allowlist y deja todos los flags activos en `0`.

### Prueba controlada

Comienza con `get_capabilities`, `health_check`, `list_hosts`, `list_services` y `map_services(scope="passive")`. Valida que el RPC apunta al entorno correcto y que la allowlist no cubre rangos más amplios de lo aprobado. Ejecuta después el reconocimiento acordado con el menor número de puertos y la menor tasa que produzca evidencia útil.

### Detección y correlación

Correlaciona la actividad con NDR/IDS, logs de autenticación, EDR, firewall, WAF, telemetría de procesos y registros de Metasploit. Las técnicas relevantes pueden mapearse a [Network Service Scanning (T1046)](https://attack.mitre.org/techniques/T1046/), [Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/), [Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/) y [Exploitation of Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/), según la actividad realmente ejecutada.[3]

### Ajuste y retest

Para cada gap, registra la señal esperada, la señal observada, la regla o control modificado, el propietario y el criterio de éxito. Ajusta detecciones, segmentación, MFA, rate limiting, gestión de parches, hardening de servicios y respuesta. Repite solo la prueba mínima necesaria y confirma que el control detecta la técnica sin generar impacto innecesario.

## Gestión de secretos y artefactos

No subas contraseñas RPC, credenciales de prueba, tokens, claves privadas, dumps, XML de Nmap, informes con datos de clientes ni salidas de sesiones. El `.gitignore` excluye artefactos comunes, pero debes revisar el estado de Git antes de cada commit. Recuerda que los argumentos de una llamada MCP pueden quedar registrados por el host; evita incluir secretos en prompts y conserva las credenciales en el mecanismo de secretos del entorno.

Las opciones `USERNAME`, `PASSWORD`, `USER_FILE` y `PASS_FILE` existen para compatibilidad con módulos seleccionados, pero su uso aumenta el riesgo de exposición y bloqueo de cuentas. Prefiere cuentas de laboratorio, listas pequeñas aprobadas, límites bajos de `THREADS` y condiciones de parada observables.

## Pruebas locales seguras

Las pruebas incluidas ejercitan únicamente validadores y políticas; no invocan Nmap, Metasploit RPC, módulos, sesiones ni objetivos de red:

```bash
. .venv/bin/activate
python -m unittest discover -s tests -v
python -m py_compile msf_bridge.py msf_bridge_mcp.py
```

La validación del protocolo debe realizarse con un inspector MCP o un cliente de pruebas que solo invoque `get_capabilities` y, si existe un endpoint RPC de laboratorio, `health_check`. No uses un target real para validar el empaquetado.

## Troubleshooting

| Síntoma | Causa probable | Acción |
|---|---|---|
| El host no descubre herramientas | El proceso no inicia o escribe texto en stdout | Ejecuta el binario con ruta absoluta y revisa stderr |
| `ModuleNotFoundError: mcp` | Dependencias no instaladas en el mismo entorno | Activa `.venv` y ejecuta `python -m pip install -e .` |
| Operación activa rechazada | Flag activo, ack o allowlist ausente | Revisa `get_capabilities`; no desactives los gates para “probar” |
| Target fuera de allowlist | El target no está cubierto por IP, CIDR o FQDN configurado | Corrige la autorización y la allowlist, no fuerces la validación |
| Error de autenticación RPC | Usuario, secreto, host o TLS incorrectos | Comprueba `MSF_*` y el servicio `msfrpcd` en el entorno autorizado |
| No hay servicios para mapear | La base de datos no contiene servicios importados | Usa datos de laboratorio o un flujo Nmap autorizado; no amplíes el alcance automáticamente |
| Un módulo es rechazado | No forma parte de `MODULE_MAP` o excede el scope | Revisa el mapa y la aprobación del ejercicio |

## Licencia y referencias

El código de este repositorio se distribuye bajo MIT. La licencia del SDK MCP es independiente y debe consultarse en su distribución oficial. Este README documenta una integración local orientada a operaciones autorizadas; no garantiza que un cliente MCP específico acepte exactamente el mismo archivo de configuración.

## Referencias

[1]: https://github.com/modelcontextprotocol/python-sdk "MCP Python SDK oficial"

[2]: https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server "MCP — Build an MCP server"

[3]: https://attack.mitre.org/ "MITRE ATT&CK — Enterprise techniques"

## Guía de ejecución

Instala el paquete dentro de un entorno virtual y valida primero el preflight:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python msf_bridge_mcp.py --guided
python -m unittest discover -s tests -v
```

El modo `--guided` escribe la guía en `stderr`, no inicia el transporte MCP y no contacta Metasploit. Para operar el servidor MCP usa `msf-bridge-mcp` con `MSF_MCP_ALLOWED_TARGETS` configurado y los flags activos deshabilitados hasta la ventana aprobada. Guarda credenciales fuera de Git, ejecuta cleanup de jobs/sesiones y conserva la licencia del proyecto.

## Ops Mono GUI y ejecución verificada

El repositorio incluye ahora una interfaz de escritorio PySide6 en `interfaces/gui/` con el perfil Ops Mono: tipografía monoespaciada, superficies grafito oscuro, acentos teal, verde de éxito, ámbar de advertencia y estados de fallo explícitos. La GUI y la CLI usan `config/tool-runner.yaml` como definición compartida de acciones.

Una acción nunca se considera completada solo porque se pulsó un botón. `runner_core` registra PID, timestamps, cwd, duración, código de salida, stdout y stderr, aplica timeout/cancelación y ejecuta un verificador de postcondición. Un proceso con código cero pero sin evidencia válida termina en `ATTENTION`, no en `COMPLETED`. Las acciones activas continúan detrás de la allowlist, acknowledgement y flags MCP existentes.

La variante visual actual conserva la estructura aprobada —menú, toolbar, explorador, overview, inspector, cola y consola— y añade una paleta de mayor contraste: navy/grafito, azul eléctrico, teal, violeta, verde, ámbar y coral. Las acciones de la cola se colorean según su estado real; las acciones activas bloqueadas se muestran en coral y las completadas en verde.

Los adaptadores RPC de solo lectura están disponibles mediante `python -m runner_core.adapter_cli` para `health-check`, `list-services` y `map-services`. El health check solo puede quedar en `COMPLETED` cuando el payload informa `rpc_alive=true`; un JSON válido con RPC no saludable termina en `ATTENTION`.

### Validación local segura

```bash
.venv/bin/python -m unittest discover -s tests -v
QT_QPA_PLATFORM=offscreen .venv/bin/python -m interfaces.gui.app
```

La suite cubre verificación de acciones, dry-run, timeout, gates de confirmación, construcción de GUI, política MCP y protocolo MCP stdio. No utiliza objetivos reales, Nmap ni sesiones de Metasploit.

La captura visual de referencia se conserva en [`previews/colorful-opsmono.png`](previews/colorful-opsmono.png). También se puede generar una nueva captura con:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m interfaces.gui.app
```

### Paquete Debian

Construye el paquete amd64 sin pasos privilegiados:

```bash
packaging/build-deb.sh
cat packaging/SHA256SUMS
dpkg-deb --info dist/msf-bridge-ops_0.1.0_amd64.deb
dpkg-deb --contents dist/msf-bridge-ops_0.1.0_amd64.deb
```

Para instalarlo en un host Debian/Ubuntu:

```bash
packaging/install.sh
msf-bridge-ops
```

El paquete instala el código en `/opt/msf-bridge-ops`, un launcher en `/usr/bin/msf-bridge-ops` y un acceso de escritorio. `install-runtime.sh` crea el entorno aislado e instala las dependencias del proyecto. Para desinstalar explícitamente: `packaging/uninstall.sh --yes`. No se incluyen credenciales ni rutas absolutas del entorno de desarrollo.

Para probar una versión recién generada sin modificar el sistema anfitrión, se puede extraer el `.deb` en una raíz temporal, crear un `.venv` nuevo e instalar el proyecto desde `/opt/msf-bridge-ops`. El runner sustituye `python3` por el intérprete activo del entorno virtual para que los adaptadores encuentren `mcp` y el resto de dependencias:

```bash
ROOT=$(mktemp -d /tmp/msf-bridge-deb-clean.XXXXXX)
mkdir -p "$ROOT/rootfs"
dpkg-deb --extract dist/msf-bridge-ops_0.1.0_amd64.deb "$ROOT/rootfs"
python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/python" -m pip install "$ROOT/rootfs/opt/msf-bridge-ops"
QT_QPA_PLATFORM=offscreen "$ROOT/venv/bin/python" -m runner_core.adapter_cli --help
```

La validación limpia ejecutada para la versión actual confirmó extracción, instalación de dependencias, imports de `mcp`/PySide6, `adapter_cli --help`, `guided-preflight` con `COMPLETED` y lanzamiento offscreen de la GUI. No se usaron objetivos de red ni Metasploit RPC.

Las capturas de esta sesión están en [`previews/deb-clean-installed.png`](previews/deb-clean-installed.png) y [`previews/deb-clean-session.png`](previews/deb-clean-session.png).

### Estado del repositorio

El repositorio contiene la implementación GUI, las pruebas de ejecución verificable, el plan técnico, los previews visuales y el paquete Debian generado. Antes de publicar una nueva versión se recomienda ejecutar:

```bash
git diff --check
QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests -v
packaging/build-deb.sh
sha256sum -c packaging/SHA256SUMS
```
