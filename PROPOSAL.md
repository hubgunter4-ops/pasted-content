# Propuesta: MSF Bridge Orchestrator

**Estado:** Propuesta pendiente  
**Tipo:** Rediseño de interfaz existente, conservando CLI + MCP  
**Repositorio:** `hubgunter4-ops/pasted-content`  
**Previews:** `previews/current.png` (mockup de captura CLI), `previews/proposed.png` (mockup de alta fidelidad), `previews/comparison.png` (comparación funcional)

## Diagnóstico

El repositorio es un orquestador de Purple Team autorizado compuesto por:

- `msf_bridge.py`: cliente Metasploit RPC, CLI heredada interactiva/batch, Nmap, mapeo de servicios, jobs, sesiones e informes.
- `msf_bridge_mcp.py`: servidor MCP por **stdio**, con allowlist de targets, acknowledgement exacto, scopes `passive`/`cred`/`full`, flags activos separados y mapa de módulos cerrado.
- `tests/`: pruebas locales de política y protocolo MCP.

No existe una GUI actual. La interfaz disponible es un menú de terminal con navegación por teclas. El diseño propuesto no sustituye comandos, argumentos, códigos de salida ni el transporte stdio.

## Objetivo y usuarios

Crear un **panel profesional local GUI + CLI** para operadores técnicos de seguridad y responsables de validación defensiva. La GUI hará descubribles las acciones y sus gates; el núcleo seguirá siendo reutilizable desde CLI y MCP.

## Dirección visual

- **Perfil:** centro de operaciones técnico, oscuro por defecto, denso pero legible.
- **Colores:** azul petróleo para navegación, verde para estados saludables/completados, ámbar para atención, rojo solo para bloqueos/riesgo; ningún estado dependerá únicamente del color.
- **Tipografía:** sans-serif legible, jerarquía 11/13/15/17/25 px.
- **Componentes:** barra superior con transporte/versión, navegación lateral, tarjetas de estado, runbook reordenable, detalle contextual, consola separada y barra de ejecución.
- **Accesibilidad:** foco visible, teclado completo, etiquetas textuales, objetivos táctiles cómodos y `prefers-reduced-motion`.

## Framework recomendado

**PySide6 — perfil “Panel profesional” — puntuación estimada 4.25/5.**

| Criterio | Peso | Nota | Motivo |
|---|---:|---:|---|
| Compatibilidad con runtime Python | 25% | 5 | Comparte el runtime y el núcleo existente |
| Facilidad de mantenimiento | 15% | 4 | Ecosistema robusto; requiere estructura por capas |
| Calidad visual/componentes | 15% | 5 | Model/View, docks, tablas, consola y accesibilidad |
| Rendimiento/RAM | 15% | 4 | Adecuado para panel local; más pesado que Tkinter |
| Acceso al sistema | 10% | 5 | Procesos, señales, archivos y entorno local |
| Multiplataforma | 10% | 4 | Linux primero; extensible a otros sistemas |
| Empaquetado | 10% | 3 | Requiere definir canal `.deb`/AppImage más adelante |

**Alternativa:** CustomTkinter (3.70/5), con menor coste inicial pero menor capacidad para consola, tablas, docks, accesibilidad y crecimiento.

## Alcance propuesto

1. Añadir un núcleo de acciones declarativas en `tool-runner.yaml`, compartido por GUI, CLI, documentación y empaquetado.
2. Añadir una capa de ejecución observable: PID, cwd, timestamps, duración, stdout/stderr, exit code, timeout y cancelación segura.
3. Crear GUI PySide6 con:
   - Overview de salud RPC, política y transporte MCP.
   - Runbook con grupos Preparar, Consultar, Escanear, Ejecutar y Mantener.
   - Detalle de acción con riesgo, precondiciones y comando reproducible.
   - Consola con stdout/stderr separados, copiar comando y conservar el último resultado.
   - Gates visibles para allowlist, acknowledgement y flags de actividad.
   - Reordenamiento persistente y restauración del orden recomendado.
4. Mantener la CLI actual y mapear los mismos IDs de acción a subcomandos no interactivos.
5. Añadir pruebas para éxito, fallo, timeout, cancelación, configuración inválida, rutas con espacios, permisos insuficientes y persistencia del orden.

## Acciones iniciales modeladas

| ID | Acción | Riesgo | Efecto |
|---|---|---:|---|
| `detect` | Detectar entorno | low | Lectura local |
| `health-check` | Verificar RPC | low | Consulta al endpoint configurado |
| `list-hosts` / `list-services` | Consultar DB | low | Lectura RPC |
| `map-services` | Mapear servicios | low | No lanza módulos |
| `scan-target` | Escanear target | high | Actividad de red; allowlist + ack + flag |
| `execute-mapped-module` | Ejecutar módulo | high | Gates por scope, credenciales y exploits |
| `list-sessions` / `list-jobs` | Monitorizar | low | Lectura RPC |
| `stop-session` / `kill-job` | Limpieza | high | Ack y validación del recurso |
| `generate-report` | Generar informe | medium | Escritura dentro del directorio de auditoría |

## Instalación y permisos

La propuesta **no instala nada todavía**. Tras confirmación:

- Crear `.venv` local y usar el lock/manifest del proyecto.
- Instalar dependencias solo dentro del entorno virtual; no usar `sudo` ni cambios globales.
- Añadir PySide6 como dependencia únicamente si se aprueba el rediseño GUI.
- No iniciar `msfrpcd`, Nmap, módulos, sesiones ni endpoints de red durante la construcción.
- No registrar ni copiar secretos; mantener `MSF_PASS` fuera de archivos versionados.

## Archivos previstos tras confirmación

- `tool-runner.yaml`
- `runner_core/` o equivalente para ejecución observable
- `gui/` o equivalente para PySide6
- `cli/` o ajustes compatibles en los entry points existentes
- `tests/` ampliados
- `pyproject.toml` actualizado
- documentación de uso y rollback
- `previews/final.png`

No se modificarán archivos ni se ejecutarán acciones operativas hasta la confirmación explícita.

## Validación y rollback

Se validará compilación, pruebas unitarias, protocolo MCP seguro, dry-run, estados de error, timeout, cancelación y que la UI no se congele. El rollback consiste en eliminar los archivos nuevos y restaurar los archivos versionados modificados; no se tocarán configuraciones globales ni servicios del sistema.

## Resultados de diagnóstico seguro

- `python3 -m py_compile msf_bridge.py msf_bridge_mcp.py`: **pasa**.
- `python3 -m unittest discover -s tests -v`: **bloqueado por dependencia faltante** (`ModuleNotFoundError: mcp`); no se instaló para respetar el modo propuesta.
- No se ejecutaron Nmap, Metasploit RPC, módulos, sesiones ni red operativa.

## Confirmación requerida

Confirma explícitamente si deseas que implemente **exactamente este alcance**, con **PySide6**, manteniendo la CLI y el servidor MCP, instalando dependencias únicamente en `.venv` y sin ejecutar acciones contra objetivos. Si prefieres solo CLI/MCP o un framework alternativo, indica el cambio para generar una nueva propuesta.
