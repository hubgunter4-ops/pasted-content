# MSF Bridge Orchestrator

Orquestador en Python que integra el descubrimiento de servicios con Nmap y la consulta/ejecución de módulos mediante Metasploit RPC. Incluye controles de alcance (`passive`, `cred` y `full`), confirmaciones para pruebas activas, clasificación de sesiones y generación de informes Markdown.

## Uso autorizado

Este proyecto está destinado exclusivamente a evaluaciones de seguridad autorizadas y ejercicios Purple Team. Antes de ejecutar cualquier prueba activa, confirma por escrito el alcance, los objetivos y las ventanas de prueba. No lo ejecutes contra sistemas de terceros ni fuera de los límites aprobados.

## Requisitos

```bash
pip3 install msgpack requests
```

También requiere `nmap` y un servicio `msfrpcd` accesible en la configuración indicada por las variables de entorno `MSF_HOST`, `MSF_PORT`, `MSF_USER`, `MSF_PASS` y `MSF_SSL`.

## Ejemplos

```bash
python3 msf_bridge.py
python3 msf_bridge.py --target 10.0.0.1 --scope passive
```

El alcance `passive` es el valor más restrictivo. Los alcances `cred` y `full` requieren confirmación de autorización durante la ejecución.

## Enfoque Purple Team

Los hallazgos generados deben correlacionarse con telemetría defensiva y técnicas de [MITRE ATT&CK](https://attack.mitre.org/), para cerrar el ciclo de prueba, detección, ajuste y nueva validación. Evita almacenar credenciales, tokens, resultados sensibles o artefactos de auditoría en este repositorio público.
