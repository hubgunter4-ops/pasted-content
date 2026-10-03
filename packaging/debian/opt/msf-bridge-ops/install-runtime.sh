#!/bin/sh
set -eu
APP_ROOT=/opt/msf-bridge-ops
python3 -m venv "$APP_ROOT/.venv"
"$APP_ROOT/.venv/bin/python" -m pip install --upgrade pip
"$APP_ROOT/.venv/bin/python" -m pip install "$APP_ROOT"
printf '%s\n' "Runtime installed at $APP_ROOT/.venv" "Launch with: msf-bridge-ops"
