#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEB=$(find "$ROOT/dist" -maxdepth 1 -name 'msf-bridge-ops_*.deb' -type f | sort | tail -n 1)
if [ -z "${DEB:-}" ]; then
  echo "No .deb found. Run packaging/build-deb.sh first." >&2
  exit 1
fi
sudo dpkg -i "$DEB" || sudo apt-get -f install
sudo /opt/msf-bridge-ops/install-runtime.sh
printf '%s\n' "MSF Bridge Ops Mono installed." "Run: msf-bridge-ops"
