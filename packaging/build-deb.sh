#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(python3 -c "import tomllib; print(tomllib.load(open('$ROOT/pyproject.toml','rb'))['project']['version'])")
ARCH=$(dpkg --print-architecture)
STAGE="$ROOT/packaging/.stage"
OUT="$ROOT/dist/msf-bridge-ops_${VERSION}_${ARCH}.deb"
rm -rf "$STAGE" "$ROOT/dist"
mkdir -p "$STAGE/opt/msf-bridge-ops" "$STAGE/usr/bin" "$STAGE/usr/share/applications" "$STAGE/usr/share/doc/msf-bridge-ops"
cp -a "$ROOT/README.md" "$ROOT/pyproject.toml" "$ROOT/msf_bridge.py" "$ROOT/msf_bridge_mcp.py" "$ROOT/runner_core" "$ROOT/interfaces" "$ROOT/config" "$STAGE/opt/msf-bridge-ops/"
cp "$ROOT/packaging/debian/opt/msf-bridge-ops/install-runtime.sh" "$STAGE/opt/msf-bridge-ops/"
find "$STAGE/opt/msf-bridge-ops" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$STAGE/opt/msf-bridge-ops" -type f -name '*.pyc' -delete
cp "$ROOT/packaging/debian/usr/bin/msf-bridge-ops" "$STAGE/usr/bin/"
cp "$ROOT/packaging/debian/usr/share/applications/msf-bridge-ops.desktop" "$STAGE/usr/share/applications/"
cp "$ROOT/README.md" "$STAGE/usr/share/doc/msf-bridge-ops/README.md"
cp "$ROOT/packaging/debian/DEBIAN/control" "$STAGE/DEBIAN.control"
mkdir -p "$STAGE/DEBIAN"
mv "$STAGE/DEBIAN.control" "$STAGE/DEBIAN/control"
chmod 0755 "$STAGE/usr/bin/msf-bridge-ops" "$STAGE/opt/msf-bridge-ops/install-runtime.sh"
mkdir -p "$ROOT/dist"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT" >/dev/null
sha256sum "$OUT" > "$ROOT/packaging/SHA256SUMS"
printf '%s\n' "Built: $OUT" "Checksum: $ROOT/packaging/SHA256SUMS"
