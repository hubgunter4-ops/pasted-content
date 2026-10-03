#!/bin/sh
set -eu
printf '%s\n' 'This removes the installed package and /opt/msf-bridge-ops runtime.'
if [ "${1:-}" != "--yes" ]; then
  printf '%s\n' 'Re-run with --yes to confirm removal.' >&2
  exit 2
fi
sudo dpkg -r msf-bridge-ops
sudo rm -rf /opt/msf-bridge-ops
