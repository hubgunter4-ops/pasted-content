from __future__ import annotations

import argparse
import json

import msf_bridge_mcp as server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="MSF Bridge verified action adapters")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("health-check")
    sub.add_parser("list-services")
    sub.add_parser("map-services")
    scan = sub.add_parser("scan-target"); scan.add_argument("target"); scan.add_argument("--ack", required=True); scan.add_argument("--scope", default="passive")
    execute = sub.add_parser("execute-mapped-module"); execute.add_argument("target"); execute.add_argument("module"); execute.add_argument("--ack", required=True); execute.add_argument("--scope", default="cred")
    args = parser.parse_args(argv)
    if args.action == "health-check": result = server.health_check()
    elif args.action == "list-services": result = server.list_services()
    elif args.action == "map-services": result = server.map_services()
    elif args.action == "scan-target": result = server.scan_target(args.target, args.ack, args.scope)
    elif args.action == "execute-mapped-module": result = server.execute_mapped_module(args.target, args.module, args.ack, args.scope)
    else: raise AssertionError(args.action)
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
