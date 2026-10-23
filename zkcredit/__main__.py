"""
CLI Entrypoint for `zkcredit`:
  python -m zkcredit bench
  python -m zkcredit serve --port 8012
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import uvicorn

from .bench import format_benchmark_table, run_benchmark


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="zkcredit",
        description="Zero-Knowledge Credit Underwriting & Cryptographic Proof-of-Solvency Engine",
    )
    sub = parser.add_subparsers(dest="command")

    bench_p = sub.add_parser("bench", help="Run completeness & soundness benchmark suite")
    bench_p.add_argument("--json", action="store_true", help="Output benchmark report as JSON")

    serve_p = sub.add_parser("serve", help="Run FastAPI server")
    serve_p.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=8012, help="Port number (default: 8012)")

    args = parser.parse_args(argv)
    cmd = args.command or "bench"

    if cmd == "bench":
        # The report prints the rupee sign, which a cp1252 Windows console cannot encode
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        report = run_benchmark()
        if getattr(args, "json", False):
            print(json.dumps(report, indent=2))
        else:
            print(format_benchmark_table(report))
        summary = report["summary"]
        if summary["completeness_rate"] < 1.0 or summary["cheating_acceptance_rate"] > 0.0:
            return 1
        return 0

    if cmd == "serve":
        if args.host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("ZKCREDIT_API_KEY"):
            print("Refusing to listen on a non-loopback address without ZKCREDIT_API_KEY set.", file=sys.stderr)
            return 2
        uvicorn.run("zkcredit.api:app", host=args.host, port=args.port, reload=False)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
