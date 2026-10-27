"""
CLI Entrypoint for `zkcredit`:
  python -m zkcredit bench
  python -m zkcredit serve       (settings: ZKCREDIT_* environment variables)
  python -m zkcredit migrate     (apply database migrations and exit)
"""

from __future__ import annotations

import argparse
import json
import os
import sys

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
    serve_p.add_argument("--host", help="Host address (default ZKCREDIT_HOST or 127.0.0.1; others need API keys)")
    serve_p.add_argument("--port", type=int, help="Port number (default ZKCREDIT_PORT or 8012)")
    sub.add_parser("migrate", help="Apply database migrations to ZKCREDIT_DATABASE_URL")

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

    if cmd in ("serve", "migrate"):
        from . import db, ops

        for name, val in (("HOST", getattr(args, "host", None)), ("PORT", getattr(args, "port", None))):
            if val is not None:
                os.environ[f"ZKCREDIT_{name}"] = str(val)
        try:
            settings = ops.load_settings()  # fail here, before uvicorn, with a readable message
        except ops.ConfigError as e:
            print(f"configuration error: {e}", file=sys.stderr)
            return 2
        if cmd == "migrate":
            print(*(db.migrate(db.engine(settings.database_url)) or ["up to date"]), sep="\n")
            return 0
        import uvicorn

        ops.setup_logging(settings.log_level)
        try:
            uvicorn.run("zkcredit.api:app", host=settings.host, port=settings.port, log_config=None, access_log=False)
        except ops.ConfigError as e:  # raised while importing the app: unreviewed-crypto consent, FIP key
            print(f"configuration error: {e}", file=sys.stderr)
            return 2
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
