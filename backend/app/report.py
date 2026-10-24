"""Render HTML reports for an analyst run.

  python -m app.report <run-id>              both variants, printed paths
  python -m app.report <run-id> --variant as-found
  python -m app.report --latest

Writes <evidence>/reports/<run-id>/{as-found,as-fixed}.html plus a `shots/` folder the pages reference.

No model call, no network: the prose was captured during the run.
"""

from __future__ import annotations

import argparse
import sys

from . import config
from .analyst import html_report

VARIANTS = ("as-found", "as-fixed")


def latest_run() -> str:
    d = config.EVIDENCE_DIR / "analyst"
    files = sorted(d.glob("arn_*.json"), key=lambda p: p.stat().st_mtime, reverse=True) if d.is_dir() else []
    if not files:
        raise SystemExit("no analyst runs found")
    return files[0].stem


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tirith report", description=__doc__)
    ap.add_argument("run_id", nargs="?", help="analyst run id, e.g. arn_abc123")
    ap.add_argument("--latest", action="store_true", help="use the most recent run")
    ap.add_argument("--variant", choices=VARIANTS, action="append",
                    help="render only this variant (repeatable; default: both)")
    ap.add_argument("--out", help="output directory (default: <evidence>/reports/<run-id>)")
    args = ap.parse_args(argv)

    run_id = args.run_id or (latest_run() if args.latest else None)
    if not run_id:
        ap.error("give a run id or --latest")
    out = None if not args.out else __import__("pathlib").Path(args.out)
    try:
        for v in (args.variant or VARIANTS):
            print(html_report.render_run(run_id, v, out))
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())