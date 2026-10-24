"""A checkout gate, not a SARIF schema validator or report rewriter."""

import argparse
import json
import sys

from . import __version__
from .core import InputError, check, load_report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify SARIF physical locations against a checkout"
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("report")
    parser.add_argument("--root", required=True)
    parser.add_argument("--base", action="append", default=[], metavar="ID=RELATIVE_DIRECTORY")
    parser.add_argument("--max-report-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--max-source-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--receipt-limit", type=int, default=100)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        maps = {}
        for item in args.base:
            name, separator, value = item.partition("=")
            if not separator or not name or name in maps:
                raise InputError("base options require unique ID=RELATIVE_DIRECTORY entries")
            maps[name] = value
        report = check(
            load_report(args.report, args.max_report_bytes),
            args.root,
            base_maps=maps,
            max_source_bytes=args.max_source_bytes,
            receipt_limit=args.receipt_limit,
        )
    except (InputError, OSError, RuntimeError) as exc:
        print(f"sarif-sourcecheck: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    else:
        print(
            f"{'PASS' if report['passed'] else 'FAIL'}: "
            f"{report['locations_checked']} locations, {report['locations_failed']} failures"
        )
        for receipt in report["receipts"]:
            print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
        if report["receipts_truncated"]:
            print("Receipts truncated; counts cover all checked locations.")
    return 0 if report["passed"] else 1
