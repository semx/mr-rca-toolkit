"""Command line interface for merge review and RCA workflows."""

from __future__ import annotations

import argparse
import json

from toolkit.manifest import load_json, load_merge_request
from toolkit.models import SEVERITY_RANK
from toolkit.rca import IncidentEvent, RCABuilder
from toolkit.review import ReviewEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mr-rca", description="Merge review and RCA toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    review = subparsers.add_parser("review", help="Review a merge request manifest")
    review.add_argument("manifest", help="Path to merge request JSON manifest")
    review.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    review.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_RANK.keys()),
        default="critical",
        help="Exit non-zero when a finding meets or exceeds this severity",
    )

    rca = subparsers.add_parser("rca", help="Build an RCA draft from incident JSON")
    rca.add_argument("incident", help="Path to incident JSON manifest")
    rca.add_argument("--pretty", action="store_true", help="Pretty-print JSON")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "review":
        report = ReviewEngine().review(load_merge_request(args.manifest))
        print(_dump(report.as_dict(), args.pretty))
        return 1 if report.should_fail(args.fail_on) else 0

    if args.command == "rca":
        incident = IncidentEvent.from_dict(load_json(args.incident))
        draft = RCABuilder().build(incident)
        print(_dump(draft.as_dict(), args.pretty))
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


def _dump(payload: object, pretty: bool) -> str:
    if pretty:
        return json.dumps(payload, indent=2, sort_keys=True)
    return json.dumps(payload, sort_keys=True)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
