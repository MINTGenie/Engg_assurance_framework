"""Command line interface: eaf assess <path> --depth 1"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eaf import DISCLAIMER, __version__
from eaf.engine import AssessmentError, Options, assess
from eaf.guidance import GuidanceError, bundled_guidance, load_guidance
from eaf.models import DEPTHS, SCOPES
from eaf.policy import PolicyError, bundled_policies, load_policy
from eaf.profile import PROFILE_TEMPLATE, ProfileError
from eaf.report import write_reports
from eaf.runner import find_tool
from eaf.scanners import all_adapters
from eaf.scanners.base import ScanContext

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2
LABEL = {"NOT_APPLICABLE": "NOT APPLICABLE", "NOT_EXECUTED": "NOT EXECUTED"}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="eaf", description="Engineering Assurance Framework - "
                                "read-only engineering quality assessment (prototype).")
    p.add_argument("--version", action="version", version=f"eaf {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("assess", help="assess a repository or source directory")
    a.add_argument("path", help="local repository or source directory")
    a.add_argument("--depth", type=int, default=1, choices=sorted(DEPTHS),
                   help="assessment depth; only 1 (static source inspection) is implemented")
    a.add_argument("--scope", default="repository", choices=SCOPES,
                   help="what the path represents (recorded in the report)")
    a.add_argument("--profile", type=Path, help="engineering context profile (TOML); default: "
                   "<path>/eaf-profile.toml if present")
    a.add_argument("--policy", help="bundled policy id or path to a policy TOML "
                   "(default: from profile, else eaf-baseline)")
    a.add_argument("--output", "-o", type=Path, default=Path("eaf-reports"),
                   help="report directory (default: ./eaf-reports; never inside the assessed tree "
                        "unless you point it there)")
    a.add_argument("--guidance", help="bundled guidance pack id or path to your own pack (TOML): "
                   "which engineering practices are checked and what advice is given")
    a.add_argument("--format", default="json,html,md",
                   help="comma list of: json, html, md (md = short evidence summary)")
    a.add_argument("--allow-network", action="store_true", default=None,
                   help="permit dependency vulnerability lookups (sends package names and "
                        "versions, never source code, to PyPI/npm advisory services)")
    a.add_argument("--timeout", type=int, default=300, help="per-scanner timeout in seconds")
    a.add_argument("--only", action="append", default=[], metavar="GLOB",
                   help="run only checks whose id matches (repeatable), e.g. 'security.*'")
    a.add_argument("--skip", action="append", default=[], metavar="GLOB",
                   help="skip checks whose id matches (repeatable)")
    a.add_argument("--no-evidence", action="store_true",
                   help="do not store raw scanner output next to the report")
    a.add_argument("--fail-on", default="fail", choices=["fail", "warning", "never"],
                   help="overall status that makes the exit code 1 (default: fail)")
    a.add_argument("--quiet", "-q", action="store_true")

    sub.add_parser("scanners", help="list scanner adapters and whether their tools are installed")
    sub.add_parser("policies", help="list bundled policies")
    g = sub.add_parser("guidance", help="show the practices and advice of a guidance pack")
    g.add_argument("pack", nargs="?", default="eaf-practices")
    ip = sub.add_parser("init-profile", help="write a profile template")
    ip.add_argument("target", nargs="?", default="eaf-profile.toml")
    return p


def _cmd_assess(args) -> int:
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    if not formats or any(f not in ("json", "html", "md") for f in formats):
        print("error: --format accepts json, html and/or md", file=sys.stderr)
        return EXIT_USAGE
    out_dir = args.output.resolve()
    options = Options(depth=args.depth, scope=args.scope, profile_path=args.profile,
                      policy=args.policy, guidance=args.guidance, allow_network=args.allow_network, timeout=args.timeout,
                      only=args.only, skip=args.skip,
                      evidence_dir=None if args.no_evidence else out_dir / "evidence")
    try:
        report = assess(args.path, options)
    except (AssessmentError, PolicyError, ProfileError, GuidanceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    report["tool"]["command_line"] = sys.argv[1:]
    written = write_reports(report, out_dir, formats)

    summary = report["summary"]
    if not args.quiet:
        scope = report["assessment"]["scope"]
        print(f"EAF {__version__} | depth {args.depth} | {scope['path']}")
        print(f"revision: {scope['git'].get('revision') or 'n/a'} | "
              f"policy: {report['assessment']['policy']['id']}@{report['assessment']['policy']['version']}"
              f" | languages: {', '.join(report['inventory']['languages']) or 'none'}")
        print()
        for c in report["checks"]:
            n = sum(c["finding_counts"].values())
            print(f"  {LABEL.get(c['status'], c['status']):<15} {c['id']:<34} "
                  f"{(str(n) + ' finding(s)') if n else '':<16} {c['reason'][:90]}")
        print()
        print(f"OVERALL: {LABEL.get(summary['overall_status'], summary['overall_status'])} - "
              f"{summary['overall_reason']}  ({report['assessment']['duration_s']}s)")
        for fmt, path in written.items():
            print(f"{fmt} report: {path}")
        print(f"\nNote: {DISCLAIMER}")
    status = summary["overall_status"]
    failing = {"fail": {"FAIL"}, "warning": {"FAIL", "WARNING"}, "never": set()}[args.fail_on]
    return EXIT_FAIL if status in failing else EXIT_OK


def _cmd_scanners() -> int:
    import tempfile
    with tempfile.TemporaryDirectory(prefix="eaf-") as tmp:
        ctx = ScanContext(root=Path(tmp), inventory=None, profile=None, workdir=Path(tmp))
        print(f"{'CHECK':<28} {'CATEGORY':<13} {'TOOL':<15} {'VERSION':<12} LANGUAGES")
        for a in all_adapters():
            if a.tool and not find_tool(a.tool):
                version = "MISSING"
            else:
                version = a.version(ctx) or "?"
            print(f"{a.id:<28} {a.category:<13} {a.scanner_name:<15} {version:<12} "
                  f"{','.join(a.languages) or 'any'}{'  [network]' if a.requires_network else ''}")
    return EXIT_OK


def _cmd_policies() -> int:
    for name in sorted(bundled_policies()):
        d = load_policy(name).describe()
        print(f"{d['id']}@{d['version']:<8} [{d['status']}] {d['title']}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "assess":
        return _cmd_assess(args)
    if args.command == "scanners":
        return _cmd_scanners()
    if args.command == "policies":
        return _cmd_policies()
    if args.command == "guidance":
        try:
            pack = load_guidance(args.pack)
        except GuidanceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
        d = pack.describe()
        print(f"{d['id']}@{d['version']} - {d['title']}  (bundled: {', '.join(sorted(bundled_guidance()))})")
        for p in pack.practices:
            print(f"\n  practice.{p['id']}  [{p.get('severity', 'low')}]  {p.get('title', '')}")
            print(f"    applies when: {', '.join(p.get('applies_when', ['code']))}")
            if p.get("why"):
                print(f"    why: {p['why']}")
            if p.get("how"):
                print(f"    how: {p['how']}")
        print(f"\n{len(pack.remediations)} remediation entries for scanner findings.")
        return EXIT_OK
    if args.command == "init-profile":
        target = Path(args.target)
        if target.exists():
            print(f"error: {target} already exists", file=sys.stderr)
            return EXIT_USAGE
        target.write_text(PROFILE_TEMPLATE, encoding="utf-8")
        print(f"wrote {target}")
        return EXIT_OK
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
