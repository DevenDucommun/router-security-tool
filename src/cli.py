"""
CLI interface for router-security-tool.

Usage:
    router-security-tool scan <host> [options]
    router-security-tool report <host> --output <file> [options]
"""

import argparse
import json
import sys
import os
import logging
from pathlib import Path

# Ensure src/ is on the path when run directly or as entry point
sys.path.insert(0, str(Path(__file__).parent))

from connections.manager import ConnectionManager  # noqa: E402
from assessment.ssh_assessor import SSHAssessor  # noqa: E402
from assessment.finding import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM  # noqa: E402

EXIT_CLEAN = 0
EXIT_LOW = 1
EXIT_HIGH = 2
EXIT_CRITICAL = 3


def severity_to_exit_code(severity_summary: dict) -> int:
    if severity_summary.get(SEVERITY_CRITICAL, 0) > 0:
        return EXIT_CRITICAL
    if severity_summary.get(SEVERITY_HIGH, 0) > 0:
        return EXIT_HIGH
    if severity_summary.get(SEVERITY_MEDIUM, 0) > 0:
        return EXIT_LOW
    return EXIT_CLEAN


def print_findings_table(results: dict):
    """Print findings in a human-readable table."""
    device = results["device_info"]
    hostname = device.get("hostname") or "unknown"
    uname = device.get("uname", "")
    profile = results.get("profile") or "generic"

    print(f"\n{'═' * 70}")
    print("  Router Security Assessment")
    print(f"{'─' * 70}")
    print(f"  Host:     {hostname}")
    print(f"  Kernel:   {uname[:60]}")
    print(f"  Profile:  {profile}")
    print(f"  Findings: {results['finding_count']}")
    print(f"{'═' * 70}")

    if not results["findings"]:
        print("  No security findings.")
    else:
        for f in results["findings"]:
            sev = f["severity"]
            color = {
                "Critical": "\033[91m",
                "High": "\033[93m",
                "Medium": "\033[33m",
                "Low": "\033[36m",
                "Info": "\033[90m",
            }.get(sev, "")
            reset = "\033[0m" if color else ""
            print(f"  {color}[{sev:8}]{reset} {f['id']:18} {f['title']}")

    print(f"{'═' * 70}")

    summary = results["severity_summary"]
    parts = []
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = summary.get(sev, 0)
        if count:
            parts.append(f"{count} {sev}")
    print(f"  Summary: {', '.join(parts) if parts else 'Clean'}")
    print()


def print_findings_detail(results: dict):
    """Print findings with full detail (evidence + remediation)."""
    print_findings_table(results)

    if not results["findings"]:
        return

    print(f"{'─' * 70}")
    print("  DETAILS")
    print(f"{'─' * 70}")
    for f in results["findings"]:
        print(f"\n  [{f['severity']}] {f['id']}: {f['title']}")
        print(f"  {f['description']}")
        if f.get("evidence"):
            evidence = f["evidence"].replace("\n", "\n    ")
            print(f"    Evidence: {evidence[:200]}")
        if f.get("remediation"):
            print(f"    Fix: {f['remediation']}")
    print()


def cmd_scan(args):
    """Execute a security scan against a target host."""
    host = args.host
    user = args.user or os.environ.get("ROUTER_USER", "root")
    password = args.password or os.environ.get("ROUTER_PASS")
    port = args.port

    if not password:
        print("Error: password required. Use --password or set ROUTER_PASS env var.",
              file=sys.stderr)
        return EXIT_CRITICAL

    if not args.json:
        print(f"Connecting to {host}:{port} as {user}...")

    conn = ConnectionManager()
    success = conn.connect_ssh(host, user, password, port=port)
    if not success:
        msg = f"Failed to connect to {host}:{port}"
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            print(f"Error: {msg}", file=sys.stderr)
        return EXIT_CRITICAL

    try:
        assessor = SSHAssessor(conn)

        def _progress(msg):
            print(f"  > {msg}")

        progress_cb = None
        if not args.json and not args.quiet:
            progress_cb = _progress

        results = assessor.run_assessment(progress_callback=progress_cb)

        if args.json:
            print(json.dumps(results, indent=2))
        elif args.verbose:
            print_findings_detail(results)
        else:
            print_findings_table(results)

        return severity_to_exit_code(results["severity_summary"])

    finally:
        conn.disconnect()


def cmd_report(args):
    """Run scan and export report to file."""
    host = args.host
    user = args.user or os.environ.get("ROUTER_USER", "root")
    password = args.password or os.environ.get("ROUTER_PASS")
    port = args.port
    output = Path(args.output)

    if not password:
        print("Error: password required. Use --password or set ROUTER_PASS env var.",
              file=sys.stderr)
        return EXIT_CRITICAL

    if not args.quiet:
        print(f"Connecting to {host}:{port} as {user}...")

    conn = ConnectionManager()
    success = conn.connect_ssh(host, user, password, port=port)
    if not success:
        print(f"Error: Failed to connect to {host}:{port}", file=sys.stderr)
        return EXIT_CRITICAL

    try:
        assessor = SSHAssessor(conn)
        progress_cb = None if args.quiet else lambda msg: print(f"  > {msg}")
        results = assessor.run_assessment(progress_callback=progress_cb)

        # Determine format from extension
        suffix = output.suffix.lower()
        if suffix == ".json":
            output.write_text(json.dumps(results, indent=2))
        elif suffix == ".html":
            from reports.export import ReportExporter
            exporter = ReportExporter()
            exporter.export_html(results, str(output))
        else:
            output.write_text(json.dumps(results, indent=2))

        if not args.quiet:
            print(f"\nReport saved to: {output}")
            print_findings_table(results)

        return severity_to_exit_code(results["severity_summary"])

    finally:
        conn.disconnect()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="router-security-tool",
        description="Network device security assessment tool",
        epilog="Exit codes: 0=clean, 1=medium findings, 2=high findings, 3=critical",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- scan --
    scan_parser = subparsers.add_parser("scan", help="Run security assessment")
    scan_parser.add_argument("host", help="Target hostname or IP")
    scan_parser.add_argument("-u", "--user", help="SSH username (default: root, or ROUTER_USER env)")
    scan_parser.add_argument("-p", "--password", help="SSH password (or set ROUTER_PASS env)")
    scan_parser.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    scan_parser.add_argument("--json", action="store_true", help="Output results as JSON")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Show evidence and remediation")
    scan_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    scan_parser.set_defaults(func=cmd_scan)

    # -- report --
    report_parser = subparsers.add_parser("report", help="Run scan and export report")
    report_parser.add_argument("host", help="Target hostname or IP")
    report_parser.add_argument("-o", "--output", required=True, help="Output file (.json or .html)")
    report_parser.add_argument("-u", "--user", help="SSH username (default: root, or ROUTER_USER env)")
    report_parser.add_argument("-p", "--password", help="SSH password (or set ROUTER_PASS env)")
    report_parser.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    report_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    report_parser.set_defaults(func=cmd_report)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return EXIT_CLEAN

    log_level = logging.ERROR if getattr(args, 'json', False) else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
    )

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
