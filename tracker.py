#!/usr/bin/env python3
"""
vuln-tracker: track security findings through their lifecycle.

Scanners are good at finding problems. They are not good at telling you
which ones got fixed. This is the missing middle: log a finding, move it
from open to resolved, and export a report you can hand to a manager or
a client.

Standard library only. Findings live in findings.json next to this script.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["open", "in-progress", "resolved", "false-positive"]
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

DATA_FILE = Path(__file__).resolve().parent / "findings.json"


def now_stamp():
    return datetime.now().isoformat(timespec="seconds")


def load():
    if not DATA_FILE.exists():
        return []
    try:
        with open(DATA_FILE) as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error: could not read {DATA_FILE}: {exc}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(data, list):
        print(f"Error: {DATA_FILE} does not contain a list of findings.",
              file=sys.stderr)
        sys.exit(1)
    return data


def save(findings):
    try:
        with open(DATA_FILE, "w") as fh:
            json.dump(findings, fh, indent=2)
            fh.write("\n")
    except OSError as exc:
        print(f"Error: could not write {DATA_FILE}: {exc}", file=sys.stderr)
        sys.exit(1)


def next_id(findings):
    return max((f["id"] for f in findings), default=0) + 1


def normalize_severity(value):
    value = str(value).strip().lower()
    if value in SEVERITIES:
        return value
    print(f"Warning: unknown severity '{value}', using 'medium'.")
    return "medium"


def normalize_status(value):
    value = str(value).strip().lower().replace("_", "-")
    if value in STATUSES:
        return value
    print(f"Warning: unknown status '{value}', using 'open'.")
    return "open"


def add_finding(findings, title, severity, source, description,
                status="open"):
    finding = {
        "id": next_id(findings),
        "title": title,
        "severity": normalize_severity(severity),
        "status": normalize_status(status),
        "source": source,
        "description": description,
        "created": now_stamp(),
        "updated": now_stamp(),
    }
    findings.append(finding)
    return finding


def find_by_id(findings, fid):
    for finding in findings:
        if finding["id"] == fid:
            return finding
    return None


def sort_key(finding):
    return (SEVERITY_RANK.get(finding["severity"], 99), finding["id"])


def print_table(findings):
    if not findings:
        print("No findings match.")
        return
    rows = sorted(findings, key=sort_key)
    print(f"{'ID':<4} {'SEVERITY':<9} {'STATUS':<13} TITLE")
    print("-" * 70)
    for f in rows:
        print(f"{f['id']:<4} {f['severity']:<9} {f['status']:<13} "
              f"{f['title']}")


def print_detail(finding):
    print(f"[{finding['id']}] {finding['title']}")
    print(f"  Severity : {finding['severity']}")
    print(f"  Status   : {finding['status']}")
    print(f"  Source   : {finding['source']}")
    print(f"  Created  : {finding['created']}")
    print(f"  Updated  : {finding['updated']}")
    print(f"  Details  : {finding['description']}")


def summary_counts(findings):
    by_sev = {s: 0 for s in SEVERITIES}
    by_status = {s: 0 for s in STATUSES}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
    return by_sev, by_status


def print_summary(findings):
    by_sev, by_status = summary_counts(findings)
    open_count = (by_status["open"] + by_status["in-progress"])
    print(f"Total findings : {len(findings)}")
    print(f"Needs work     : {open_count} "
          f"(open: {by_status['open']}, in-progress: {by_status['in-progress']})")
    print(f"Closed out     : {by_status['resolved']} resolved, "
          f"{by_status['false-positive']} false-positive")
    print()
    print("By severity:")
    for sev in SEVERITIES:
        print(f"  {sev:<9} {by_sev[sev]}")


def render_report(findings):
    by_sev, by_status = summary_counts(findings)
    lines = []
    lines.append("# Vulnerability Findings Report")
    lines.append(f"Generated: {now_stamp()}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"Total findings tracked: {len(findings)}")
    lines.append("")
    lines.append("By severity:")
    lines.append("")
    for sev in SEVERITIES:
        lines.append(f"- {sev}: {by_sev[sev]}")
    lines.append("")
    lines.append("By status:")
    lines.append("")
    for status in STATUSES:
        lines.append(f"- {status}: {by_status[status]}")
    lines.append("")

    active = [f for f in findings
              if f["status"] in ("open", "in-progress")]
    done = [f for f in findings if f["status"] == "resolved"]
    dismissed = [f for f in findings if f["status"] == "false-positive"]

    lines.append("## Findings needing attention")
    lines.append("")
    if not active:
        lines.append("Nothing outstanding. All findings are resolved or "
                     "dismissed.")
        lines.append("")
    for f in sorted(active, key=sort_key):
        lines.append(f"### [{f['id']}] {f['title']} ({f['severity']})")
        lines.append("")
        lines.append(f"Status: {f['status']} | Source: {f['source']} | "
                     f"Found: {f['created']}")
        lines.append("")
        lines.append(f["description"])
        lines.append("")

    lines.append("## Resolved")
    lines.append("")
    if not done:
        lines.append("None yet.")
        lines.append("")
    for f in sorted(done, key=sort_key):
        lines.append(f"- [{f['id']}] {f['title']} ({f['severity']})")

    lines.append("")
    lines.append("## False positives")
    lines.append("")
    if not dismissed:
        lines.append("None.")
        lines.append("")
    for f in sorted(dismissed, key=sort_key):
        lines.append(f"- [{f['id']}] {f['title']} ({f['severity']})")
    lines.append("")
    return "\n".join(lines)


def import_scan_file(path, source):
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error: could not read {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    if isinstance(data, dict) and "findings" in data:
        items = data["findings"]
    elif isinstance(data, list):
        items = data
    else:
        print("Error: expected a JSON list of findings, or an object with "
              "a 'findings' list.", file=sys.stderr)
        sys.exit(1)
    imported = []
    for item in items:
        if not isinstance(item, dict) or "title" not in item:
            print("Warning: skipping an entry with no title.")
            continue
        imported.append({
            "title": item["title"],
            "severity": item.get("severity", "medium"),
            "source": source,
            "description": item.get("description", "Imported from scan."),
        })
    return imported


DEMO_FINDINGS = [
    {
        "title": "Reflected XSS in site search parameter",
        "severity": "critical",
        "source": "web-security-scanner",
        "description": "The q parameter on /search reflects input without "
                       "encoding. Confirmed with a benign script payload. "
                       "Any visitor clicking a crafted link runs attacker "
                       "JavaScript in the site's origin.",
        "status": "open",
    },
    {
        "title": "SSH exposed to the internet with password auth",
        "severity": "critical",
        "source": "manual review",
        "description": "Port 22 reachable from anywhere and "
                       "PasswordAuthentication is on. Brute-force attempts "
                       "are already showing up in auth.log. Should be key "
                       "only, behind the VPN.",
        "status": "in-progress",
    },
    {
        "title": "Missing Content-Security-Policy header",
        "severity": "high",
        "source": "web-security-scanner",
        "description": "No CSP header on any page. This is the main "
                       "browser-side defense against XSS, and without it a "
                       "single injection runs with full page privileges.",
        "status": "open",
    },
    {
        "title": "TLS 1.0 and 1.1 still negotiated",
        "severity": "medium",
        "source": "manual review",
        "description": "The server still negotiates TLS 1.0 and 1.1 for "
                       "old clients. Both are deprecated. Minimum should "
                       "be TLS 1.2.",
        "status": "open",
    },
    {
        "title": "Server version disclosed in response headers",
        "severity": "low",
        "source": "web-security-scanner",
        "description": "The Server header advertises the exact software "
                       "version. Not a vulnerability by itself, but it "
                       "makes an attacker's job easier. Strip it.",
        "status": "resolved",
    },
]


def seed_demo(findings, reset=False):
    if findings and not reset:
        print("findings.json already has data. Use --reset to reseed.")
        return 0
    if reset:
        findings.clear()
    for item in DEMO_FINDINGS:
        add_finding(findings, item["title"], item["severity"],
                    item["source"], item["description"],
                    status=item["status"])
    save(findings)
    return len(DEMO_FINDINGS)


def cmd_add(args):
    findings = load()
    finding = add_finding(findings, args.title, args.severity, args.source,
                          args.description, status=args.status)
    save(findings)
    print(f"Added finding [{finding['id']}]: {finding['title']}")


def cmd_list(args):
    findings = load()
    if args.status:
        findings = [f for f in findings if f["status"] == args.status]
    if args.severity:
        findings = [f for f in findings if f["severity"] == args.severity]
    if args.detail:
        for f in sorted(findings, key=sort_key):
            print_detail(f)
            print()
    else:
        print_table(findings)


def cmd_update(args):
    findings = load()
    finding = find_by_id(findings, args.id)
    if finding is None:
        print(f"Error: no finding with id {args.id}.", file=sys.stderr)
        sys.exit(1)
    finding["status"] = normalize_status(args.status)
    finding["updated"] = now_stamp()
    save(findings)
    print(f"[{finding['id']}] {finding['title']} -> {finding['status']}")


def cmd_resolve(args):
    findings = load()
    finding = find_by_id(findings, args.id)
    if finding is None:
        print(f"Error: no finding with id {args.id}.", file=sys.stderr)
        sys.exit(1)
    finding["status"] = "resolved"
    finding["updated"] = now_stamp()
    save(findings)
    print(f"[{finding['id']}] {finding['title']} -> resolved")


def cmd_summary(_args):
    print_summary(load())


def cmd_report(args):
    report = render_report(load())
    out = Path(args.output)
    try:
        out.write_text(report)
    except OSError as exc:
        print(f"Error: could not write {out}: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Wrote report to {out}")


def cmd_import(args):
    findings = load()
    items = import_scan_file(args.file, args.source)
    for item in items:
        finding = add_finding(findings, item["title"], item["severity"],
                              item["source"], item["description"])
        print(f"Imported [{finding['id']}]: {finding['title']} "
              f"({finding['severity']})")
    save(findings)
    print(f"Imported {len(items)} findings from {args.file}.")


def cmd_demo(args):
    findings = load()
    count = seed_demo(findings, reset=args.reset)
    if count:
        print(f"Seeded {count} demo findings into findings.json.")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Track security findings from open to resolved.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="add a finding")
    p_add.add_argument("--title", required=True)
    p_add.add_argument("--severity", required=True, choices=SEVERITIES)
    p_add.add_argument("--source", default="manual")
    p_add.add_argument("--description", required=True)
    p_add.add_argument("--status", default="open", choices=STATUSES)
    p_add.set_defaults(func=cmd_add)

    p_list = sub.add_parser("list", help="list findings")
    p_list.add_argument("--status", choices=STATUSES)
    p_list.add_argument("--severity", choices=SEVERITIES)
    p_list.add_argument("--detail", action="store_true",
                        help="show full details for each finding")
    p_list.set_defaults(func=cmd_list)

    p_update = sub.add_parser("update", help="change a finding's status")
    p_update.add_argument("id", type=int)
    p_update.add_argument("--status", required=True, choices=STATUSES)
    p_update.set_defaults(func=cmd_update)

    p_resolve = sub.add_parser("resolve", help="mark a finding resolved")
    p_resolve.add_argument("id", type=int)
    p_resolve.set_defaults(func=cmd_resolve)

    p_summary = sub.add_parser("summary", help="counts by severity/status")
    p_summary.set_defaults(func=cmd_summary)

    p_report = sub.add_parser("report", help="export a markdown report")
    p_report.add_argument("--output", default="report.md")
    p_report.set_defaults(func=cmd_report)

    p_import = sub.add_parser("import", help="import a JSON scan report")
    p_import.add_argument("--file", required=True)
    p_import.add_argument("--source", default="scan import")
    p_import.set_defaults(func=cmd_import)

    p_demo = sub.add_parser("demo", help="seed realistic demo findings")
    p_demo.add_argument("--reset", action="store_true",
                        help="wipe existing findings first")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
