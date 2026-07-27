#!/usr/bin/env python3

"""
===============================================================================
                     Prisma Cloud Defender Inventory & Health Report
===============================================================================

Author  : Stan Zvenigorodskiy
Version : 2.0

Description
-----------
Enterprise inventory and health reporting utility for Prisma Cloud Compute
Defenders.

The script authenticates using the official pcpi SDK, retrieves Defender
inventory from the Prisma Cloud Compute API, normalizes inconsistent API
responses, evaluates Defender health, and generates detailed inventory
reports for virtual machines, Kubernetes, and Amazon EKS environments.

Designed for security engineers and cloud administrators who need a quick
view of Defender deployment, connectivity, version compliance, and overall
coverage across large environments.

===============================================================================
FEATURES
===============================================================================

✓ Authenticate using the official pcpi Python SDK

✓ Retrieve all Defenders from Prisma Cloud Compute

✓ Pagination-safe Defender retrieval using limit=100

✓ Automatic Console Version detection

✓ Inventory VM, Kubernetes and EKS Defenders

✓ Automatic EKS / Kubernetes discovery

✓ Normalize inconsistent Prisma API fields

✓ Detect disconnected Defenders

✓ Detect outdated Defender versions

✓ Detect missing cluster names

✓ Detect missing instance IDs

✓ Group Defenders by Cluster or Cloud Provider

✓ Generate CSV inventory reports

✓ Generate JSON reports

✓ Generate interactive HTML Dashboard

✓ Console summary and health statistics

✓ Quiet mode

✓ Summary-only mode

✓ Issue-only filtering

===============================================================================
SUPPORTED MODES
===============================================================================

Default

    Display all Prisma Cloud Defenders

--eks_only

    Display only Kubernetes / Amazon EKS Defenders

--only_issues

    Display only unhealthy Defenders

--summary_only

    Display cluster summary only

--quiet

    Suppress terminal output

===============================================================================
GENERATED REPORTS
===============================================================================

CSV

    defenders_inventory.csv

JSON

    defenders_inventory.json

HTML Dashboard

    defenders_inventory_dashboard.html

When using --eks_only

    defenders_eks_inventory.csv

    defenders_eks_inventory.json

    defenders_eks_inventory_dashboard.html

===============================================================================
INFORMATION COLLECTED
===============================================================================

• Cluster Name

• Hostname

• Instance ID

• Defender Connection Status

• Defender Version

• Defender Type

• Cloud Provider

• AWS Account / Project ID

• Cloud Region

• Health Issues

===============================================================================
HEALTH VALIDATION
===============================================================================

Each Defender is automatically evaluated for

✓ Connected

✓ Running latest Console version

✓ Cluster detected

✓ Instance ID detected

Reported Issues

• disconnected

• outdated

• missing-version

• missing-cluster

• missing-instance-id

• version-parse-error

===============================================================================
PREREQUISITES
===============================================================================

Python 3.10+

Required packages

    pip install pcpi packaging

Prisma Cloud Compute credentials configured using the pcpi SDK.

Example

~/.prismacloud/credentials

===============================================================================
PRISMA CLOUD APIs USED
===============================================================================

GET /api/v1/version

    Retrieves current Console version

GET /api/v1/defenders

    Retrieves complete Defender inventory using limit=100 offset pagination

===============================================================================
USAGE
===============================================================================

Display all Defenders

python pcs_eks_defender_inventory.py

Display only EKS Defenders

python pcs_eks_defender_inventory.py --eks_only

Generate all reports

python pcs_eks_defender_inventory.py \
    --csv \
    --json \
    --html

Generate EKS dashboard

python pcs_eks_defender_inventory.py \
    --eks_only \
    --csv \
    --json \
    --html

Display only unhealthy Defenders

python pcs_eks_defender_inventory.py \
    --only_issues

Summary only

python pcs_eks_defender_inventory.py \
    --summary_only

===============================================================================
TERMINAL OUTPUT
===============================================================================

✔ Prisma Cloud Authentication

✔ Console Version

✔ Total Defenders

✔ Defender Inventory

✔ Cluster Summary

✔ Connected vs Disconnected

✔ Version Compliance

✔ Generated Reports

===============================================================================
OUTPUT FILES
===============================================================================

CSV

    Defender inventory suitable for Excel.

JSON

    Complete structured inventory for automation.

HTML

    Interactive dashboard with

    • Summary cards

    • Cluster statistics

    • Provider statistics

    • Health overview

    • Searchable Defender inventory

===============================================================================
BEST PRACTICES
===============================================================================

• Run after every Defender deployment.

• Validate Defender version after Console upgrades.

• Periodically review disconnected Defenders.

• Export HTML reports for management reviews.

• Schedule the script using cron or Jenkins for continuous inventory reporting.

===============================================================================
AUTHOR
===============================================================================

Stan Zvenigorodskiy

Senior DevSecOps / Cloud Security Engineer

AWS | Kubernetes | Prisma Cloud | Cortex Cloud | Python | Terraform |
Security Automation | Splunk

===============================================================================
"""
from packaging import version
from pcpi import session_loader
import csv
import json
import argparse
import time
from html import escape
from pathlib import Path
from datetime import datetime, timezone

# ---------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------

parser = argparse.ArgumentParser(description="Prisma Cloud Defender Inventory")

parser.add_argument(
    "--csv",
    action="store_true",
    help="Save compact output to defenders_inventory.csv",
)

parser.add_argument(
    "--json",
    action="store_true",
    help="Save detailed output to defenders_inventory.json",
)

parser.add_argument(
    "--html",
    action="store_true",
    help="Save self-contained HTML dashboard to defenders_inventory_dashboard.html",
)


parser.add_argument(
    "--output_dir",
    default=".",
    help="Directory where CSV, JSON, and HTML reports will be saved. Default: current directory.",
)

parser.add_argument(
    "--quiet",
    action="store_true",
    help="Suppress terminal output",
)

parser.add_argument(
    "--summary_only",
    action="store_true",
    help="Print only summary, skip per-host rows",
)

parser.add_argument(
    "--only_issues",
    action="store_true",
    help="Show only defenders with issues",
)

parser.add_argument(
    "--eks_only",
    action="store_true",
    help="Show only EKS/Kubernetes defenders",
)

args = parser.parse_args()

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

csv_file = None
csv_writer = None


def out(text: str) -> None:
    if not args.quiet:
        print(text)


def cloud_meta(defender):
    return defender.get("cloudMetadata") or {}


def orchestration_meta(defender):
    return defender.get("orchestrationMetadata") or {}


def labels(defender):
    raw = defender.get("labels")

    if not raw:
        return {}

    if isinstance(raw, dict):
        return raw

    if isinstance(raw, list):
        normalized = {}

        for item in raw:
            if isinstance(item, dict):
                if "key" in item and "value" in item:
                    normalized[str(item["key"])] = item["value"]
                elif "name" in item and "value" in item:
                    normalized[str(item["name"])] = item["value"]
                else:
                    for k, v in item.items():
                        normalized[str(k)] = v
            elif isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                normalized[k.strip()] = v.strip()

        return normalized

    return {}


def get_cluster(defender):
    o = orchestration_meta(defender)
    c = cloud_meta(defender)
    l = labels(defender)

    candidates = [
        defender.get("cluster"),
        o.get("cluster"),
        o.get("clusterName"),
        o.get("name"),
        c.get("cluster"),
        l.get("cluster"),
        l.get("clusterName"),
        l.get("kubernetes.cluster"),
    ]

    for value in candidates:
        if value:
            return str(value).strip()

    return "Unknown"


def get_hostname(defender):
    candidates = [
        defender.get("hostname"),
        defender.get("hostName"),
        defender.get("name"),
        defender.get("host"),
        cloud_meta(defender).get("hostname"),
        defender.get("id"),
    ]

    for value in candidates:
        if value:
            return str(value).strip()

    return "Unknown"


def get_instance_id(defender):
    cloud = cloud_meta(defender)
    orch = orchestration_meta(defender)

    candidates = [
        cloud.get("instanceID"),
        cloud.get("instanceId"),
        defender.get("instanceID"),
        defender.get("instanceId"),
        cloud.get("resourceID"),
        cloud.get("resourceId"),
        cloud.get("providerResourceId"),
        cloud.get("hostId"),
        cloud.get("hostID"),
        defender.get("hostId"),
        defender.get("hostID"),
        defender.get("resourceId"),
        defender.get("resourceID"),
        orch.get("instanceId"),
        orch.get("instanceID"),
        defender.get("id"),
    ]

    for value in candidates:
        if value:
            return str(value).strip()

    return "Unknown"


def get_provider(defender):
    meta = cloud_meta(defender)
    return (
        meta.get("provider")
        or meta.get("cloudProvider")
        or meta.get("cloudType")
        or defender.get("provider")
        or "Unknown"
    )


def get_account(defender):
    meta = cloud_meta(defender)
    return (
        meta.get("accountID")
        or meta.get("accountId")
        or meta.get("projectId")
        or defender.get("accountId")
        or "Unknown"
    )


def get_region(defender):
    meta = cloud_meta(defender)
    return (
        meta.get("region")
        or meta.get("awsRegion")
        or meta.get("location")
        or defender.get("region")
        or "Unknown"
    )


def get_connected(defender):
    return defender.get("connected", "Unknown")


def get_defender_type(defender):
    return (
        defender.get("type")
        or defender.get("defenderType")
        or defender.get("service")
        or "Unknown"
    )


def get_defender_version(defender):
    return str(defender.get("version") or "")


def is_k8s_or_eks(defender):
    cluster = str(get_cluster(defender)).lower()
    orchestration = str(defender.get("orchestration", "")).lower()
    orchestrator = str(defender.get("orchestrator", "")).lower()
    dtype = str(get_defender_type(defender)).lower()
    raw = json.dumps(defender).lower()

    return (
        "eks" in cluster
        or "kubernetes" in cluster
        or orchestration == "kubernetes"
        or orchestrator == "kubernetes"
        or "container" in dtype
        or "kubernetes" in dtype
        or "daemonset" in dtype
        or '"cluster"' in raw
        or "eks" in raw
        or "kubernetes" in raw
    )


def build_issues(defender, console_version):
    issues = []

    connected = get_connected(defender)
    if str(connected).lower() != "true":
        issues.append("disconnected")

    dver = get_defender_version(defender)
    if dver:
        try:
            if console_version and version.parse(dver) < version.parse(console_version):
                issues.append("outdated")
        except Exception:
            issues.append("version-parse-error")
    else:
        issues.append("missing-version")

    if get_cluster(defender) == "Unknown":
        issues.append("missing-cluster")

    if get_instance_id(defender) == "Unknown":
        issues.append("missing-instance-id")

    return ";".join(issues) if issues else "healthy"



# ---------------------------------------------------------------------
# HTML DASHBOARD: Create a self-contained executive Defender dashboard
# ---------------------------------------------------------------------

def write_html_dashboard(rows, group_summary, console_version, output_path):
    """
    Build a standalone HTML dashboard from the processed Defender inventory rows.

    The file is fully self-contained and can be opened locally in a browser.
    No external JavaScript, CSS, or web server is required.
    """
    total = len(rows)
    connected_count = sum(1 for r in rows if str(r.get("connected", "")).lower() == "true")
    issue_count = sum(1 for r in rows if r.get("issues") != "healthy")
    healthy_count = total - issue_count
    disconnected_count = total - connected_count

    outdated_count = sum(1 for r in rows if "outdated" in str(r.get("issues", "")))
    missing_cluster_count = sum(1 for r in rows if "missing-cluster" in str(r.get("issues", "")))
    missing_instance_count = sum(1 for r in rows if "missing-instance-id" in str(r.get("issues", "")))

    provider_counts = {}
    region_counts = {}
    type_counts = {}

    for row in rows:
        provider_counts[row.get("provider") or "Unknown"] = provider_counts.get(row.get("provider") or "Unknown", 0) + 1
        region_counts[row.get("region") or "Unknown"] = region_counts.get(row.get("region") or "Unknown", 0) + 1
        type_counts[row.get("type") or "Unknown"] = type_counts.get(row.get("type") or "Unknown", 0) + 1

    def render_bar_table(title, data):
        if not data:
            return f"<h2>{escape(title)}</h2><p>No data.</p>"

        max_value = max(data.values()) or 1
        lines = [f"<h2>{escape(title)}</h2>", "<table>", "<tr><th>Name</th><th>Count</th><th>Bar</th></tr>"]
        for name, count in sorted(data.items(), key=lambda x: x[1], reverse=True):
            pct = int((count / max_value) * 100)
            lines.append(
                "<tr>"
                f"<td>{escape(str(name))}</td>"
                f"<td>{count}</td>"
                f"<td><div class='bar'><span style='width:{pct}%'></span></div></td>"
                "</tr>"
            )
        lines.append("</table>")
        return "\n".join(lines)

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Prisma Cloud Defender Inventory Dashboard</title>
<style>
    body {{
        font-family: Arial, Helvetica, sans-serif;
        margin: 28px;
        background: #f4f6f8;
        color: #1f2937;
    }}
    h1 {{ margin-bottom: 5px; }}
    h2 {{ margin-top: 28px; }}
    .subtitle {{ color: #6b7280; margin-bottom: 22px; }}
    .cards {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
        gap: 14px;
        margin-bottom: 25px;
    }}
    .card {{
        background: white;
        border-radius: 12px;
        padding: 18px;
        box-shadow: 0 2px 8px rgba(0,0,0,.08);
    }}
    .label {{ color: #6b7280; font-size: 13px; }}
    .num {{ font-size: 30px; font-weight: bold; margin-top: 8px; }}
    table {{
        width: 100%;
        border-collapse: collapse;
        background: white;
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 2px 8px rgba(0,0,0,.08);
    }}
    th, td {{
        padding: 10px;
        border-bottom: 1px solid #e5e7eb;
        text-align: left;
        font-size: 13px;
    }}
    th {{ background: #111827; color: white; }}
    tr:hover {{ background: #f9fafb; }}
    .ok {{ color: #047857; font-weight: bold; }}
    .bad {{ color: #b91c1c; font-weight: bold; }}
    .warn {{ color: #b45309; font-weight: bold; }}
    .bar {{ background: #e5e7eb; border-radius: 8px; width: 100%; height: 12px; }}
    .bar span {{ display: block; height: 12px; background: #374151; border-radius: 8px; }}
    .small {{ font-size: 12px; color: #6b7280; }}
</style>
</head>
<body>
<h1>Prisma Cloud Defender Inventory Dashboard</h1>
<div class="subtitle">Console Version: {escape(str(console_version or "Unknown"))}</div>

<div class="cards">
    <div class="card"><div class="label">Total Defenders</div><div class="num">{total}</div></div>
    <div class="card"><div class="label">Connected</div><div class="num ok">{connected_count}</div></div>
    <div class="card"><div class="label">Disconnected</div><div class="num bad">{disconnected_count}</div></div>
    <div class="card"><div class="label">Healthy</div><div class="num ok">{healthy_count}</div></div>
    <div class="card"><div class="label">With Issues</div><div class="num bad">{issue_count}</div></div>
    <div class="card"><div class="label">Outdated</div><div class="num warn">{outdated_count}</div></div>
    <div class="card"><div class="label">Missing Cluster</div><div class="num warn">{missing_cluster_count}</div></div>
    <div class="card"><div class="label">Missing Instance ID</div><div class="num warn">{missing_instance_count}</div></div>
</div>

<h2>Cluster / Provider Summary</h2>
<table>
<tr><th>Group</th><th>Total</th><th>Connected</th><th>Issues</th></tr>
"""

    for group, stats in sorted(group_summary.items()):
        html += (
            "<tr>"
            f"<td>{escape(str(group))}</td>"
            f"<td>{stats.get('total', 0)}</td>"
            f"<td class='ok'>{stats.get('connected', 0)}</td>"
            f"<td class='bad'>{stats.get('issues', 0)}</td>"
            "</tr>\n"
        )

    html += "</table>\n"
    html += render_bar_table("Defenders by Provider", provider_counts)
    html += render_bar_table("Defenders by Region", region_counts)
    html += render_bar_table("Defenders by Type", type_counts)

    html += """
<h2>Defender Details</h2>
<table>
<tr>
    <th>Cluster / Provider</th>
    <th>Hostname</th>
    <th>Instance ID</th>
    <th>Connected</th>
    <th>Version</th>
    <th>Type</th>
    <th>Issues</th>
    <th>Account</th>
    <th>Region</th>
</tr>
"""

    for row in sorted(rows, key=lambda r: (r["cluster"], r["hostname"])):
        group_value = row["cluster"] if row["cluster"] != "Unknown" else row["provider"]
        connected_class = "ok" if str(row.get("connected", "")).lower() == "true" else "bad"
        issue_class = "ok" if row.get("issues") == "healthy" else "bad"

        html += (
            "<tr>"
            f"<td>{escape(str(group_value))}</td>"
            f"<td>{escape(str(row.get('hostname', '')))}</td>"
            f"<td>{escape(str(row.get('instance_id', '')))}</td>"
            f"<td class='{connected_class}'>{escape(str(row.get('connected', '')))}</td>"
            f"<td>{escape(str(row.get('version', '')))}</td>"
            f"<td>{escape(str(row.get('type', '')))}</td>"
            f"<td class='{issue_class}'>{escape(str(row.get('issues', '')))}</td>"
            f"<td>{escape(str(row.get('account', '')))}</td>"
            f"<td>{escape(str(row.get('region', '')))}</td>"
            "</tr>\n"
        )

    html += """
</table>
<p class="small">Generated by pcs_eks_defender_inventory.py</p>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as html_file:
        html_file.write(html)

    return output_path




def write_csv_report(rows, output_path, fieldnames):
    """Write Defender inventory rows to CSV after processing completes."""
    with open(output_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return output_path


def write_json_report(rows, group_summary, console_version, output_path):
    """Write a detailed JSON report after processing completes."""
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "console_version": console_version,
        "total_rows": len(rows),
        "summary": group_summary,
        "rows": rows,
    }
    with open(output_path, "w", encoding="utf-8") as json_file:
        json.dump(payload, json_file, indent=2)
    return output_path



# ---------------------------------------------------------------------
# API HELPER: Retrieve ALL Defenders with limit=100 pagination + retry
# ---------------------------------------------------------------------

def request_with_retry(session, method, endpoint, params=None, max_retries=5, sleep_seconds=2):
    """
    Execute Prisma Cloud Compute API request with retry for transient errors.

    Retries:
    - 429 rate limit
    - 500 internal server error
    - 502 bad gateway
    - 503 service unavailable
    - 504 gateway timeout
    """
    last_response = None

    for attempt in range(1, max_retries + 1):
        response = session.request(method, endpoint, params=params)
        last_response = response

        if response.ok:
            return response

        if response.status_code not in (429, 500, 502, 503, 504):
            return response

        wait_time = sleep_seconds * attempt
        out(
            f"Transient API error {response.status_code} on {endpoint}. "
            f"Retry {attempt}/{max_retries} in {wait_time}s..."
        )
        time.sleep(wait_time)

    return last_response


def extract_defender_items(payload):
    """
    Normalize Prisma response shapes.

    Supports:
    - plain list: [ {...}, {...} ]
    - wrapped dict: {"items": [...]}
    - wrapped dict: {"defenders": [...]}
    - wrapped dict: {"data": [...]}
    - wrapped dict: {"results": [...]}
    """
    if isinstance(payload, list):
        return payload

    if isinstance(payload, dict):
        for key in ("items", "defenders", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return value

    return []


def defender_unique_key(defender):
    """
    Build stable key to deduplicate defenders across pages.
    """
    if not isinstance(defender, dict):
        return str(defender)

    return str(
        defender.get("id")
        or defender.get("_id")
        or defender.get("hostname")
        or defender.get("hostName")
        or defender.get("name")
        or defender.get("instanceId")
        or defender.get("instanceID")
        or json.dumps(defender, sort_keys=True)
    )


def get_all_defenders(session, page_size=100):
    """
    Retrieve every Defender from Prisma Cloud Compute.

    Prisma API rejected higher limits with:
        {"err":"limit must be at most 100"}

    Therefore page_size defaults to 100.
    """
    all_defenders = []
    seen_keys = set()
    offset = 0
    page_number = 1

    while True:
        params = {
            "limit": page_size,
            "offset": offset,
        }

        response = request_with_retry(session, "GET", "/api/v1/defenders", params=params)

        if not response.ok:
            raise SystemExit(
                f"Failed to pull defenders: {response.status_code} {response.text}"
            )

        payload = response.json()
        items = extract_defender_items(payload)

        if not items:
            if offset == 0:
                out("No defenders returned by API.")
            break

        new_count = 0

        for defender in items:
            if not isinstance(defender, dict):
                continue

            key = defender_unique_key(defender)

            if key in seen_keys:
                continue

            seen_keys.add(key)
            all_defenders.append(defender)
            new_count += 1

        out(
            f"Loaded page {page_number}: {len(items)} returned, "
            f"{new_count} new, total loaded {len(all_defenders)}"
        )

        # Last page.
        if len(items) < page_size:
            break

        # API ignored offset or returned duplicates; stop to avoid infinite loop.
        if new_count == 0:
            out(
                "Pagination returned duplicate data or API ignored offset. "
                "Stopping to avoid infinite loop."
            )
            break

        offset += page_size
        page_number += 1

    return all_defenders


# ---------------------------------------------------------------------
# Init auth using pcpi
# ---------------------------------------------------------------------

session_managers = session_loader.load_config()

if not session_managers:
    raise SystemExit("No Prisma Cloud session managers were loaded from config.")

session_man = session_managers[0]

try:
    cwp_session = session_man.create_cwp_session()
except Exception as e:
    raise SystemExit(f"Failed to create Prisma Cloud CWP session: {e}")

out("✅ Prisma Cloud authentication successful")
out("")

# ---------------------------------------------------------------------
# Fetch data
# ---------------------------------------------------------------------

version_response = cwp_session.request("GET", "/api/v1/version")
if not version_response.ok:
    raise SystemExit(
        f"Failed to pull console version: {version_response.status_code} {version_response.text}"
    )

version_payload = version_response.json()

if isinstance(version_payload, dict):
    console_version = (
        version_payload.get("version")
        or version_payload.get("consoleVersion")
        or version_payload.get("release")
        or ""
    )
else:
    console_version = str(version_payload)

defenders = get_all_defenders(cwp_session)

out(f"Current Console Version: {console_version}")
out(f"Total Defenders loaded from API: {len(defenders)}")
out("")

# ---------------------------------------------------------------------
# Prepare output files
# ---------------------------------------------------------------------

rows = []
group_summary = {}

# If no explicit report flags are supplied, generate all reports by default.
# This prevents the common issue where the script runs successfully but no
# report files are created because --csv/--json/--html were omitted.
generate_all_reports = not (args.csv or args.json or args.html)
generate_csv = args.csv or generate_all_reports
generate_json = args.json or generate_all_reports
generate_html = args.html or generate_all_reports

output_dir = Path(args.output_dir).expanduser().resolve()
output_dir.mkdir(parents=True, exist_ok=True)

base_name = "defenders_eks_inventory" if args.eks_only else "defenders_inventory"
csv_name = output_dir / f"{base_name}.csv"
json_name = output_dir / f"{base_name}.json"
html_name = output_dir / f"{base_name}_dashboard.html"

fieldnames = [
    "cluster",
    "hostname",
    "instance_id",
    "connected",
    "version",
    "type",
    "issues",
    "provider",
    "account",
    "region",
]

# ---------------------------------------------------------------------
# Process defenders
# ---------------------------------------------------------------------

for defender in defenders:
    if args.eks_only and not is_k8s_or_eks(defender):
        continue

    cluster = get_cluster(defender)
    hostname = get_hostname(defender)
    instance_id = get_instance_id(defender)
    connected = get_connected(defender)
    dver = get_defender_version(defender)
    dtype = get_defender_type(defender)
    provider = get_provider(defender)
    account = get_account(defender)
    region = get_region(defender)
    issues = build_issues(defender, console_version)

    if args.only_issues and issues == "healthy":
        continue

    row = {
        "cluster": cluster,
        "hostname": hostname,
        "instance_id": instance_id,
        "connected": connected,
        "version": dver,
        "type": dtype,
        "issues": issues,
        "provider": provider,
        "account": account,
        "region": region,
    }
    rows.append(row)

    group_key = cluster if cluster != "Unknown" else provider

    if group_key not in group_summary:
        group_summary[group_key] = {"total": 0, "connected": 0, "issues": 0}
    group_summary[group_key]["total"] += 1
    if str(connected).lower() == "true":
        group_summary[group_key]["connected"] += 1
    if issues != "healthy":
        group_summary[group_key]["issues"] += 1


# ---------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------

if not args.summary_only:
    title = "Prisma Cloud Defender Inventory"
    if args.eks_only:
        title = "Prisma Cloud Defender Inventory by EKS Cluster"

    out(title)
    out("=" * 140)
    out(
        f"{'CLUSTER/PROVIDER':22} {'HOSTNAME':28} {'INSTANCE_ID':20} "
        f"{'CONNECTED':10} {'VERSION':14} {'TYPE':16} {'ISSUES':18}"
    )
    out("-" * 140)

    for row in sorted(rows, key=lambda r: (r["cluster"], r["hostname"])):
        group_value = row["cluster"] if row["cluster"] != "Unknown" else row["provider"]
        out(
            f"{str(group_value)[:22]:22} "
            f"{str(row['hostname'])[:28]:28} "
            f"{str(row['instance_id'])[:20]:20} "
            f"{str(row['connected'])[:10]:10} "
            f"{str(row['version'])[:14]:14} "
            f"{str(row['type'])[:16]:16} "
            f"{str(row['issues'])[:18]:18}"
        )

    out("")

# ---------------------------------------------------------------------
# Summary output
# ---------------------------------------------------------------------

summary_title = "Summary"
if args.eks_only:
    summary_title = "EKS Cluster Summary"

out(summary_title)
out("=" * 60)
out(f"{'GROUP':22} {'TOTAL':8} {'CONNECTED':10} {'ISSUES':8}")
out("-" * 60)

for group, stats in sorted(group_summary.items()):
    out(
        f"{str(group)[:22]:22} "
        f"{stats['total']:<8} "
        f"{stats['connected']:<10} "
        f"{stats['issues']:<8}"
    )

out("")
out(f"Total Defenders reported: {len(rows)}")

# ---------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------

created_reports = []

if generate_csv:
    created_reports.append(("CSV", write_csv_report(rows, csv_name, fieldnames)))

if generate_json:
    created_reports.append(("JSON", write_json_report(rows, group_summary, console_version, json_name)))

if generate_html:
    created_reports.append(("HTML", write_html_dashboard(rows, group_summary, console_version, html_name)))

out("")
out("Reports created:")
for report_type, report_path in created_reports:
    out(f"{report_type}: {report_path}")

if not created_reports:
    out("No report files requested. Use --csv, --json, --html, or omit all three to generate all reports.")
