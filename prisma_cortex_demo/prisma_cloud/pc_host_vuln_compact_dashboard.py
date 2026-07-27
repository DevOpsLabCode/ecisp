#!/usr/bin/env python3

# =============================================================================
# Prisma Cloud Host Vulnerability Report 
#
# Pulls host + vulnerability data from Prisma Cloud Compute (/api/v1/hosts)
# using pcpi session_loader authentication.
#
# Extracts:
# - Host: hostname, resource_id, cluster, account_id, region
# - Vulnerabilities: CVE, package, version, severity, fix_status, discovered
#
# Normalizes inconsistent API fields (labels, metadata, CVE formats).
#
# Output:
# - Terminal summary (first 50 rows)
# - CSV: host_vuln_compact.csv
#
# Use cases: quick triage, CVE reporting, EKS/AWS coverage validation
# =============================================================================
from pcpi import session_loader   # Prisma Cloud Python SDK (pcpi auth)
import csv                        # CSV export
import re                         # regex (for CVE detection)

# -----------------------------------------------------------------------------
# AUTH: Load Prisma credentials from local config (~/.prismacloud/credentials)
# -----------------------------------------------------------------------------

session_managers = session_loader.load_config()   # returns list of session objects

if not session_managers:
    raise SystemExit("No Prisma Cloud session managers were loaded from config.")

session_man = session_managers[0]  # take first profile (most setups only have one)

try:
    cwp_session = session_man.create_cwp_session()  # create Compute (CWP) session
except Exception as e:
    raise SystemExit(f"Failed to create Prisma Cloud CWP session: {e}")

print("\n✅ Prisma Cloud Auth OK\n")

# -----------------------------------------------------------------------------
# API CALL: Pull all hosts from Prisma Cloud Compute
# -----------------------------------------------------------------------------

response = cwp_session.request("GET", "/api/v1/hosts")  # main API call

if not response.ok:
    raise SystemExit(f"Failed to pull hosts: {response.status_code} {response.text}")

hosts = response.json()   # list of hosts with metadata + vulnerabilities

rows = []                 # final flattened vulnerability rows
sev_count = {}            # severity summary counter

# -----------------------------------------------------------------------------
# HELPERS: Normalize messy Prisma API fields (important)
# -----------------------------------------------------------------------------

def meta(host):
    return host.get("cloudMetadata") or {}   # AWS/Azure/GCP metadata

def orch(host):
    return host.get("orchestrationMetadata") or {}   # Kubernetes/EKS info

def labels(host):
    """
    Normalize labels (can be dict OR list OR string list)
    """
    raw = host.get("labels")

    if not raw:
        return {}

    if isinstance(raw, dict):
        return raw

    if isinstance(raw, list):
        normalized = {}

        for item in raw:
            if isinstance(item, dict):
                # supports multiple label formats
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

def hostname(host):
    """
    Try multiple fields to get readable hostname
    """
    return (
        host.get("hostname")
        or host.get("name")
        or host.get("host")
        or host.get("hostnameOverride")
        or meta(host).get("hostname")
        or host.get("id")   # fallback
        or "unknown"
    )

def cluster(host):
    """
    Extract cluster name (works for EKS/K8s)
    """
    o = orch(host)
    m = meta(host)
    l = labels(host)

    return (
        host.get("cluster")
        or o.get("cluster")
        or o.get("clusterName")
        or o.get("name")
        or m.get("cluster")
        or l.get("cluster")
        or l.get("clusterName")
        or l.get("kubernetes.cluster")
        or "unknown"
    )

def account_id(host):
    """
    Extract AWS account / project ID
    """
    m = meta(host)
    return (
        m.get("accountId")
        or m.get("accountID")
        or m.get("projectId")
        or host.get("accountId")
        or "unknown"
    )

def region(host):
    """
    Extract cloud region
    """
    m = meta(host)
    return (
        m.get("region")
        or m.get("awsRegion")
        or m.get("location")
        or host.get("region")
        or "unknown"
    )

def resource_id(host):
    """
    Extract instance ID (like i-xxxx in AWS)
    """
    m = meta(host)
    o = orch(host)

    candidates = [
        host.get("resourceID"),
        host.get("resourceId"),
        host.get("instanceId"),
        host.get("instanceID"),
        host.get("hostId"),
        host.get("_id"),
        host.get("id"),
        m.get("instanceId"),
        m.get("providerResourceId"),
        o.get("instanceId"),
    ]

    for value in candidates:
        if value:
            return str(value).strip()

    return "unknown"

def vuln_ref(vuln):
    """
    Extract CVE (prefer real CVE like CVE-2024-11053)
    """
    candidates = [
        vuln.get("cve"),
        vuln.get("cveId"),
        vuln.get("name"),
        vuln.get("id"),
    ]

    for value in candidates:
        if not value:
            continue
        value = str(value).strip()
        if re.match(r"^CVE-\d{4}-\d+$", value, re.IGNORECASE):
            return value.upper()

    for value in candidates:
        if value:
            return str(value).strip()

    return "unknown"

def package_name(vuln):
    return (
        vuln.get("packageName")
        or vuln.get("package")
        or vuln.get("packages")
        or "unknown"
    )

def package_version(vuln):
    return (
        vuln.get("packageVersion")
        or vuln.get("version")
        or "unknown"
    )

# -----------------------------------------------------------------------------
# MAIN LOOP: Flatten host + vulnerabilities into rows
# -----------------------------------------------------------------------------

for host in hosts:
    host_name = hostname(host)
    host_cluster = cluster(host)
    host_resource_id = resource_id(host)
    host_account_id = account_id(host)
    host_region = region(host)

    vulnerabilities = host.get("vulnerabilities") or []

    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "")).lower()

        row = {
            "hostname": host_name,
            "resource_id": host_resource_id,
            "cluster": host_cluster,
            "account_id": host_account_id,
            "region": host_region,
            "severity": severity,
            "cve": vuln_ref(vuln),
            "package": package_name(vuln),
            "version": package_version(vuln),
            "fix_status": vuln.get("fixStatus"),
            "discovered": vuln.get("discovered"),
        }

        rows.append(row)

        # count severity
        sev_count[severity] = sev_count.get(severity, 0) + 1

# -----------------------------------------------------------------------------
# OUTPUT: Console view (compact)
# -----------------------------------------------------------------------------

print("📊 Prisma Host Vulnerability Summary")
print("=" * 130)

print(
    f"{'HOSTNAME':28} "
    f"{'RESOURCE_ID':22} "
    f"{'CLUSTER':20} "
    f"{'SEV':8} "
    f"{'CVE':20} "
    f"{'PKG':18}"
)
print("-" * 130)

for row in rows[:50]:   # show only first 50 rows (avoid spam)
    print(
        f"{str(row['hostname'])[:28]:28} "
        f"{str(row['resource_id'])[:22]:22} "
        f"{str(row['cluster'])[:20]:20} "
        f"{str(row['severity'])[:8]:8} "
        f"{str(row['cve'])[:20]:20} "
        f"{str(row['package'])[:18]:18}"
    )

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------

print("\nSummary:")
for severity_name, count in sev_count.items():
    print(f"{severity_name}: {count}")

print(f"\nTotal rows: {len(rows)}")



# -----------------------------------------------------------------------------
# HTML DASHBOARD EXPORT
# -----------------------------------------------------------------------------
from pathlib import Path
from collections import Counter

def write_html_dashboard(rows, output_path="host_vuln_dashboard.html"):
    counts = Counter(r["severity"] for r in rows)
    html = ['<!DOCTYPE html><html><head><title>Dashboard</title><style>body{font-family:Arial;margin:20px;background:#f4f4f4}.card{display:inline-block;background:#fff;padding:15px;margin:8px;border-radius:8px;box-shadow:0 2px 5px #ccc}table{width:100%;border-collapse:collapse;background:#fff}th,td{border:1px solid #ddd;padding:8px}th{background:#222;color:#fff}</style></head><body>']
    html.append(f'<h1>Prisma Cloud Host Vulnerability Dashboard</h1><div class="card"><h2>Total Findings</h2><h1>{len(rows)}</h1></div>')
    for sev,cnt in sorted(counts.items()):
        html.append(f'<div class="card"><h3>{sev.title()}</h3><h1>{cnt}</h1></div>')
    html.append('<table><tr><th>Hostname</th><th>Cluster</th><th>Severity</th><th>CVE</th><th>Package</th><th>Version</th></tr>')
    for r in rows:
        html.append(f"<tr><td>{r['hostname']}</td><td>{r['cluster']}</td><td>{r['severity']}</td><td>{r['cve']}</td><td>{r['package']}</td><td>{r['version']}</td></tr>")
    html.append('</table></body></html>')
    Path(output_path).write_text(''.join(html), encoding='utf-8')
    return output_path

# -----------------------------------------------------------------------------
# CSV EXPORT 
# -----------------------------------------------------------------------------

with open("host_vuln_compact.csv", "w", newline="", encoding="utf-8") as csv_file:
    fieldnames = [
        "hostname",
        "resource_id",
        "cluster",
        "account_id",
        "region",
        "severity",
        "cve",
        "package",
        "version",
        "fix_status",
        "discovered",
    ]

    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print("\n✅ CSV saved: host_vuln_compact.csv")
html_file=write_html_dashboard(rows)
print(f"✅ HTML dashboard saved: {html_file}")