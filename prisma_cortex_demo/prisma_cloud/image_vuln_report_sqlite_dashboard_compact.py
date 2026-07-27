#!/usr/bin/env python3
"""
===========================================================================
          Prisma Cloud Compute Image Vulnerability Report
        Latest Image Versions Vulnerability Export (Enterprise)
===============================================================================

Author  : Stan Zvenigorodskiy
Version : 7.0

Purpose
-------
Enterprise reporting utility for Prisma Cloud Compute that exports
container image vulnerabilities while keeping only the latest N image
versions (default = 2) for each repository. This dramatically reduces
report size while preserving the most relevant vulnerability data.

===============================================================================
FEATURES
===============================================================================

✓ Authenticate using PCPI configuration
✓ Automatic API pagination
✓ Retrieve complete image inventory
✓ Normalize image versions
✓ Keep latest N image versions per repository
✓ Calculate image age
✓ Repository / Environment / Severity filtering
✓ Fixable-only filtering
✓ CSV export
✓ JSON export
✓ SQLite database generation
✓ Interactive SQL-backed Dashboard
✓ Extensive debugging and diagnostics

===============================================================================
OUTPUT
===============================================================================

CSV
    latest2_image_vulnerabilities.csv

JSON
    latest2_image_vulnerabilities.json

SQLite
    latest2_image_vulnerabilities.db

Dashboard
    latest2_image_dashboard_server.py

===============================================================================
SQLITE DASHBOARD
===============================================================================

Large Prisma Cloud exports can contain millions of vulnerabilities. Rendering
all rows inside HTML is impractical and consumes excessive memory.

Instead, this utility stores the report in SQLite and serves the dashboard
using SQL queries.

Benefits

✓ Handles millions of vulnerabilities
✓ Fast SQL search
✓ Server-side sorting
✓ Server-side filtering
✓ Pagination
✓ Low memory usage
✓ Lightweight dashboard
✓ SQLite included with Python (no installation required)

To reduce database size, repetitive metadata fields are excluded from SQLite:

• BTO
• AppClass
• AssetID
• AppName
• Support_SME
• IT Owner
• Business_Owner_SME

These fields remain available in the CSV and JSON reports.

===============================================================================
DASHBOARD FEATURES
===============================================================================

✓ Executive Summary
✓ Total Findings
✓ Severity Counters
✓ Repository Count
✓ Repository Filter
✓ Severity Filter
✓ Full-text Search
✓ Adjustable Page Size
✓ SQL-backed Pagination
✓ SQL-backed Sorting

Only the requested page of results is loaded into the browser, keeping the
dashboard responsive even for multi-million-row datasets.

===============================================================================
WORKFLOW
===============================================================================

Prisma Cloud Compute
        │
        ▼
Retrieve Image Inventory
        │
        ▼
Normalize Versions
        │
        ▼
Keep Latest N Images
        │
        ▼
Collect Vulnerabilities
        │
        ▼
Apply Filters
        │
        ▼
Export CSV / JSON
        │
        ▼
Build SQLite Database
        │
        ▼
Launch Interactive Dashboard

===============================================================================
USAGE
===============================================================================

Generate Report

python pcs_compute_latest2_image_vuln_report.py

Keep Latest 3 Versions

python pcs_compute_latest2_image_vuln_report.py --latest_versions 3

Critical Only

python pcs_compute_latest2_image_vuln_report.py --severity critical

Production Only

python pcs_compute_latest2_image_vuln_report.py --environment prod

Launch Dashboard

python latest2_image_dashboard_server.py \
    --db latest2_image_vulnerabilities.db --open

Dashboard URL

http://127.0.0.1:8000

===============================================================================


"""

from pcpi import session_loader
from collections import defaultdict, Counter
from datetime import datetime, timezone
import argparse
import csv
import json
import re
import sys
import sqlite3
from pathlib import Path


# -----------------------------------------------------------------------------
# CLI arguments
# -----------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Prisma Cloud image vulnerability report limited to latest N image versions per repository."
)

parser.add_argument("--latest_versions", type=int, default=2,
                    help="Number of latest normalized versions to keep per repository. Default: 2")
parser.add_argument("--severity", default="critical,high,medium,low",
                    help="Comma-separated severities to include. Default: critical,high,medium,low")
parser.add_argument("--fixable_only", action="store_true",
                    help="Only include vulnerabilities that appear to have a fix available.")
parser.add_argument("--repository",
                    help="Only include repositories containing this text. Example: jl8210")
parser.add_argument("--environment",
                    help="Only include rows where Environment matches/contains this value. Example: prod")
parser.add_argument("--exclude_prev", action="store_true",
                    help="Exclude tags containing '-prev-' or 'prev'.")
parser.add_argument("--summary_only", action="store_true",
                    help="Only print summary counts; still writes CSV/JSON.")
parser.add_argument("--debug", action="store_true", default=True,
                    help="Print detailed debug output. Default: enabled.")
parser.add_argument("--no_debug", action="store_true",
                    help="Disable detailed debug output.")
parser.add_argument("--debug_sample", type=int, default=20,
                    help="Number of sample images/rows to print on screen. Default: 20")
parser.add_argument("--keep_unknown_versions", action="store_true", default=True,
                    help="Keep images with tags that do not contain semantic versions. Default: enabled.")
parser.add_argument("--drop_unknown_versions", action="store_true",
                    help="Drop tags that do not contain semantic versions.")
parser.add_argument("--output_csv", default="latest2_image_vulnerabilities.csv",
                    help="CSV output file.")
parser.add_argument("--output_json", default="latest2_image_vulnerabilities.json",
                    help="JSON output file.")
parser.add_argument("--output_sqlite", default="latest2_image_vulnerabilities.db",
                    help="SQLite database output file used by dashboard.")
parser.add_argument("--dashboard_server", default="latest2_image_dashboard_server.py",
                    help="Local SQLite dashboard server script to generate.")
parser.add_argument("--no_sqlite", action="store_true",
                    help="Skip SQLite database and dashboard server generation.")
parser.add_argument("--dedupe_level", choices=["stable", "strict"], default="stable",
                    help="Duplicate handling. stable removes duplicate rows by repository/tag/package/CVE. strict removes exact row copies only.")

args = parser.parse_args()

if args.no_debug:
    args.debug = False
if args.drop_unknown_versions:
    args.keep_unknown_versions = False

if args.latest_versions < 1:
    raise SystemExit("--latest_versions must be 1 or greater")

severity_filter = {s.strip().lower() for s in args.severity.split(",") if s.strip()}


def debug_print(*parts):
    if args.debug:
        print(*parts)


def safe_json_sample(obj, limit=10000):
    try:
        return json.dumps(obj, indent=2, default=str)[:limit]
    except Exception as exc:
        return f"<could not serialize sample: {exc}>"


# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------

def first_value(obj, keys, default=""):
    if not isinstance(obj, dict):
        return default
    for key in keys:
        value = obj.get(key)
        if value not in (None, "", []):
            return value
    return default


def labels_as_dict(obj):
    out = {}
    if not isinstance(obj, dict):
        return out

    candidates = [
        obj.get("labels"),
        obj.get("tags"),
        obj.get("collections"),
        obj.get("metadata"),
        obj.get("labelsMap"),
    ]

    for raw in candidates:
        if not raw:
            continue
        if isinstance(raw, dict):
            for k, v in raw.items():
                out[str(k)] = v
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    if "key" in item and "value" in item:
                        out[str(item["key"])] = item["value"]
                    elif "name" in item and "value" in item:
                        out[str(item["name"])] = item["value"]
                    else:
                        for k, v in item.items():
                            if isinstance(v, (str, int, float, bool)):
                                out[str(k)] = v
                elif isinstance(item, str) and "=" in item:
                    k, v = item.split("=", 1)
                    out[k.strip()] = v.strip()
    return out


def meta_value(img, label_dict, names, default=""):
    variants = []
    for name in names:
        variants.extend([
            name,
            name.lower(),
            name.upper(),
            name.replace(" ", "_"),
            name.replace(" ", "_").lower(),
            name.replace("_", " "),
            name.replace("_", " ").lower(),
            name.replace("-", "_"),
            name.replace("-", "_").lower(),
        ])

    for key in variants:
        value = img.get(key) if isinstance(img, dict) else None
        if value not in (None, "", []):
            return value

    for key in variants:
        value = label_dict.get(key)
        if value not in (None, "", []):
            return value

    return default


def split_repo_tag(repo_tag):
    value = str(repo_tag).strip()
    if not value:
        return "unknown", "unknown"

    # Remove digest part if present: repo:tag@sha256:abc
    if "@sha256:" in value:
        value = value.split("@sha256:", 1)[0]

    last_slash = value.rfind("/")
    last_colon = value.rfind(":")

    if last_colon > last_slash:
        return value[:last_colon], value[last_colon + 1:]
    return value, "unknown"


def get_repo_tags(img):
    """Return repo tags from many possible Prisma shapes."""
    values = []
    for key in ["repoTags", "repoTag", "repo_tags", "names", "imageNames", "tags"]:
        raw = img.get(key) if isinstance(img, dict) else None
        if not raw:
            continue
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    values.append(item)
                elif isinstance(item, dict):
                    for subkey in ["repoTag", "repo", "name", "tag", "imageName"]:
                        if item.get(subkey):
                            values.append(str(item[subkey]))
                            break

    # Some image objects use repo + tag separately.
    repo = first_value(img, ["repo", "repository", "repoName", "imageName", "name"], "")
    tag = first_value(img, ["tag", "imageTag"], "")
    if repo and tag:
        values.append(f"{repo}:{tag}")
    elif repo:
        values.append(str(repo))

    # Deduplicate while preserving order.
    seen = set()
    out = []
    for value in values:
        value = str(value).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def repository_from_img(img, repo_tag=None):
    if repo_tag:
        repo, _ = split_repo_tag(repo_tag)
        if repo != "unknown":
            return repo
    repo = first_value(img, ["repo", "repository", "repoName", "imageName", "name"], "")
    return str(repo) if repo else "unknown"


def tag_from_img(img, repo_tag=None):
    if repo_tag:
        _, tag = split_repo_tag(repo_tag)
        if tag != "unknown":
            return tag
    tag = first_value(img, ["tag", "imageTag"], "")
    return str(tag) if tag else "unknown"


def normalize_version(tag):
    text = str(tag)

    # Full semantic version: 1.2.3 or 1.2.3.4 or v1.2.3
    match = re.search(r"(?:^|[^0-9])v?(\d+\.\d+\.\d+(?:\.\d+)?)", text, re.IGNORECASE)
    if match:
        return match.group(1)

    # Two-part version: 1.2
    match = re.search(r"(?:^|[^0-9])v?(\d+\.\d+)", text, re.IGNORECASE)
    if match:
        return match.group(1)

    # Date style: 20240625, 2024-06-25, 2024.06.25
    match = re.search(r"(20\d{2})[-_.]?(\d{2})[-_.]?(\d{2})", text)
    if match:
        return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"

    return "unknown"


def version_key(version):
    if not version or version == "unknown":
        return (-1,)
    parts = []
    for piece in re.split(r"[.\-_]", str(version)):
        try:
            parts.append(int(piece))
        except ValueError:
            parts.append(-1)
    return tuple(parts)


def is_prev_tag(tag):
    return "prev" in str(tag).lower()


def vuln_list(img):
    """Return inline vulnerabilities from known Prisma shapes."""
    candidates = [
        "vulnerabilities", "vulns", "vulnerability", "cves", "complianceVulnerabilities",
        "packages", "vulnerablePackages"
    ]
    for key in candidates:
        val = img.get(key) if isinstance(img, dict) else None
        if isinstance(val, list) and val:
            # Do not treat package inventory as vulns unless package entries contain CVE fields.
            if key in ("packages", "vulnerablePackages"):
                if any(isinstance(x, dict) and ("cve" in x or "cveId" in x or "vulnerabilities" in x) for x in val[:20]):
                    return val
                continue
            return val

    # Nested scan results sometimes exist.
    for parent in ["scanResult", "scan", "result", "imageScanResult"]:
        nested = img.get(parent) if isinstance(img, dict) else None
        if isinstance(nested, dict):
            for key in candidates:
                val = nested.get(key)
                if isinstance(val, list) and val:
                    return val
    return []


def vuln_id(vuln):
    value = first_value(vuln, ["cve", "cveId", "cveID", "id", "name", "identifier"], "")
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value).upper() if str(value).lower().startswith("cve-") else str(value)


def vuln_severity(vuln):
    return str(first_value(vuln, ["severity", "riskRating", "risk", "cvssSeverity"], "unknown")).lower()


def risk_factors_text(vuln):
    rf = first_value(vuln, ["riskFactors", "risk_factors", "factors"], "")
    if isinstance(rf, list):
        return ", ".join(str(x) for x in rf if x)
    return str(rf)


def vuln_fix_status(vuln):
    fixed = first_value(vuln, ["fixStatus", "fix_status", "status", "fixDate"], "")
    fixed_version = first_value(vuln, ["fixedVersion", "fixedIn", "fixVersion", "fixVersions"], "")
    if isinstance(fixed_version, list):
        fixed_version = ", ".join(str(x) for x in fixed_version if x)
    if fixed_version:
        return f"fixed in {fixed_version}"
    return str(fixed)


def has_fix(vuln):
    fs = vuln_fix_status(vuln).lower()
    if "fixed in" in fs or "fix_available" in fs or "has fix" in fs:
        return True
    if first_value(vuln, ["fixedVersion", "fixedIn", "fixVersion", "fixVersions"], ""):
        return True
    return "has fix" in risk_factors_text(vuln).lower()


def package_path(vuln):
    paths = first_value(vuln, ["packagePath", "path", "binaryPath", "filepath", "filePath"], "")
    if isinstance(paths, list):
        return ", ".join(str(x) for x in paths if x)
    return str(paths)


def stable_text(value):
    """Return deterministic text for duplicate detection."""
    if value in (None, "", []):
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, sort_keys=True, default=str)
        except Exception:
            return str(value)
    return str(value).strip()


def image_identity(img):
    """Best-effort unique image identity across Prisma response shapes.

    Prisma responses vary by tenant/version. Prefer digest/id when present.
    If no digest exists, fall back to a stable hash of the raw image object so
    duplicate repoTags collapse only when the actual image payload is identical.
    """
    value = stable_text(first_value(img, [
        "id", "_id", "imageID", "imageId", "imageDigest", "digest", "repoDigest",
        "sha", "sha256", "entityId", "entityID"
    ], ""))
    if value:
        return value
    try:
        import hashlib
        raw = json.dumps(img, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    except Exception:
        return stable_text(img)


def normalize_date(value):
    if value in (None, "", []):
        return ""
    if isinstance(value, (int, float)):
        ts = value / 1000 if value > 10_000_000_000 else value
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            return str(value)
    text = str(value)
    return text[:10] if len(text) >= 10 else text


def image_created(img):
    candidates = [
        "created", "createdAt", "imageCreated", "imageCreatedTime", "imageCreateTime",
        "creationTime", "buildTime", "imageBuildTime", "dockerCreated", "createdTime"
    ]
    for k in candidates:
        v = img.get(k) if isinstance(img, dict) else None
        if v not in (None, "", []):
            return v
    metadata = img.get("metadata") if isinstance(img, dict) else {}
    if isinstance(metadata, dict):
        for k in candidates:
            v = metadata.get(k)
            if v not in (None, "", []):
                return v
    return ""


def image_age_days(created):
    if not created:
        return ""
    try:
        if isinstance(created, (int, float)):
            ts = created / 1000 if created > 10_000_000_000 else created
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return ""


def image_sort_timestamp(img):
    """Best-effort timestamp used to choose the newest image when tags are not semver."""
    for value in [
        image_created(img),
        first_value(img, ["lastSeen", "lastModified", "scanTime", "time"], ""),
    ]:
        if value in (None, "", []):
            continue
        try:
            if isinstance(value, (int, float)):
                return value / 1000 if value > 10_000_000_000 else value
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except Exception:
            pass
    return 0


def image_alias_key(img):
    """Canonical key used to collapse repeated image records returned by the API.

    Prefer digest/id when available. If digest is missing, use sorted repo tags plus
    creation/scan timestamps. This is more stable than hashing the full raw object,
    because Prisma can repeat the same image with minor metadata differences.
    """
    strong = stable_text(first_value(img, [
        "imageDigest", "digest", "repoDigest", "sha", "sha256",
        "imageID", "imageId", "id", "_id", "entityId", "entityID"
    ], ""))
    if strong:
        return strong.lower()
    tags = sorted(set(get_repo_tags(img)))
    created = stable_text(image_created(img))
    scanned = stable_text(first_value(img, ["scanTime", "lastSeen", "lastModified", "time"], ""))
    return "|".join(tags + [created, scanned]).lower()


def entry_dedupe_key(entry):
    """Collapse duplicate repo/tag entries while preserving true distinct tags."""
    return (
        image_alias_key(entry["image"]),
        stable_text(entry["repository"]).lower(),
        stable_text(entry["tag"]).lower(),
        stable_text(entry["version"]).lower(),
    )


def row_dedupe_key(row, img):
    """Stable finding key for duplicate removal.

    The default key intentionally ignores prose-only fields such as Description,
    Risk Factors, Fix Status, and Prisma-Image aliases. Those fields can vary while
    the finding is still the same vulnerability on the same repository/tag/package.
    """
    return (
        stable_text(row.get("Repository", "")).lower(),
        stable_text(row.get("Tag", "")).lower(),
        stable_text(row.get("Normalized Version", "")).lower(),
        stable_text(row.get("CVE ID", "")).upper(),
        stable_text(row.get("Packages", "")).lower(),
        stable_text(row.get("Package Version", "")).lower(),
        stable_text(row.get("Source Package", "")).lower(),
        stable_text(row.get("Namespace", "")).lower(),
        stable_text(row.get("Package Path", "")).lower(),
    )


def duplicate_audit(rows):
    """Return duplicate counts using the same visible business key as the dashboard."""
    counts = Counter()
    for row in rows:
        counts[(
            stable_text(row.get("Repository", "")).lower(),
            stable_text(row.get("Tag", "")).lower(),
            stable_text(row.get("Normalized Version", "")).lower(),
            stable_text(row.get("CVE ID", "")).upper(),
            stable_text(row.get("Packages", "")).lower(),
            stable_text(row.get("Package Version", "")).lower(),
            stable_text(row.get("Source Package", "")).lower(),
            stable_text(row.get("Namespace", "")).lower(),
            stable_text(row.get("Package Path", "")).lower(),
        )] += 1
    return {k: v for k, v in counts.items() if v > 1}


# Shared diagnostic counters
skip_reasons = Counter()

# -----------------------------------------------------------------------------
# Auth using the same method as the working pcpi example
# -----------------------------------------------------------------------------

session_managers = session_loader.load_config()
if not session_managers:
    raise SystemExit("No Prisma Cloud session managers were loaded from config.")

session_man = session_managers[0]
try:
    cwp_session = session_man.create_cwp_session()
except Exception as e:
    raise SystemExit(f"Failed to create Prisma Cloud CWP session: {e}")

print("\n✅ Prisma Cloud Auth OK\n")


# -----------------------------------------------------------------------------
# Pull image scan data from Compute
# -----------------------------------------------------------------------------

# Paginated image retrieval with page-level de-duplication.
# Some Compute tenants can repeat image records across offset pages while scans are updating.
images = []
seen_api_images = set()
# Prisma Compute /api/v1/images currently allows max limit=100.
# Keep this at 100 to avoid: {"err":"limit must be at most 100"}.
limit = 100
offset = 0
while True:
    response = cwp_session.request("GET", "/api/v1/images", params={"limit": limit, "offset": offset})
    if not response.ok:
        raise SystemExit(f"Failed to pull images: {response.status_code} {response.text}")
    batch = response.json()
    if not isinstance(batch, list):
        raise SystemExit("Unexpected /api/v1/images response")

    added = 0
    for img in batch:
        key = image_alias_key(img)
        if key in seen_api_images:
            skip_reasons["duplicate_api_image"] += 1
            continue
        seen_api_images.add(key)
        images.append(img)
        added += 1

    print(f"Retrieved {len(batch)} images (offset={offset}); added unique={added}")
    if len(batch) < limit:
        break
    offset += limit
class _Resp: pass
response=_Resp()
response.status_code=200
response.ok=True
response.text=""


print("\nPrisma API Response")
print("Status Code :", getattr(response, "status_code", "unknown"))
try:
    print("Response Size:", len(response.text))
except Exception:
    print("Response Size: unknown")

if not response.ok:
    raise SystemExit(f"Failed to pull images: {response.status_code} {response.text}")

if not isinstance(images, list):
    raise SystemExit("Unexpected /api/v1/images response. Expected a list of image objects.")

print(f"📡 Pulled {len(images)} image records from Prisma Cloud Compute")

if args.debug:
    print("\n" + "=" * 120)
    print("DEBUG: FIRST IMAGE DISCOVERY")
    print("=" * 120)
    if images:
        first = images[0]
        print("FIRST IMAGE KEYS:")
        for key in sorted(first.keys()):
            print(f"  {key}")

        print("\nCOMMON FIELD VALUES:")
        for key in [
            "repoTags", "repoTag", "repo", "repository", "repoName", "imageName", "name",
            "tag", "imageTag", "vulnerabilities", "vulns", "cves", "packages",
            "created", "createdAt", "imageCreated", "scanTime", "lastSeen"
        ]:
            val = first.get(key)
            if isinstance(val, list):
                print(f"{key:25}: list count={len(val)} sample={str(val[:2])[:300]}")
            else:
                print(f"{key:25}: {str(val)[:300]}")

        print("\nFIRST IMAGE JSON SAMPLE, FIRST 10000 CHARS:")
        print(safe_json_sample(first, 10000))
    else:
        print("No images returned from /api/v1/images")
    print("=" * 120 + "\n")


# -----------------------------------------------------------------------------
# Build image candidates and identify latest N versions per repository
# -----------------------------------------------------------------------------

image_entries = []
seen_image_entry_keys = set()

for img in images:
    repo_tags = get_repo_tags(img)

    if not repo_tags:
        skip_reasons["no_repo_tags_found"] += 1
        repo = repository_from_img(img)
        tag = tag_from_img(img)
        repo_tags = [f"{repo}:{tag}" if tag != "unknown" else repo]

    for repo_tag in repo_tags:
        repository = repository_from_img(img, repo_tag)
        tag = tag_from_img(img, repo_tag)
        version = normalize_version(tag)

        if args.repository and args.repository.lower() not in repository.lower():
            skip_reasons["repository_filter"] += 1
            continue

        if args.exclude_prev and is_prev_tag(tag):
            skip_reasons["exclude_prev"] += 1
            continue

        if version == "unknown" and not args.keep_unknown_versions:
            skip_reasons["unknown_version_dropped"] += 1
            continue

        entry_key = (image_alias_key(img), repository.lower(), tag.lower(), version.lower())
        if entry_key in seen_image_entry_keys:
            skip_reasons["duplicate_image_entry"] += 1
            continue
        seen_image_entry_keys.add(entry_key)

        image_entries.append({
            "image": img,
            "repo_tag": repo_tag,
            "repository": repository,
            "tag": tag,
            "version": version,
        })

versions_by_repo = defaultdict(set)
unknown_entries_by_repo = defaultdict(list)

for entry in image_entries:
    if entry["version"] != "unknown":
        versions_by_repo[entry["repository"]].add(entry["version"])
    else:
        unknown_entries_by_repo[entry["repository"]].append(entry)

latest_versions_by_repo = {}
for repo, versions in versions_by_repo.items():
    latest = sorted(versions, key=version_key, reverse=True)[:args.latest_versions]
    latest_versions_by_repo[repo] = set(latest)

for repo in list(unknown_entries_by_repo.keys()):
    unknown_entries_by_repo[repo] = sorted(
        unknown_entries_by_repo[repo],
        key=lambda e: (image_sort_timestamp(e["image"]), stable_text(e["tag"])),
        reverse=True,
    )

latest_entries = []
seen_latest_entry_keys = set()
for entry in image_entries:
    repo = entry["repository"]
    version = entry["version"]

    if version != "unknown" and version in latest_versions_by_repo.get(repo, set()):
        rank = sorted(latest_versions_by_repo[repo], key=version_key, reverse=True).index(version) + 1
        entry["latest_rank"] = rank
        latest_key = entry_dedupe_key(entry)
        if latest_key not in seen_latest_entry_keys:
            seen_latest_entry_keys.add(latest_key)
            latest_entries.append(entry)
    elif version == "unknown" and args.keep_unknown_versions and repo not in latest_versions_by_repo:
        # Fallback: if a repo has no parseable semantic versions at all, keep up to latest_versions tags.
        selected_unknowns = unknown_entries_by_repo.get(repo, [])[:args.latest_versions]
        if entry in selected_unknowns:
            entry["latest_rank"] = selected_unknowns.index(entry) + 1
            latest_key = entry_dedupe_key(entry)
            if latest_key not in seen_latest_entry_keys:
                seen_latest_entry_keys.add(latest_key)
                latest_entries.append(entry)


# -----------------------------------------------------------------------------
# Debug selection output
# -----------------------------------------------------------------------------

if args.debug:
    unknown_versions = sum(1 for e in image_entries if e["version"] == "unknown")
    inline_vuln_images = sum(1 for e in image_entries if vuln_list(e["image"]))
    selected_inline_vuln_images = sum(1 for e in latest_entries if vuln_list(e["image"]))

    print("\n" + "=" * 120)
    print("DEBUG: FILTER / SELECTION COUNTS")
    print("=" * 120)
    print(f"Images pulled from API              : {len(images)}")
    print(f"Image entries created               : {len(image_entries)}")
    print(f"Repositories with parseable versions: {len(versions_by_repo)}")
    print(f"Latest image entries selected       : {len(latest_entries)}")
    print(f"Unknown version entries             : {unknown_versions}")
    print(f"Image entries with inline vulns     : {inline_vuln_images}")
    print(f"Selected entries with inline vulns  : {selected_inline_vuln_images}")
    print(f"Skip reasons                        : {dict(skip_reasons)}")

    print("\nFIRST IMAGE ENTRIES:")
    for e in image_entries[:args.debug_sample]:
        print(f"repo={e['repository']} | tag={e['tag']} | version={e['version']} | repoTag={e['repo_tag']} | vuln_count={len(vuln_list(e['image']))}")

    print("\nFIRST SELECTED LATEST ENTRIES:")
    for e in latest_entries[:args.debug_sample]:
        print(f"repo={e['repository']} | tag={e['tag']} | version={e['version']} | rank={e.get('latest_rank')} | vuln_count={len(vuln_list(e['image']))}")
    print("=" * 120 + "\n")


# -----------------------------------------------------------------------------
# Flatten vulnerabilities into report rows
# -----------------------------------------------------------------------------

rows = []
seen_row_keys = set()
summary = defaultdict(int)
repo_version_seen = defaultdict(set)
row_skip_reasons = Counter()

for entry in latest_entries:
    img = entry["image"]
    label_dict = labels_as_dict(img)

    environment = str(meta_value(img, label_dict, ["Environment", "env"], ""))
    if args.environment and args.environment.lower() not in environment.lower():
        row_skip_reasons["environment_filter"] += 1
        continue

    vulns = vuln_list(img)
    if not vulns:
        row_skip_reasons["no_inline_vulnerabilities"] += 1
        if args.debug:
            print(f"No inline vulnerabilities found for selected image: {entry['repo_tag']}")
        continue

    for vuln in vulns:
        if not isinstance(vuln, dict):
            row_skip_reasons["vuln_not_dict"] += 1
            continue

        sev = vuln_severity(vuln)
        if severity_filter and sev.lower() not in severity_filter:
            row_skip_reasons["severity_filter"] += 1
            continue

        if args.fixable_only and not has_fix(vuln):
            row_skip_reasons["fixable_only_filter"] += 1
            continue

        row = {
            "BTO": meta_value(img, label_dict, ["BTO"], ""),
            "AppClass": meta_value(img, label_dict, ["AppClass", "App Class", "Class"], ""),
            "AssetID": meta_value(img, label_dict, ["AssetID", "Asset ID", "asset_id"], ""),
            "AppName": meta_value(img, label_dict, ["AppName", "App Name", "application"], ""),
            "CMDB Status": meta_value(img, label_dict, ["CMDB Status", "cmdb_status"], ""),
            "Environment": environment,
            "Risk Rating": str(sev).upper(),
            "Support_SME": meta_value(img, label_dict, ["Support_SME", "Support SME", "support"], ""),
            "IT Owner": meta_value(img, label_dict, ["IT Owner", "IT_Owner", "it_owner"], ""),
            "Business_Owner_SME": meta_value(img, label_dict, ["Business_Owner_SME", "Business Owner SME", "business_owner"], ""),
            "Repository": entry["repository"],
            "Type": meta_value(img, label_dict, ["Type", "assetType"], "Application"),
            "Tag": entry["tag"],
            "Normalized Version": entry["version"],
            "Latest Version Rank": entry["latest_rank"],
            "Image Created": image_created(img),
            "Image Age (Days)": image_age_days(image_created(img)),
            "Prisma-Image": entry["repo_tag"],
            "Packages": first_value(vuln, ["packageName", "package", "packages", "pkgName"], ""),
            "Package Version": first_value(vuln, ["packageVersion", "version", "package_version"], ""),
            "Source Package": first_value(vuln, ["sourcePackage", "sourcePackageName", "packageSource"], ""),
            "Namespace": first_value(vuln, ["namespace", "packageType", "type"], ""),
            "Last Seen Date": normalize_date(first_value(img, ["lastSeen", "lastModified", "scanTime", "time"], "")),
            "Due Date": meta_value(img, label_dict, ["Due Date", "due_date"], ""),
            "Days Until OverDue": meta_value(img, label_dict, ["Days Until OverDue", "days_until_overdue"], ""),
            "OverDue Band": meta_value(img, label_dict, ["OverDue Band", "overdue_band"], ""),
            "Fix Status": vuln_fix_status(vuln),
            "CVE ID": vuln_id(vuln),
            "CVSS": first_value(vuln, ["cvss", "cvssScore", "score"], ""),
            "Risk Factors": risk_factors_text(vuln),
            "Package Path": package_path(vuln),
            "Description": first_value(vuln, ["description", "desc", "title"], ""),
        }

        if args.dedupe_level == "strict":
            row_key = tuple(stable_text(row.get(c, "")) for c in sorted(row.keys()))
        else:
            # Stable duplicate key: same image/repo/tag/version + same package/CVE.
            # This removes duplicate records caused by repeated repoTags/API pages and
            # image aliases without collapsing different package versions or images.
            row_key = row_dedupe_key(row, img)
        if row_key in seen_row_keys:
            row_skip_reasons["duplicate_vulnerability_row"] += 1
            continue
        seen_row_keys.add(row_key)

        rows.append(row)
        summary[sev] += 1
        repo_version_seen[entry["repository"]].add(entry["version"])


# -----------------------------------------------------------------------------
# Final screen debug before writing files
# -----------------------------------------------------------------------------

print("\n" + "=" * 120)
print("FINAL DEBUG SUMMARY")
print("=" * 120)
print(f"Images returned from Prisma       : {len(images)}")
print(f"Image entries created             : {len(image_entries)}")
print(f"Latest image entries selected     : {len(latest_entries)}")
print(f"Final vulnerability rows          : {len(rows)}")
print(f"Row skip reasons                  : {dict(row_skip_reasons)}")
print(f"Duplicate vulnerability rows removed: {row_skip_reasons.get('duplicate_vulnerability_row', 0)}")
visible_dupes = duplicate_audit(rows)
print(f"Duplicate rows remaining after final audit: {len(visible_dupes)}")
if visible_dupes:
    print("WARNING: duplicate audit found remaining duplicates. Showing first 10 keys:")
    for dup_key, dup_count in list(visible_dupes.items())[:10]:
        print(f"  count={dup_count} key={dup_key}")

if rows:
    print("\nFIRST REPORT ROWS:")
    for row in rows[:args.debug_sample]:
        print("-" * 100)
        print(f"Repository : {row['Repository']}")
        print(f"Tag        : {row['Tag']}")
        print(f"Version    : {row['Normalized Version']}")
        print(f"Package    : {row['Packages']}")
        print(f"CVE        : {row['CVE ID']}")
        print(f"Severity   : {row['Risk Rating']}")
        print(f"Created    : {row['Image Created']}")
else:
    print("\n⚠️  REPORT IS EMPTY. DIAGNOSIS:")
    if not images:
        print("- /api/v1/images returned zero images.")
    elif not image_entries:
        print("- Images were returned, but no repo/tag entries were created.")
    elif not latest_entries:
        print("- Repo/tag entries were created, but none passed latest-version selection.")
        print("- Try running with default keep-unknown behavior, or check tag naming.")
    elif row_skip_reasons.get("no_inline_vulnerabilities") == len(latest_entries):
        print("- Selected images do NOT contain inline vulnerabilities from /api/v1/images.")
        print("- This is the most likely reason your report is empty.")
        print("- Your old 4 GB report is probably using a different vulnerability/export endpoint.")
        print("- Use the old working report script as the base, then add latest-2 filtering there.")
    else:
        print("- Rows were removed by filters. Check severity/environment/fixable filters above.")
print("=" * 120 + "\n")



# -----------------------------------------------------------------------------
# SQLite + lightweight dashboard server output
# -----------------------------------------------------------------------------

def sql_quote(identifier):
    return '"' + str(identifier).replace('"', '""') + '"'


def write_sqlite_database(rows, fieldnames, db_path):
    """Write full report to SQLite for scalable dashboard search/sort/pagination."""
    db_file = Path(db_path)
    if db_file.exists():
        db_file.unlink()
    conn = sqlite3.connect(str(db_file))
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode = WAL")
        cur.execute("PRAGMA synchronous = NORMAL")
        cur.execute("PRAGMA temp_store = MEMORY")
        columns_sql = ", ".join(f"{sql_quote(c)} TEXT" for c in fieldnames)
        cur.execute(f"CREATE TABLE findings ({columns_sql})")
        placeholders = ", ".join("?" for _ in fieldnames)
        insert_sql = f"INSERT INTO findings VALUES ({placeholders})"
        batch = []
        db_seen = set()
        for row in rows:
            values = tuple("" if row.get(c) is None else str(row.get(c, "")) for c in fieldnames)
            if values in db_seen:
                continue
            db_seen.add(values)
            batch.append(list(values))
            if len(batch) >= 5000:
                cur.executemany(insert_sql, batch)
                batch.clear()
        if batch:
            cur.executemany(insert_sql, batch)
        for col in ["Risk Rating", "Repository", "CVE ID", "Packages", "Image Created", "Latest Version Rank", "Environment"]:
            if col in fieldnames:
                idx = "idx_" + re.sub(r"[^A-Za-z0-9_]", "_", col).strip("_").lower()
                cur.execute(f"CREATE INDEX IF NOT EXISTS {idx} ON findings ({sql_quote(col)})")
        conn.commit()
    finally:
        conn.close()
    return str(db_file)


def write_dashboard_server_script(server_path, db_path, fieldnames):
    """Generate a local SQLite-backed dashboard server script with clean HTML/JS."""
    fields = list(fieldnames)
    html = """<!doctype html>
<html><head><meta charset="utf-8"><title>Prisma Image Vulnerability Dashboard</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:0;background:#f4f6f8;color:#111827}header{background:#111827;color:white;padding:18px 24px}main{padding:20px}.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}.card{background:white;border-radius:10px;padding:14px 18px;box-shadow:0 1px 5px #cbd5e1;min-width:160px}.label{color:#64748b;font-size:12px;text-transform:uppercase}.num{font-size:28px;font-weight:bold}.controls{background:white;border-radius:10px;padding:14px;box-shadow:0 1px 5px #cbd5e1;margin:14px 0;display:flex;gap:10px;flex-wrap:wrap;align-items:end}label{font-size:12px;color:#475569;display:block}input,select,button{padding:8px;border:1px solid #cbd5e1;border-radius:6px}button{background:#111827;color:white;cursor:pointer}.tablewrap{overflow:auto;max-height:72vh;border-radius:10px;box-shadow:0 1px 5px #cbd5e1;background:white}table{border-collapse:collapse;table-layout:fixed;width:100%;min-width:1800px;background:white}th,td{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left;font-size:12px;vertical-align:top;white-space:normal;word-break:break-word;overflow-wrap:anywhere;max-width:260px}th{background:#1f2937;color:white;position:sticky;top:0;z-index:1;cursor:pointer}.badge{padding:2px 6px;border-radius:999px;font-weight:bold;font-size:11px;white-space:nowrap}.CRITICAL{background:#fee2e2;color:#991b1b}.HIGH{background:#ffedd5;color:#9a3412}.MEDIUM{background:#fef9c3;color:#854d0e}.LOW{background:#dcfce7;color:#166534}.pager{display:flex;gap:10px;align-items:center;margin:12px 0}.error{display:none;background:#fee2e2;color:#991b1b;padding:10px;border-radius:8px;margin:10px 0}
</style></head><body><header><h1>Prisma Image Vulnerability Dashboard</h1><div>SQLite-backed dashboard for large reports</div></header><main>
<div class="cards" id="cards"></div>
<div class="controls"><div><label>Search</label><input id="q" placeholder="repo, CVE, package, image" size="35"></div><div><label>Severity</label><select id="severity"><option value="">All</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div><div><label>Repository contains</label><input id="repo" size="25"></div><div><label>Rows</label><select id="limit"><option>100</option><option selected>250</option><option>500</option><option>1000</option></select></div><button onclick="reload()">Apply</button></div>
<div class="error" id="err"></div><div class="pager"><button onclick="prevPage()">Previous</button><span id="pageInfo"></span><button onclick="nextPage()">Next</button></div><div class="tablewrap"><table><thead id="thead"></thead><tbody id="tbody"></tbody></table></div>
<script>
const fields = __FIELDS_JSON__; let offset=0, sort='Risk Rating', dir='desc', total=0;
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function cell(v){const s=String(v??''); return esc(s.length>160?s.slice(0,160)+'...':s);}
function err(m){const e=document.getElementById('err'); e.textContent=m||''; e.style.display=m?'block':'none';}
function params(){const p=new URLSearchParams(); p.set('offset',offset); p.set('limit',limit.value); p.set('sort',sort); p.set('dir',dir); p.set('q',q.value); p.set('severity',severity.value); p.set('repo',repo.value); return p;}
async function getJson(u){const r=await fetch(u); if(!r.ok) throw new Error(r.status+' '+r.statusText); return await r.json();}
async function summary(){const s=await getJson('/api/summary'); cards.innerHTML=`<div class="card"><div class="label">Total Findings</div><div class="num">${Number(s.total||0).toLocaleString()}</div></div><div class="card"><div class="label">Critical</div><div class="num">${Number(s.by_severity.CRITICAL||0).toLocaleString()}</div></div><div class="card"><div class="label">High</div><div class="num">${Number(s.by_severity.HIGH||0).toLocaleString()}</div></div><div class="card"><div class="label">Medium</div><div class="num">${Number(s.by_severity.MEDIUM||0).toLocaleString()}</div></div><div class="card"><div class="label">Repositories</div><div class="num">${Number(s.repositories||0).toLocaleString()}</div></div>`;}
function heads(){thead.innerHTML='<tr>'+fields.map(f=>`<th data-field="${esc(f)}">${esc(f)}${sort===f?(dir==='asc'?' ▲':' ▼'):''}</th>`).join('')+'</tr>'; document.querySelectorAll('th[data-field]').forEach(th=>th.addEventListener('click',()=>setSort(th.dataset.field)));}
function drawRows(rs){tbody.innerHTML=rs.map(r=>'<tr>'+fields.map(f=>f==='Risk Rating'?`<td><span class="badge ${esc(String(r[f]||'').toUpperCase().replace(/[^A-Z0-9_-]/g,''))}">${esc(r[f])}</span></td>`:`<td>${cell(r[f])}</td>`).join('')+'</tr>').join('');}
async function load(){try{err(''); heads(); const d=await getJson('/api/rows?'+params()); total=Number(d.total||0); drawRows(d.rows||[]); const l=Number(limit.value); pageInfo.textContent=`${total?offset+1:0}-${Math.min(offset+l,total)} of ${total.toLocaleString()}`;}catch(e){err('Dashboard load failed: '+e.message);}}
function setSort(f){if(sort===f)dir=dir==='asc'?'desc':'asc'; else{sort=f;dir='asc'} offset=0; load();}
function reload(){offset=0; load();} function nextPage(){const l=Number(limit.value); if(offset+l<total){offset+=l;load();}} function prevPage(){const l=Number(limit.value); offset=Math.max(0,offset-l); load();}
q.addEventListener('keydown',e=>{if(e.key==='Enter')reload()}); repo.addEventListener('keydown',e=>{if(e.key==='Enter')reload()}); summary().then(load).catch(e=>err('Dashboard load failed: '+e.message));
</script></main></body></html>"""
    html = html.replace("__FIELDS_JSON__", json.dumps(fields))
    server_code = "".join([
        "#!/usr/bin/env python3\n",
        "import argparse, json, sqlite3, webbrowser\n",
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n",
        "from urllib.parse import urlparse, parse_qs\n\n",
        "DEFAULT_DB = " + repr(db_path) + "\n",
        "FIELDS = " + repr(fields) + "\n",
        "HTML = " + repr(html) + "\n\n",
        "def qi(name):\n    return '\"' + str(name).replace('\\\"', '\"\"') + '\"'\n\n",
        "class H(BaseHTTPRequestHandler):\n",
        "    db_path = DEFAULT_DB\n",
        "    def log_message(self, fmt, *args):\n        return\n",
        "    def send_json(self, data):\n        raw=json.dumps(data,default=str).encode('utf-8'); self.send_response(200); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)\n",
        "    def do_GET(self):\n        p=urlparse(self.path)\n        if p.path=='/':\n            raw=HTML.encode('utf-8'); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw); return\n        if p.path=='/api/summary': return self.summary()\n        if p.path=='/api/rows': return self.rows(parse_qs(p.query))\n        self.send_response(404); self.end_headers()\n",
        "    def summary(self):\n        con=sqlite3.connect(self.db_path); con.row_factory=sqlite3.Row; cur=con.cursor()\n        total=cur.execute('SELECT COUNT(*) FROM findings').fetchone()[0]\n        sev=cur.execute('SELECT \"Risk Rating\" AS s, COUNT(*) AS c FROM findings GROUP BY \"Risk Rating\"').fetchall()\n        repos=cur.execute('SELECT COUNT(DISTINCT \"Repository\") FROM findings').fetchone()[0]\n        con.close(); self.send_json({'total':total,'repositories':repos,'by_severity':{str(r['s']).upper():r['c'] for r in sev}})\n",
        "    def rows(self, q):\n        allowed=set(FIELDS); limit=min(max(int(q.get('limit',['250'])[0] or 250),1),2000); off=max(int(q.get('offset',['0'])[0] or 0),0)\n        sort=q.get('sort',['Risk Rating'])[0]; sort=sort if sort in allowed else 'Risk Rating'; direction='ASC' if q.get('dir',['desc'])[0].lower()=='asc' else 'DESC'\n        where=[]; params=[]; term=q.get('q',[''])[0].strip(); sev=q.get('severity',[''])[0].strip().upper(); repo=q.get('repo',[''])[0].strip()\n        if term:\n            like='%'+term+'%'; cols=[c for c in FIELDS if c in allowed]; where.append('('+' OR '.join(qi(c)+' LIKE ?' for c in cols)+')'); params.extend([like]*len(cols))\n        if sev and 'Risk Rating' in allowed: where.append('UPPER(\"Risk Rating\") = ?'); params.append(sev)\n        if repo and 'Repository' in allowed: where.append('\"Repository\" LIKE ?'); params.append('%'+repo+'%')\n        wh=' WHERE '+' AND '.join(where) if where else ''\n        if sort=='Risk Rating': order='CASE UPPER(\"Risk Rating\") WHEN \"CRITICAL\" THEN 4 WHEN \"HIGH\" THEN 3 WHEN \"MEDIUM\" THEN 2 WHEN \"LOW\" THEN 1 ELSE 0 END'\n        elif sort in ('CVSS','Image Age (Days)','Latest Version Rank'): order='CAST('+qi(sort)+' AS REAL)'\n        else: order=qi(sort)\n        con=sqlite3.connect(self.db_path); con.row_factory=sqlite3.Row; cur=con.cursor()\n        total=cur.execute('SELECT COUNT(*) FROM findings'+wh, params).fetchone()[0]\n        sql='SELECT * FROM findings '+wh+' ORDER BY '+order+' '+direction+' LIMIT ? OFFSET ?'\n        data=[dict(r) for r in cur.execute(sql, params+[limit,off]).fetchall()]\n        con.close(); self.send_json({'total':total,'rows':data})\n",
        "def main():\n    ap=argparse.ArgumentParser(); ap.add_argument('--db',default=DEFAULT_DB); ap.add_argument('--host',default='127.0.0.1'); ap.add_argument('--port',type=int,default=8000); ap.add_argument('--open',action='store_true'); a=ap.parse_args()\n    H.db_path=a.db; url=f'http://{a.host}:{a.port}'; print('Dashboard running:',url); print('Database:',a.db); print('Press Ctrl+C to stop.')\n    if a.open: webbrowser.open(url)\n    HTTPServer((a.host,a.port),H).serve_forever()\n",
        "if __name__=='__main__': main()\n",
    ])
    with open(server_path, "w", encoding="utf-8") as f:
        f.write(server_code)
    return server_path

# -----------------------------------------------------------------------------
# Output CSV and JSON
# -----------------------------------------------------------------------------

fieldnames = [
    "BTO", "AppClass", "AssetID", "AppName", "CMDB Status", "Environment",
    "Risk Rating", "Support_SME", "IT Owner", "Business_Owner_SME",
    "Repository", "Type", "Tag", "Normalized Version", "Latest Version Rank",
    "Image Created", "Image Age (Days)", "Prisma-Image", "Packages",
    "Package Version", "Source Package", "Namespace", "Last Seen Date",
    "Due Date", "Days Until OverDue", "OverDue Band", "Fix Status", "CVE ID",
    "CVSS", "Risk Factors", "Package Path", "Description",
]

with open(args.output_csv, "w", newline="", encoding="utf-8") as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

with open(args.output_json, "w", encoding="utf-8") as json_file:
    json.dump(rows, json_file, indent=2, default=str)

# SQLite/dashboard uses a compact column set.
# These high-repetition metadata columns are intentionally excluded from SQLite
# to reduce database size and improve dashboard speed. They remain in CSV/JSON.
sqlite_excluded_fieldnames = {
    "BTO",
    "AppClass",
    "AssetID",
    "AppName",
    "Support_SME",
    "IT Owner",
    "Business_Owner_SME",
}
sqlite_fieldnames = [c for c in fieldnames if c not in sqlite_excluded_fieldnames]

if not args.no_sqlite:
    sqlite_path = write_sqlite_database(rows, sqlite_fieldnames, args.output_sqlite)
    dashboard_server_path = write_dashboard_server_script(args.dashboard_server, args.output_sqlite, sqlite_fieldnames)
else:
    sqlite_path = ""
    dashboard_server_path = ""


# -----------------------------------------------------------------------------
# Terminal summary
# -----------------------------------------------------------------------------

print("\n📊 Prisma Image Vulnerability Report - Latest Versions Only")
print("=" * 100)
print(f"Latest versions per repository: {args.latest_versions}")
print(f"Repositories with selected versions: {len(repo_version_seen)}")
print(f"Total vulnerability rows: {len(rows)}")

if summary:
    print("\nSeverity summary:")
    for sev, count in sorted(summary.items()):
        print(f"  {sev}: {count}")

if not args.summary_only:
    print("\nSelected repository versions:")
    for repo in sorted(repo_version_seen.keys())[:50]:
        versions = sorted(repo_version_seen[repo], key=version_key, reverse=True)
        print(f"  {repo}: {', '.join(versions)}")
    if len(repo_version_seen) > 50:
        print(f"  ... {len(repo_version_seen) - 50} more repositories omitted from terminal output")

print(f"\n✅ CSV saved:     {args.output_csv}")
print(f"✅ JSON saved:    {args.output_json}")
if not args.no_sqlite:
    print(f"✅ SQLite saved:  {sqlite_path}")
    print(f"✅ Dashboard app: {dashboard_server_path}")
    print("\nOpen dashboard:")
    print(f"  python3 {dashboard_server_path} --db {sqlite_path} --open")

