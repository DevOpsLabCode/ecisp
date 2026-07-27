#!/usr/bin/env python3
"""
Prisma Cloud Compute Image Scan Report
- Auth via pcpi session_loader
- Reads images from images.txt
- Pulls deployed image scan data from Prisma Cloud Compute
- Matches requested images
- Exports CSV + JSON
"""

from pcpi import session_loader
import json
import csv
import html

# -----------------------------------------------------------------------------
# Step 1: Simple script arguments (edit defaults here if needed)
# -----------------------------------------------------------------------------

INPUT_FILE = "images.txt"
OUTPUT_CSV = "prisma_image_scan_report.csv"
OUTPUT_JSON = "prisma_image_scan_report.json"
OUTPUT_HTML = "prisma_image_scan_report.html"
QUIET = False
SHOW_INPUT = False

# -----------------------------------------------------------------------------
# Step 2: Authenticate using the same working method as your other script
# -----------------------------------------------------------------------------

session_managers = session_loader.load_config()

if not session_managers:
    raise SystemExit("No Prisma Cloud session managers were loaded from config.")

session_man = session_managers[0]

try:
    cwp_session = session_man.create_cwp_session()
except Exception as e:
    raise SystemExit(f"Failed to create Prisma Cloud CWP session: {e}")

print("\n✅ Prisma Cloud authentication successful\n")

# -----------------------------------------------------------------------------
# Step 3: Parse each line from the input file
# Supports:
#   image:tag
#   image -> tag
# Safely handles image names with registry ports
# -----------------------------------------------------------------------------

def parse_line(line):
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    if "->" in line:
        parts = line.split("->", 1)
        image = parts[0].strip()
        tag = parts[1].strip()
        if not image or not tag:
            return None
        return f"{image}:{tag}"

    if ":" not in line:
        return None

    # split from the RIGHT so registry:5000/image:tag still works
    image, tag = line.rsplit(":", 1)
    image = image.strip()
    tag = tag.strip()

    if not image or not tag:
        return None

    return f"{image}:{tag}"

# -----------------------------------------------------------------------------
# Step 4: Read requested images
# -----------------------------------------------------------------------------

images = []

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    for line in f:
        val = parse_line(line)
        if val:
            images.append(val)

if SHOW_INPUT:
    print("📥 Input Images:")
    for i in images:
        print("  -", i)
    print()

if not images:
    raise SystemExit(f"No valid images found in input file: {INPUT_FILE}")

# -----------------------------------------------------------------------------
# Step 5: Pull deployed image scan data from Prisma Cloud Compute
# -----------------------------------------------------------------------------

print("📡 Fetching deployed image scan data from Prisma Cloud...\n")

response = cwp_session.request("GET", "/api/v1/images")

if not response.ok:
    raise SystemExit(f"Failed to pull image scan data: {response.status_code} {response.text}")

all_images = response.json()

# -----------------------------------------------------------------------------
# Step 6: Normalize image tags from returned objects
# -----------------------------------------------------------------------------

def get_tags(img):
    tags = img.get("repoTag") or img.get("repoTags") or []

    if isinstance(tags, str):
        return [tags]

    if isinstance(tags, list):
        return [str(t).strip() for t in tags if t]

    return []

# -----------------------------------------------------------------------------
# Step 7: Find matching image
# -----------------------------------------------------------------------------

def match_image(full):
    for img in all_images:
        tags = get_tags(img)
        if full in tags:
            return img

        # fallback: sometimes compare just trailing image:tag
        for t in tags:
            if t.endswith(full):
                return img

    return None

# -----------------------------------------------------------------------------
# Step 8: Extract vulnerability counts safely
# -----------------------------------------------------------------------------

def get_vulns(img):
    v = img.get("vulnerabilities") or img.get("vulnerabilitySummary") or {}

    if isinstance(v, list):
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "fixable": 0,
        }

        for item in v:
            sev = str(item.get("severity", "")).lower()
            if sev in counts:
                counts[sev] += 1

            fix_status = str(item.get("fixStatus", "")).lower()
            if fix_status == "fix_available":
                counts["fixable"] += 1

        return counts

    return {
        "critical": v.get("critical", v.get("criticalCount", 0)),
        "high": v.get("high", v.get("highCount", 0)),
        "medium": v.get("medium", v.get("mediumCount", 0)),
        "low": v.get("low", v.get("lowCount", 0)),
        "fixable": v.get("fixable", v.get("fixableCount", 0)),
    }

# -----------------------------------------------------------------------------
# Step 9: Process images
# -----------------------------------------------------------------------------

results = []

print("======================================================")
print("📊 Prisma Cloud Scan Summary")
print("======================================================")
print(f"{'IMAGE':55} {'FOUND':8} {'CRITICAL':8} {'HIGH':8} {'MEDIUM':8} {'LOW':8} {'FIXABLE':8}")
print("-" * 110)

for img in images:
    match = match_image(img)

    if not match:
        row = {
            "image": img,
            "found": False,
            "critical": "",
            "high": "",
            "medium": "",
            "low": "",
            "fixable": "",
        }
    else:
        vulns = get_vulns(match)
        row = {
            "image": img,
            "found": True,
            **vulns,
        }

    results.append(row)

    if not QUIET:
        print(
            f"{row['image'][:55]:55} "
            f"{str(row['found']):8} "
            f"{str(row['critical']):8} "
            f"{str(row['high']):8} "
            f"{str(row['medium']):8} "
            f"{str(row['low']):8} "
            f"{str(row['fixable']):8}"
        )


# -----------------------------------------------------------------------------
# Step 10: Save HTML Dashboard
# -----------------------------------------------------------------------------
# Creates a self-contained HTML report that can be opened directly in a browser.
# No web server, JavaScript library, or external dependency is required.
# -----------------------------------------------------------------------------

def severity_int(value):
    """
    Convert vulnerability count values to integers safely.

    Missing images use blank values in the report, so this helper prevents
    empty strings or None values from breaking summary math.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def severity_class(row):
    """
    Return a CSS class based on the highest vulnerability severity present.

    This is used to color table rows in the HTML dashboard.
    """
    if severity_int(row.get("critical")) > 0:
        return "sev-critical"
    if severity_int(row.get("high")) > 0:
        return "sev-high"
    if severity_int(row.get("medium")) > 0:
        return "sev-medium"
    if severity_int(row.get("low")) > 0:
        return "sev-low"
    if not row.get("found"):
        return "sev-missing"
    return "sev-clean"


def write_html_report(results, output_file):
    """
    Generate an HTML dashboard from the image scan results.

    Dashboard includes:
    - Summary cards
    - Severity totals
    - Found / missing image count
    - Full image table
    - Lightweight search box
    """
    total_images = len(results)
    found_count = sum(1 for r in results if r.get("found") is True)
    missing_count = total_images - found_count

    total_critical = sum(severity_int(r.get("critical")) for r in results)
    total_high = sum(severity_int(r.get("high")) for r in results)
    total_medium = sum(severity_int(r.get("medium")) for r in results)
    total_low = sum(severity_int(r.get("low")) for r in results)
    total_fixable = sum(severity_int(r.get("fixable")) for r in results)

    generated_at = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows_html = ""
    for row in results:
        row_class = severity_class(row)
        found_display = "Yes" if row.get("found") is True else "No"
        rows_html += f"""
        <tr class="{row_class}">
            <td>{html.escape(str(row.get("image", "")))}</td>
            <td>{html.escape(found_display)}</td>
            <td>{html.escape(str(row.get("critical", "")))}</td>
            <td>{html.escape(str(row.get("high", "")))}</td>
            <td>{html.escape(str(row.get("medium", "")))}</td>
            <td>{html.escape(str(row.get("low", "")))}</td>
            <td>{html.escape(str(row.get("fixable", "")))}</td>
        </tr>
        """

    dashboard = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Prisma Cloud Image Scan Report</title>
<style>
    body {{
        font-family: Arial, Helvetica, sans-serif;
        margin: 24px;
        background: #f4f6f8;
        color: #111827;
    }}
    h1 {{
        margin-bottom: 4px;
    }}
    .subtitle {{
        color: #4b5563;
        margin-bottom: 24px;
    }}
    .cards {{
        display: flex;
        flex-wrap: wrap;
        gap: 14px;
        margin-bottom: 24px;
    }}
    .card {{
        background: #ffffff;
        border-radius: 10px;
        padding: 16px 18px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        min-width: 145px;
    }}
    .card-title {{
        color: #6b7280;
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: .04em;
    }}
    .card-number {{
        font-size: 30px;
        font-weight: 700;
        margin-top: 6px;
    }}
    .search {{
        margin: 12px 0 18px 0;
    }}
    input {{
        width: 360px;
        max-width: 95%;
        padding: 10px;
        border: 1px solid #cbd5e1;
        border-radius: 8px;
        font-size: 14px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        background: #ffffff;
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }}
    th, td {{
        border-bottom: 1px solid #e5e7eb;
        padding: 10px;
        text-align: left;
        font-size: 14px;
    }}
    th {{
        background: #111827;
        color: white;
        position: sticky;
        top: 0;
    }}
    .sev-critical td {{ background: #fee2e2; }}
    .sev-high td {{ background: #ffedd5; }}
    .sev-medium td {{ background: #fef9c3; }}
    .sev-low td {{ background: #eff6ff; }}
    .sev-missing td {{ background: #f3f4f6; color: #6b7280; }}
    .sev-clean td {{ background: #ecfdf5; }}
    .footer {{
        margin-top: 18px;
        color: #6b7280;
        font-size: 12px;
    }}
</style>
<script>
function filterTable() {{
    const filter = document.getElementById("searchBox").value.toLowerCase();
    const rows = document.querySelectorAll("#reportTable tbody tr");
    rows.forEach(row => {{
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(filter) ? "" : "none";
    }});
}}
</script>
</head>
<body>
    <h1>Prisma Cloud Image Scan Report</h1>
    <div class="subtitle">Generated: {html.escape(generated_at)}</div>

    <div class="cards">
        <div class="card"><div class="card-title">Images Requested</div><div class="card-number">{total_images}</div></div>
        <div class="card"><div class="card-title">Found</div><div class="card-number">{found_count}</div></div>
        <div class="card"><div class="card-title">Missing</div><div class="card-number">{missing_count}</div></div>
        <div class="card"><div class="card-title">Critical</div><div class="card-number">{total_critical}</div></div>
        <div class="card"><div class="card-title">High</div><div class="card-number">{total_high}</div></div>
        <div class="card"><div class="card-title">Medium</div><div class="card-number">{total_medium}</div></div>
        <div class="card"><div class="card-title">Low</div><div class="card-number">{total_low}</div></div>
        <div class="card"><div class="card-title">Fixable</div><div class="card-number">{total_fixable}</div></div>
    </div>

    <div class="search">
        <input id="searchBox" onkeyup="filterTable()" placeholder="Search image, severity, found status...">
    </div>

    <table id="reportTable">
        <thead>
            <tr>
                <th>Image</th>
                <th>Found</th>
                <th>Critical</th>
                <th>High</th>
                <th>Medium</th>
                <th>Low</th>
                <th>Fixable</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>

    <div class="footer">
        Report generated from Prisma Cloud Compute deployed image scan data.
    </div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(dashboard)

# -----------------------------------------------------------------------------
# Step 11: Save JSON
# -----------------------------------------------------------------------------

with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

# -----------------------------------------------------------------------------
# Step 12: Save CSV
# -----------------------------------------------------------------------------

with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["image", "found", "critical", "high", "medium", "low", "fixable"]
    )
    writer.writeheader()
    writer.writerows(results)

write_html_report(results, OUTPUT_HTML)

# -----------------------------------------------------------------------------
# Step 13: Final output
# -----------------------------------------------------------------------------

print("\n✅ Output files generated:")
print("   JSON:", OUTPUT_JSON)
print("   CSV :", OUTPUT_CSV)
print("   HTML:", OUTPUT_HTML)