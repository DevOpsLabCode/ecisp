"""Cross-references a runtime alert's container image against this app's
own registry-scan history, so a Falco alert about a container doesn't just
say "here's suspicious behavior" -- it can also say "and by the way, the
image behind this container has N known CVEs from a scan run earlier."

This is the one piece of "AI-platform-style correlation" this v1 actually
does: no ML, just joining two data sets this app already has (a running
container's exact image reference, and that same image reference's SCA
scan results) that competing tools generally keep in separate products.
"""

from __future__ import annotations


def correlate_image_with_registry_scans(image_ref: str | None) -> str | None:
    if not image_ref:
        return None

    # Lazy import: registryscan and runtimedefender are independent
    # feature packages, and registryscan's manager spins up a worker
    # thread at import time -- no reason to pay for that (or create an
    # import-order dependency between the two packages) unless a runtime
    # alert actually names an image to look up.
    from ..registryscan.registry_scan_job import manager as registry_scan_manager

    matches = [
        scan
        for scan in registry_scan_manager.list()
        if scan.status == "completed" and scan.image_ref == image_ref and scan.result
    ]
    if not matches:
        return None

    # list() returns newest-first; the most recent scan of this exact
    # image is the most relevant one to cite.
    scan = matches[0]
    counts = scan.result.severity_counts()  # type: ignore[union-attr]
    total = sum(counts.values())
    if total == 0:
        return None

    breakdown = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
    return (
        f"This container is running image {image_ref}, which a registry scan "
        f"(id {scan.id}, completed {scan.finished_at}) found to have {total} "
        f"known vulnerabilities: {breakdown}."
    )
