"""
Parses a bulk-import file (CSV, XLSX, or JSON) of many accounts to scan --
each row is one account's full scan configuration, flattened (no nested
auth/scope objects, since CSV/XLSX can't represent nesting). A single file
can mix rows for different providers; unrecognized columns for a given
row's provider are ignored rather than rejected, since one shared column
set has to cover every provider's differently-named fields.
"""
import csv
import io
import json

import openpyxl
from pydantic import ValidationError

from .providers_meta import PROVIDERS, all_field_names, auth_field_names, scope_field_names
from .schemas import ScanCreateRequest

GENERAL_COLUMNS = [
    "provider",
    "auth_method",
    "report_name",
    "services",
    "skipped_services",
    "ruleset",
    "max_workers",
    "max_rate",
    "debug",
]

# Fields that hold multiple values -- split on comma/semicolon when read from
# a flat cell.
LIST_FIELDS = {"regions", "excluded_regions", "subscription_ids", "services", "skipped_services"}
BOOL_FIELDS = {"all_projects", "all_subscriptions", "debug"}
NUMERIC_FIELDS = {"max_workers", "max_rate"}

TEMPLATE_COLUMNS = GENERAL_COLUMNS + all_field_names()

TEMPLATE_EXAMPLE_ROWS = [
    {
        "provider": "aws",
        "auth_method": "profile",
        "report_name": "prod-account-1",
        "profile": "prod-account-1-audit",
        "regions": "us-east-1;us-west-2",
    },
    {
        "provider": "azure",
        "auth_method": "service_principal",
        "report_name": "prod-subscription-2",
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "client_id": "11111111-1111-1111-1111-111111111111",
        "client_secret": "<secret>",
    },
]


class RowParseError(ValueError):
    pass


def _coerce(name: str, raw) -> object:
    if raw is None:
        return None
    if name in BOOL_FIELDS:
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "y")
    if name in NUMERIC_FIELDS:
        if isinstance(raw, int | float):
            return int(raw)
        raw = str(raw).strip()
        if not raw:
            return None
        try:
            return int(raw)
        except ValueError:
            raise RowParseError(f"{name!r} must be a whole number, got {raw!r}") from None
    raw_str = str(raw).strip() if not isinstance(raw, str) else raw.strip()
    if raw_str == "":
        return None
    if name in LIST_FIELDS:
        return [v.strip() for v in raw_str.replace(";", ",").split(",") if v.strip()]
    return raw_str


def row_to_scan_request(row: dict) -> tuple[ScanCreateRequest | None, str | None]:
    """Returns (request, None) on success or (None, error_message) on failure."""
    provider = str(row.get("provider") or "").strip().lower()
    auth_method = str(row.get("auth_method") or "").strip()

    provider_meta = PROVIDERS.get(provider)
    if not provider_meta:
        return None, f"Unknown provider: {provider!r}"
    if auth_method not in provider_meta["authMethods"]:
        valid = ", ".join(provider_meta["authMethods"])
        return None, f"Unknown auth_method {auth_method!r} for {provider}. Valid: {valid}"

    method_fields = auth_field_names(provider, auth_method)
    scope_fields = scope_field_names(provider)

    # Everything below can raise RowParseError (a malformed cell, e.g. a
    # non-numeric max_workers) or Pydantic's ValidationError -- both are
    # per-row problems, not per-batch ones, so both are converted to the
    # (None, message) failure shape rather than propagating and aborting
    # every other row in the same import.
    try:
        auth: dict = {}
        scope: dict = {}
        for key, raw in row.items():
            if key in GENERAL_COLUMNS or key in ("provider", "auth_method") or raw is None:
                continue
            value = _coerce(key, raw)
            if value in (None, "", []):
                continue
            if key in method_fields:
                auth[key] = value
            elif key in scope_fields:
                scope[key] = value

        return ScanCreateRequest(
            provider=provider,
            auth_method=auth_method,
            auth=auth,
            scope=scope,
            report_name=_coerce("report_name", row.get("report_name")) or None,
            services=_coerce("services", row.get("services")) or [],
            skipped_services=_coerce("skipped_services", row.get("skipped_services")) or [],
            ruleset=_coerce("ruleset", row.get("ruleset")) or "default.json",
            max_workers=_coerce("max_workers", row.get("max_workers")) or 10,
            max_rate=_coerce("max_rate", row.get("max_rate")),
            debug=bool(_coerce("debug", row.get("debug"))),
        ), None
    except ValidationError as exc:
        return None, "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
    except RowParseError as exc:
        return None, str(exc)


def parse_csv_bytes(data: bytes) -> list[dict]:
    text = data.decode("utf-8-sig")
    return [dict(row) for row in csv.DictReader(io.StringIO(text))]


def parse_json_bytes(data: bytes) -> list[dict]:
    parsed = json.loads(data.decode("utf-8"))
    if not isinstance(parsed, list):
        raise RowParseError("JSON import must be a top-level array of row objects")
    for row in parsed:
        if not isinstance(row, dict):
            raise RowParseError("Each row in the JSON array must be an object")
    return parsed


def parse_xlsx_bytes(data: bytes) -> list[dict]:
    workbook = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    sheet = workbook.worksheets[0]
    rows_iter = sheet.iter_rows(values_only=True)
    try:
        header = [str(c).strip() if c is not None else "" for c in next(rows_iter)]
    except StopIteration:
        return []
    rows = []
    for values in rows_iter:
        if values is None or all(v is None for v in values):
            continue
        rows.append({header[i]: values[i] for i in range(min(len(header), len(values)))})
    return rows


def parse_upload(filename: str, data: bytes) -> list[dict]:
    name = (filename or "").lower()
    if name.endswith(".csv"):
        return parse_csv_bytes(data)
    if name.endswith(".json"):
        return parse_json_bytes(data)
    if name.endswith(".xlsx"):
        return parse_xlsx_bytes(data)
    raise RowParseError(f"Unsupported file type: {filename!r} (use .csv, .xlsx, or .json)")


def csv_template_text() -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=TEMPLATE_COLUMNS)
    writer.writeheader()
    for example in TEMPLATE_EXAMPLE_ROWS:
        writer.writerow(example)
    return buf.getvalue()
