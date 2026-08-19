import json

import openpyxl
import pytest

from app.batch_import import (
    TEMPLATE_COLUMNS,
    RowParseError,
    csv_template_text,
    parse_csv_bytes,
    parse_json_bytes,
    parse_upload,
    parse_xlsx_bytes,
    row_to_scan_request,
)


class TestParseCsvBytes:
    def test_parses_rows_into_dicts(self):
        data = b"provider,auth_method,profile\naws,profile,audit-1\naws,profile,audit-2\n"
        rows = parse_csv_bytes(data)
        assert rows == [
            {"provider": "aws", "auth_method": "profile", "profile": "audit-1"},
            {"provider": "aws", "auth_method": "profile", "profile": "audit-2"},
        ]

    def test_strips_utf8_bom(self):
        data = "provider,auth_method\naws,profile\n".encode("utf-8-sig")
        rows = parse_csv_bytes(data)
        assert rows == [{"provider": "aws", "auth_method": "profile"}]

    def test_empty_file_yields_no_rows(self):
        assert parse_csv_bytes(b"") == []


class TestParseJsonBytes:
    def test_parses_array_of_objects(self):
        data = json.dumps([{"provider": "aws", "auth_method": "profile"}]).encode()
        assert parse_json_bytes(data) == [{"provider": "aws", "auth_method": "profile"}]

    def test_rejects_non_array_top_level(self):
        with pytest.raises(RowParseError, match="top-level array"):
            parse_json_bytes(json.dumps({"provider": "aws"}).encode())

    def test_rejects_non_object_row(self):
        with pytest.raises(RowParseError, match="must be an object"):
            parse_json_bytes(json.dumps(["not-an-object"]).encode())


class TestParseXlsxBytes:
    def _make_workbook_bytes(self, rows: list[list]) -> bytes:
        import io

        wb = openpyxl.Workbook()
        ws = wb.active
        for row in rows:
            ws.append(row)
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    def test_parses_header_and_rows(self):
        data = self._make_workbook_bytes(
            [
                ["provider", "auth_method", "profile"],
                ["aws", "profile", "audit-1"],
                ["azure", "service_principal", None],
            ]
        )
        rows = parse_xlsx_bytes(data)
        assert rows[0] == {"provider": "aws", "auth_method": "profile", "profile": "audit-1"}
        assert rows[1]["provider"] == "azure"

    def test_skips_fully_blank_rows(self):
        data = self._make_workbook_bytes(
            [
                ["provider", "auth_method"],
                ["aws", "profile"],
                [None, None],
                ["azure", "cli"],
            ]
        )
        rows = parse_xlsx_bytes(data)
        assert len(rows) == 2

    def test_header_only_yields_no_rows(self):
        data = self._make_workbook_bytes([["provider", "auth_method"]])
        assert parse_xlsx_bytes(data) == []

    def test_empty_sheet_yields_no_rows(self):
        data = self._make_workbook_bytes([])
        assert parse_xlsx_bytes(data) == []


class TestParseUpload:
    def test_dispatches_csv(self):
        assert parse_upload("accounts.csv", b"provider,auth_method\naws,profile\n") == [
            {"provider": "aws", "auth_method": "profile"}
        ]

    def test_dispatches_json(self):
        data = json.dumps([{"provider": "aws"}]).encode()
        assert parse_upload("accounts.JSON", data) == [{"provider": "aws"}]

    def test_rejects_unsupported_extension(self):
        with pytest.raises(RowParseError, match="Unsupported file type"):
            parse_upload("accounts.txt", b"whatever")


class TestRowToScanRequest:
    def test_valid_aws_row(self):
        row = {"provider": "aws", "auth_method": "profile", "profile": "audit-1", "regions": "us-east-1,us-west-2"}
        req, error = row_to_scan_request(row)
        assert error is None
        assert req.provider == "aws"
        assert req.auth == {"profile": "audit-1"}
        assert req.scope == {"regions": ["us-east-1", "us-west-2"]}

    def test_unknown_provider(self):
        req, error = row_to_scan_request({"provider": "nope", "auth_method": "profile"})
        assert req is None
        assert "Unknown provider" in error

    def test_unknown_auth_method(self):
        req, error = row_to_scan_request({"provider": "aws", "auth_method": "nope"})
        assert req is None
        assert "Unknown auth_method" in error

    def test_auth_method_with_no_fields_is_valid(self):
        req, error = row_to_scan_request({"provider": "azure", "auth_method": "cli"})
        assert error is None
        assert req.auth == {}

    def test_ignores_columns_not_relevant_to_this_providers_method(self):
        row = {
            "provider": "aws",
            "auth_method": "profile",
            "profile": "audit-1",
            "tenant_id": "leftover-from-an-azure-row",
        }
        req, error = row_to_scan_request(row)
        assert error is None
        assert "tenant_id" not in req.auth

    def test_general_columns_are_applied(self):
        row = {
            "provider": "aws",
            "auth_method": "profile",
            "profile": "audit-1",
            "report_name": "my-report",
            "ruleset": "custom.json",
            "max_workers": "3",
            "debug": "true",
            "services": "iam,s3",
        }
        req, error = row_to_scan_request(row)
        assert error is None
        assert req.report_name == "my-report"
        assert req.ruleset == "custom.json"
        assert req.max_workers == 3
        assert req.debug is True
        assert req.services == ["iam", "s3"]

    def test_blank_optional_field_is_omitted(self):
        row = {"provider": "aws", "auth_method": "profile", "profile": "audit-1", "regions": ""}
        req, error = row_to_scan_request(row)
        assert error is None
        assert "regions" not in req.scope

    def test_bool_field_from_xlsx_native_bool(self):
        row = {"provider": "gcp", "auth_method": "user_account", "all_projects": True}
        req, error = row_to_scan_request(row)
        assert error is None
        assert req.scope == {"all_projects": True}

    def test_numeric_field_from_xlsx_native_number(self):
        row = {"provider": "aws", "auth_method": "profile", "profile": "audit-1", "max_workers": 7.0}
        req, error = row_to_scan_request(row)
        assert error is None
        assert req.max_workers == 7

    def test_blank_max_workers_falls_back_to_default(self):
        row = {"provider": "aws", "auth_method": "profile", "profile": "audit-1", "max_workers": ""}
        req, error = row_to_scan_request(row)
        assert error is None
        assert req.max_workers == 10

    def test_non_numeric_max_workers_is_a_row_error_not_a_crash(self):
        # Regression: this used to raise an uncaught ValueError instead of
        # returning a per-row error, which would abort the entire batch
        # rather than just skipping this one malformed row.
        row = {"provider": "aws", "auth_method": "profile", "profile": "audit-1", "max_workers": "abc"}
        req, error = row_to_scan_request(row)
        assert req is None
        assert "max_workers" in error
        assert "whole number" in error

    def test_non_numeric_max_rate_is_a_row_error_not_a_crash(self):
        row = {"provider": "aws", "auth_method": "profile", "profile": "audit-1", "max_rate": "fast"}
        req, error = row_to_scan_request(row)
        assert req is None
        assert "max_rate" in error


def test_csv_template_has_header_and_example_rows():
    text = csv_template_text()
    lines = text.strip().splitlines()
    assert lines[0].split(",") == TEMPLATE_COLUMNS
    assert len(lines) > 1
    parsed = parse_csv_bytes(text.encode())
    for row in parsed:
        req, error = row_to_scan_request(row)
        assert error is None, f"template example row failed to parse: {error}"
