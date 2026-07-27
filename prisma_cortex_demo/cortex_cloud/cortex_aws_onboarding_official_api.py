#!/usr/bin/env python3

'''
===============================================================================
                  Cortex Cloud AWS Account Onboarding Automation
                    Official Cortex Cloud Platform API Workflow
                                Version 2.7
===============================================================================

Author
------
Stan Zvenigorodskiy

Overview
--------
This utility automates AWS account onboarding into Cortex Cloud by integrating
with the official Cortex Cloud Platform APIs and AWS CloudFormation.

The script is designed for enterprise environments managing multiple AWS
accounts through AWS Organizations or manually maintained account inventories.

Instead of onboarding accounts individually through the Cortex Cloud UI,
this utility performs inventory discovery, onboarding analysis, CloudFormation
template generation, optional CloudFormation deployment, validation, and
report generation.

The implementation follows the official Cortex Cloud onboarding workflow.

-------------------------------------------------------------------------------
Business Value
-------------------------------------------------------------------------------

• Eliminates repetitive manual AWS account onboarding.
• Compares AWS Organizations against Cortex Cloud inventory.
• Identifies missing onboarded accounts.
• Generates official Cortex Cloud onboarding templates.
• Optionally deploys CloudFormation automatically.
• Produces audit-ready CSV and JSON reports.
• Supports hundreds or thousands of AWS accounts.
• Safe Dry Run mode for change validation.
• Enterprise logging and troubleshooting.

-------------------------------------------------------------------------------
Architecture
-------------------------------------------------------------------------------

                 +----------------------------+
                 | AWS Organizations          |
                 +-------------+--------------+
                               |
                               |
                    Discover AWS Accounts
                               |
                               v
                 +----------------------------+
                 | Inventory Comparison       |
                 | Cortex Cloud APIs          |
                 +-------------+--------------+
                               |
               Already Onboarded / Missing
                               |
                               v
                 +----------------------------+
                 | Create Onboarding Template |
                 | Cortex Cloud API           |
                 +-------------+--------------+
                               |
                     CloudFormation Template
                               |
                               v
                 +----------------------------+
                 | Optional Deployment        |
                 | AWS CloudFormation         |
                 +-------------+--------------+
                               |
                               |
                               v
                 +----------------------------+
                 | Validation & Reporting     |
                 +----------------------------+

-------------------------------------------------------------------------------
Official Cortex Cloud APIs
-------------------------------------------------------------------------------

Uses the official Cloud Onboarding Platform APIs.

• get_instances
      Retrieves Cloud Onboarding Instances

• get_accounts
      Retrieves onboarded cloud accounts

• create_instance_template
      Generates the official onboarding template

Authentication

Authorization
x-xdr-auth-id

Optional endpoint overrides are supported through environment variables.

-------------------------------------------------------------------------------
Supported Modes
-------------------------------------------------------------------------------

REPORT

    Inventory only.

    • Discover AWS accounts
    • Compare with Cortex Cloud
    • Generate onboarding report

ONBOARD

    Creates official Cortex Cloud onboarding templates
    for accounts not currently onboarded.

Optionally:

    • Deploy CloudFormation automatically
    • Wait for deployment completion
    • Record stack status

VALIDATE

    Confirms current onboarding status for selected
    AWS accounts.

-------------------------------------------------------------------------------
Supported Input Sources
-------------------------------------------------------------------------------

1) AWS Organizations

Automatically discovers all ACTIVE AWS accounts.

Example

python cortex_aws_onboarding.py \
    --mode report \
    --source aws-org

2) TXT File

Supports:

123456789012
123456789012,Production
123456789012 Development Account

-------------------------------------------------------------------------------
CloudFormation Deployment
-------------------------------------------------------------------------------

The script supports two execution models.

Template Generation Only

Creates the official Cortex Cloud onboarding template.

CloudFormation Deployment

When enabled

--deploy-template

the script

• downloads the generated template
• extracts TemplateURL if required
• creates or updates the CloudFormation stack
• waits for completion
• records deployment status

Supported operations

Create Stack

Update Stack

Waiters

Stack Status Collection

-------------------------------------------------------------------------------
AWS Authentication
-------------------------------------------------------------------------------

Supports

• Local AWS credentials
• AWS Profiles
• AssumeRole
• External ID
• Cross-account deployment

-------------------------------------------------------------------------------
Cortex Authentication
-------------------------------------------------------------------------------

Environment Variables

CORTEX_API_BASE_URL

CORTEX_API_KEY

CORTEX_API_KEY_ID

-------------------------------------------------------------------------------
Generated Reports
-------------------------------------------------------------------------------

CSV

Complete onboarding report

JSON

Machine-readable report

Columns

AWS Account ID

Account Name

Onboarding Status

Validation Status

Cloud Instance ID

CloudFormation Stack Name

CloudFormation Stack Status

Template URL

Timestamp

Error Message

-------------------------------------------------------------------------------
Examples
-------------------------------------------------------------------------------

Inventory Report

python cortex_aws_onboarding.py \
    --mode report \
    --source aws-org

Inventory from TXT

python cortex_aws_onboarding.py \
    --mode report \
    --input accounts.txt

Validate

python cortex_aws_onboarding.py \
    --mode validate \
    --input accounts.txt

Generate Templates

python cortex_aws_onboarding.py \
    --mode onboard \
    --input accounts.txt

Generate First 10 Templates

python cortex_aws_onboarding.py \
    --mode onboard \
    --input accounts.txt \
    --count 10

Dry Run

python cortex_aws_onboarding.py \
    --mode onboard \
    --input accounts.txt \
    --dry-run

Deploy CloudFormation

python cortex_aws_onboarding.py \
    --mode onboard \
    --input accounts.txt \
    --deploy-template

Verbose Debug

python cortex_aws_onboarding.py \
    --mode onboard \
    --input accounts.txt \
    --verbose

-------------------------------------------------------------------------------
Safety Features
-------------------------------------------------------------------------------

✓ Dry Run mode

✓ Automatic retries

✓ Request timeout

✓ SSL verification

✓ Pagination

✓ Duplicate account removal

✓ Account ID validation

✓ CloudFormation waiters

✓ Structured logging

✓ Error handling

-------------------------------------------------------------------------------
Current Limitations
-------------------------------------------------------------------------------

• Final onboarding validation depends on Cortex Cloud asynchronously
  processing the deployed CloudFormation stack.

• CloudFormation deployment requires sufficient IAM permissions.

• API response fields may differ between Cortex Cloud versions. The script
  automatically searches for common response keys but may require updates if
  future API versions introduce breaking changes.

-------------------------------------------------------------------------------
Future Enhancements
-------------------------------------------------------------------------------

Planned improvements include:

• Parallel onboarding of multiple AWS accounts
• SQLite inventory database
• Interactive HTML dashboard
• Resume failed deployments
• Automatic rollback detection
• Organization Unit (OU) onboarding
• Account tagging policies
• Multi-region deployment
• Scheduled inventory reports
• Email and Slack notifications
• Cortex Cloud SDK support (when publicly available)

-------------------------------------------------------------------------------
Version History
-------------------------------------------------------------------------------

Version 2.7

• Official Cortex Cloud onboarding workflow
• Uses create_instance_template API
• Supports AWS Organizations
• TXT inventory support
• CloudFormation deployment
• Cross-account AssumeRole
• Pagination
• Retry logic
• Detailed reporting
• Dry Run mode
• Enterprise logging

===============================================================================

'''

import argparse
import csv
import html
import json
import logging
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import boto3
except ImportError:
    boto3 = None


AWS_ACCOUNT_RE = re.compile(r"^\d{12}$")

DEFAULT_GET_INSTANCES_ENDPOINT = "/public_api/v1/cloud_onboarding/get_instances"
DEFAULT_GET_ACCOUNTS_ENDPOINT = "/public_api/v1/cloud_onboarding/get_accounts"
DEFAULT_CREATE_TEMPLATE_ENDPOINT = "/public_api/v1/cloud_onboarding/create_instance_template"


@dataclass(frozen=True)
class AwsAccount:
    account_id: str
    account_name: str = ""


@dataclass(frozen=True)
class AccountReportRow:
    aws_account_id: str
    account_name: str
    onboarding_status: str
    validation_status: str
    template_url: str
    cortex_instance_id: str
    error_message: str
    timestamp: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(message)s")


def require_valid_aws_account_id(account_id: str) -> str:
    normalized = str(account_id).strip()
    if not AWS_ACCOUNT_RE.match(normalized):
        raise ValueError(f"Invalid AWS account ID: {account_id!r}. Expected exactly 12 digits.")
    return normalized


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    safe = dict(headers)
    for key in ("Authorization", "x-xdr-auth-id"):
        if key in safe and safe[key]:
            value = str(safe[key])
            safe[key] = value[:4] + "..." + value[-4:] if len(value) > 8 else "***"
    return safe


def normalize_key(key: Any) -> str:
    """Normalize Cortex response keys so DATA, data, AccountId, account_id all compare safely."""
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def get_any_key(data: Dict[str, Any], names: Iterable[str]) -> Optional[Any]:
    """Case-insensitive / underscore-insensitive dictionary lookup."""
    if not isinstance(data, dict):
        return None
    wanted = {normalize_key(name) for name in names}
    for key, value in data.items():
        if normalize_key(key) in wanted:
            return value
    return None


def find_first_key(data: Any, keys: Iterable[str]) -> Optional[Any]:
    key_set = {normalize_key(key) for key in keys}
    if isinstance(data, dict):
        for key, value in data.items():
            if normalize_key(key) in key_set and value not in (None, "", []):
                return value
            nested = find_first_key(value, key_set)
            if nested not in (None, "", []):
                return nested
    elif isinstance(data, list):
        for item in data:
            nested = find_first_key(item, key_set)
            if nested not in (None, "", []):
                return nested
    return None


class CortexClient:
    """Cortex Cloud API client using official cloud onboarding endpoints."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_key_id: str,
        timeout: int = 60,
        verify_ssl: bool = True,
        max_retries: int = 3,
        page_size: int = 50,
        dump_raw: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_key_id = str(api_key_id)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.page_size = page_size
        self.dump_raw = dump_raw

        self.get_instances_endpoint = os.getenv("CORTEX_GET_INSTANCES_ENDPOINT", DEFAULT_GET_INSTANCES_ENDPOINT)
        self.get_accounts_endpoint = os.getenv("CORTEX_GET_ACCOUNTS_ENDPOINT", DEFAULT_GET_ACCOUNTS_ENDPOINT)
        self.create_template_endpoint = os.getenv("CORTEX_CREATE_TEMPLATE_ENDPOINT", DEFAULT_CREATE_TEMPLATE_ENDPOINT)

        self.session = requests.Session()
        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": self.api_key,
            "x-xdr-auth-id": self.api_key_id,
        }

    def _request(self, method: str, endpoint: str, payload: Optional[dict] = None) -> Any:
        url = f"{self.base_url}{endpoint}"
        logging.debug("Cortex API %s %s headers=%s payload=%s", method, url, redact_headers(self._headers()), json.dumps(payload or {}, default=str))
        response = self.session.request(
            method=method,
            url=url,
            headers=self._headers(),
            json=payload,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )

        if response.status_code >= 400:
            raise RuntimeError(f"Cortex API error {response.status_code} for {endpoint}: {response.text[:1000]}")

        if not response.text.strip():
            return {}

        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError(f"Cortex API returned non-JSON response for {endpoint}: {response.text[:500]}") from exc

    @staticmethod
    def _unwrap_items(data: Any) -> List[Dict[str, Any]]:
        """
        Cortex Cloud API response shapes differ by tenant/API version.
        Supports lowercase and uppercase keys such as reply.DATA, DATA, RESULT, ITEMS, etc.
        """
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if not isinstance(data, dict):
            return []

        preferred_keys = (
            "DATA", "data",
            "ITEMS", "items",
            "RESULTS", "results",
            "RESULT", "result",
            "RESOURCES", "resources",
            "CLOUD_ACCOUNTS", "cloud_accounts", "cloudAccounts",
            "ACCOUNTS", "accounts",
            "INSTANCES", "instances",
            "CLOUD_INSTANCES", "cloud_instances", "cloudInstances",
            "CLOUD_ONBOARDING_INSTANCES", "cloud_onboarding_instances", "cloudOnboardingInstances",
            "reply", "REPLY",
        )

        for key in preferred_keys:
            value = get_any_key(data, [key])
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
            if isinstance(value, dict):
                nested = CortexClient._unwrap_items(value)
                if nested:
                    return nested

        return recursively_collect_dicts(data)

    @staticmethod
    def _extract_account_id(item: Dict[str, Any]) -> Optional[str]:
        value = find_first_key(item, [
            "account_id", "accountId", "ACCOUNT_ID", "ACCOUNTID",
            "aws_account_id", "awsAccountId", "AWS_ACCOUNT_ID", "AWSACCOUNTID",
            "cloud_account_id", "cloudAccountId", "CLOUD_ACCOUNT_ID", "CLOUDACCOUNTID",
            "cloud_account", "cloudAccount", "external_id", "externalId",
            "awsId", "AWS_ID", "id", "ID", "account", "ACCOUNT",
        ])
        if value and AWS_ACCOUNT_RE.match(str(value).strip()):
            return str(value).strip()

        # Last-resort recursive regex search for any standalone 12-digit AWS account ID.
        text = json.dumps(item, default=str)
        match = re.search(r"(?<!\d)(\d{12})(?!\d)", text)
        return match.group(1) if match else None

    @staticmethod
    def _extract_all_account_ids(item: Dict[str, Any]) -> List[str]:
        """Return every 12-digit AWS account ID found anywhere in a Cortex object.

        Cortex get_instances may return a single integration instance containing
        scope_modifications.accounts.account_ids with many AWS accounts. Older
        script versions only kept the first ID from that object, which caused
        false MISSING rows even though the inventory was pulled from Cortex.
        """
        ids = set()

        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                for value in obj.values():
                    walk(value)
            elif isinstance(obj, list):
                for value in obj:
                    walk(value)
            elif isinstance(obj, (str, int)):
                text = str(obj).strip()
                if AWS_ACCOUNT_RE.match(text):
                    ids.add(text)
                else:
                    for match in re.findall(r"(?<!\d)(\d{12})(?!\d)", text):
                        ids.add(match)

        direct = CortexClient._extract_account_id(item)
        if direct:
            ids.add(direct)
        walk(item)
        return sorted(ids)

    @staticmethod
    def _extract_instance_id(item: Dict[str, Any]) -> str:
        return str(find_first_key(item, [
            "instance_id", "instanceId", "INSTANCE_ID", "INSTANCEID",
            "cloud_instance_id", "cloudInstanceId", "CLOUD_INSTANCE_ID",
            "id", "ID",
        ]) or "")

    @staticmethod
    def _extract_name(item: Dict[str, Any]) -> str:
        return str(find_first_key(item, [
            "account_name", "accountName", "ACCOUNT_NAME",
            "name", "NAME",
            "instance_name", "instanceName", "INSTANCE_NAME",
            "display_name", "displayName", "DISPLAY_NAME",
        ]) or "")

    @staticmethod
    def _extract_status(item: Dict[str, Any]) -> str:
        return str(find_first_key(item, [
            "status", "STATUS",
            "onboarding_status", "onboardingStatus", "ONBOARDING_STATUS",
            "connection_status", "connectionStatus", "CONNECTION_STATUS",
            "state", "STATE",
            "_cortex_instance_status",
        ]) or "UNKNOWN")


    @staticmethod
    def _is_aws_item(item: Dict[str, Any]) -> bool:
        provider = str(find_first_key(item, [
            "cloud_provider", "cloudProvider", "CLOUD_PROVIDER",
            "provider", "PROVIDER",
            "cloud_type", "cloudType", "CLOUD_TYPE",
            "type", "TYPE",
        ]) or "").upper()
        if "AWS" in provider or "AMAZON" in provider:
            return True
        # If it has a valid 12-digit account id and came from cloud onboarding, keep it.
        return CortexClient._extract_account_id(item) is not None

    @staticmethod
    def _filter_payload(search_field: str, search_value: str, start: int, end: int, search_type: str = "EQ") -> Dict[str, Any]:
        return {
            "request_data": {
                "filter_data": {
                    "sort": [{"FIELD": "STATUS", "ORDER": "DESC"}],
                    "paging": {"from": start, "to": end},
                    "filter": {
                        "AND": [
                            {
                                "SEARCH_FIELD": search_field,
                                "SEARCH_TYPE": search_type,
                                "SEARCH_VALUE": search_value,
                            }
                        ]
                    },
                }
            }
        }

    def list_instances(self) -> List[Dict[str, Any]]:
        """
        List AWS cloud onboarding instances.

        Important: do NOT apply a Cortex-side CLOUD_PROVIDER=AWS filter by default.
        Some Cortex tenants/API versions return provider values such as AWS, aws,
        AMAZON, or Amazon Web Services. Pull the page unfiltered, then filter in Python.
        """
        all_items: List[Dict[str, Any]] = []
        start = 0

        while True:
            payload = {
                "request_data": {
                    "filter_data": {
                        "paging": {"from": start, "to": start + self.page_size}
                    }
                }
            }
            data = self._request("POST", self.get_instances_endpoint, payload)

            if self.dump_raw:
                dump_cortex_response(f"get_instances_from_{start}", data)

            if isinstance(data, dict):
                logging.debug("Cortex get_instances top-level keys: %s", list(data.keys()))
                reply = get_any_key(data, ["reply", "REPLY"])
                if isinstance(reply, dict):
                    logging.debug("Cortex get_instances reply keys: %s", list(reply.keys()))

            raw_items = self._unwrap_items(data)
            items = [item for item in raw_items if self._is_aws_item(item)]
            all_items.extend(items)

            logging.info(
                "Loaded Cortex cloud instances page from=%s raw_count=%s aws_count=%s total_aws=%s",
                start,
                len(raw_items),
                len(items),
                len(all_items),
            )

            if len(raw_items) < self.page_size:
                break
            start += self.page_size

        return all_items

    def list_accounts_for_instance(self, instance_id: str) -> List[Dict[str, Any]]:
        """
        List accounts for one Cortex cloud onboarding instance.

        Important: do not force STATUS=ENABLED here. Cortex may report already-onboarded
        AWS accounts as CONNECTED, ACTIVE, ENABLED, PENDING, SUCCESS, or a tenant-specific
        status. Filtering only ENABLED can hide accounts and create false MISSING results.
        """
        all_items: List[Dict[str, Any]] = []
        start = 0

        while True:
            payload = {
                "request_data": {
                    "instance_id": instance_id,
                    "filter_data": {
                        "sort": [{"FIELD": "STATUS", "ORDER": "DESC"}],
                        "paging": {"from": start, "to": start + self.page_size},
                    },
                }
            }
            data = self._request("POST", self.get_accounts_endpoint, payload)

            if self.dump_raw:
                dump_cortex_response(f"get_accounts_instance_{instance_id}_from_{start}", data)

            if isinstance(data, dict):
                logging.debug("Cortex get_accounts top-level keys: %s", list(data.keys()))
                reply = get_any_key(data, ["reply", "REPLY"])
                if isinstance(reply, dict):
                    logging.debug("Cortex get_accounts reply keys: %s", list(reply.keys()))

            items = self._unwrap_items(data)
            all_items.extend(items)

            logging.info("Loaded Cortex accounts for instance=%s from=%s count=%s total=%s", instance_id, start, len(items), len(all_items))

            if len(items) < self.page_size:
                break
            start += self.page_size

        return all_items

    @staticmethod
    def _merge_instance_context(account_item: Dict[str, Any], instance: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(account_item)
        merged.setdefault("_cortex_instance_id", CortexClient._extract_instance_id(instance))
        merged.setdefault("_cortex_instance_name", CortexClient._extract_name(instance))
        merged.setdefault("_cortex_instance_status", CortexClient._extract_status(instance))
        return merged

    def list_onboarded_accounts(self, instance_id: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Build a normalized map: AWS account ID -> Cortex object.

        Cortex can expose the AWS account ID either in get_instances.DATA or in
        get_accounts.DATA. The previous version only trusted get_accounts, which caused
        false MISSING results when the instance itself was the AWS account record.
        """
        results: Dict[str, Dict[str, Any]] = {}
        account_items: List[Dict[str, Any]] = []
        instances: List[Dict[str, Any]] = []

        if instance_id:
            account_items.extend(self.list_accounts_for_instance(instance_id))
        else:
            instances = self.list_instances()
            if not instances:
                logging.warning("No AWS cloud onboarding instances returned by Cortex.")

            # First trust get_instances itself. In many Cortex tenants this is the
            # source containing the actual AWS account ID.
            for instance in instances:
                account_ids = self._extract_all_account_ids(instance)
                for account_id in account_ids:
                    results[account_id] = self._merge_instance_context(instance, instance)
                    logging.debug("Discovered AWS account from get_instances: account_id=%s instance_id=%s status=%s", account_id, self._extract_instance_id(instance), self._extract_status(instance))

            # Then enrich with get_accounts for every instance where available.
            for instance in instances:
                discovered_id = self._extract_instance_id(instance)
                if not discovered_id:
                    logging.debug("Skipping instance without ID: %s", json.dumps(instance, default=str)[:500])
                    continue
                try:
                    for account_item in self.list_accounts_for_instance(discovered_id):
                        account_items.append(self._merge_instance_context(account_item, instance))
                except Exception as exc:
                    logging.warning("Could not list accounts for instance %s: %s", discovered_id, exc)

        missing_id_count = 0
        for item in account_items:
            account_ids = self._extract_all_account_ids(item)
            if account_ids:
                # Prefer richer get_accounts object, but keep instance context.
                for account_id in account_ids:
                    existing = results.get(account_id, {})
                    merged = dict(existing)
                    merged.update(item)
                    results[account_id] = merged
            else:
                missing_id_count += 1
                logging.debug("Cortex account object without discoverable 12-digit AWS account ID: %s", json.dumps(item, default=str)[:1000])

        sample_ids = sorted(results.keys())[:10]
        logging.info("Discovered onboarded Cortex AWS accounts with account IDs: %s", len(results))
        logging.info("Sample discovered Cortex AWS account IDs: %s", ", ".join(sample_ids) if sample_ids else "NONE")
        if missing_id_count:
            logging.warning("Cortex returned %s account objects but no 12-digit AWS account ID was found in them.", missing_id_count)
        return results

    def create_aws_instance_template(self, account: AwsAccount, args: argparse.Namespace, dry_run: bool = False) -> Tuple[str, str, str]:
        """
        Create official cloud onboarding integration template.

        Returns:
            onboarding_status, template_url, cortex_instance_id_or_error
        """
        regions = [r.strip() for r in (args.regions or "").split(",") if r.strip()]

        request_data: Dict[str, Any] = {
            "scope": args.scope,
            "scan_mode": args.scan_mode,
            "cloud_provider": "AWS",
            "instance_name": account.account_name or f"AWS-{account.account_id}",
            "custom_resources_tags": [{"key": k, "value": v} for k, v in args.resource_tags.items()],
            "collection_configuration": {
                "audit_logs": {"enabled": bool(args.enable_audit_logs)}
            },
            "scope_modifications": {
                "accounts": {
                    "enabled": True,
                    "type": "INCLUDE",
                    "account_ids": [account.account_id],
                }
            },
            "additional_capabilities": {
                "xsiam_analytics": bool(args.enable_xsiam_analytics),
                "data_security_posture_management": bool(args.enable_dspm),
                "registry_scanning": bool(args.enable_registry),
                "registry_scanning_options": {"type": "ECR"},
                "serverless_scanning": bool(args.enable_serverless),
                "agentless_disk_scanning": bool(args.enable_agentless),
            },
        }

        if regions:
            request_data["scope_modifications"]["regions"] = {
                "enabled": True,
                "type": "INCLUDE",
                "regions": regions,
            }

        payload = {"request_data": request_data}

        if dry_run:
            logging.info("[DRY RUN] Would call %s payload=%s", self.create_template_endpoint, json.dumps(payload, default=str))
            return "DRY_RUN_TEMPLATE_NOT_CREATED", "", ""

        try:
            data = self._request("POST", self.create_template_endpoint, payload=payload)
            template_url = str(find_first_key(data, [
                "template_url",
                "templateUrl",
                "cloudFormationTemplateUrl",
                "cloud_formation_template_url",
                "cftUrl",
                "download_url",
                "url",
                "link",
            ]) or "")
            instance_id = str(find_first_key(data, ["instance_id", "instanceId", "id"]) or "")
            return "PENDING_TEMPLATE_DEPLOYMENT", template_url, instance_id
        except Exception as exc:
            return "FAILED", "", str(exc)



def looks_like_account_or_instance(item: Dict[str, Any]) -> bool:
    """Return True when a dict looks like a Cortex cloud account/instance object."""
    if not isinstance(item, dict):
        return False
    text = json.dumps(item, default=str).upper()
    if re.search(r"\b\d{12}\b", text):
        return True
    useful_keys = {
        "instanceid", "cloudprovider", "provider", "cloudtype",
        "accountid", "awsaccountid", "cloudaccountid",
        "status", "onboardingstatus", "connectionstatus", "state",
    }
    return bool(useful_keys.intersection({normalize_key(k) for k in item.keys()}))


def recursively_collect_dicts(data: Any) -> List[Dict[str, Any]]:
    """Collect nested dictionaries that look like Cortex cloud objects."""
    found: List[Dict[str, Any]] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            if looks_like_account_or_instance(obj):
                found.append(obj)
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)

    walk(data)
    # Deduplicate by JSON content while preserving order
    seen = set()
    unique: List[Dict[str, Any]] = []
    for item in found:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def dump_cortex_response(prefix: str, data: Any) -> None:
    """Save raw Cortex response for troubleshooting."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_prefix = re.sub(r"[^A-Za-z0-9_.-]+", "_", prefix).strip("_")
    path = f"cortex_raw_{safe_prefix}_{stamp}.json"
    with open(path, "w", encoding="utf-8") as file_handle:
        json.dump(data, file_handle, indent=2, default=str)
    logging.info("Saved raw Cortex response: %s", path)

def parse_key_value(raw: str) -> Tuple[str, str]:
    if "=" not in raw:
        raise ValueError(f"Invalid key=value value: {raw!r}")
    key, value = raw.split("=", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"Invalid key=value value: {raw!r}")
    return key, value.strip()


def parse_key_value_list(values: List[str]) -> Dict[str, str]:
    parsed = {}
    for value in values:
        key, val = parse_key_value(value)
        parsed[key] = val
    return parsed


def read_accounts_txt(path: str) -> List[AwsAccount]:
    """
    Read TXT input.

    Supports:
        123456789012
        123456789012,Production
        123456789012 Production Account
    """
    accounts: List[AwsAccount] = []
    input_path = Path(path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with input_path.open("r", encoding="utf-8") as file_handle:
        for line_number, raw in enumerate(file_handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if "," in line:
                parts = [part.strip() for part in line.split(",", maxsplit=1)]
                account_id = require_valid_aws_account_id(parts[0])
                account_name = parts[1] if len(parts) > 1 else ""
            else:
                parts = line.split(maxsplit=1)
                account_id = require_valid_aws_account_id(parts[0])
                account_name = parts[1].strip() if len(parts) > 1 else ""

            accounts.append(AwsAccount(account_id=account_id, account_name=account_name))

    return accounts


def get_aws_org_accounts(profile: Optional[str] = None, region: Optional[str] = None) -> List[AwsAccount]:
    if boto3 is None:
        raise RuntimeError("boto3 is not installed. Run: pip install boto3")

    session_kwargs: Dict[str, str] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    client = session.client("organizations")
    paginator = client.get_paginator("list_accounts")

    accounts: List[AwsAccount] = []
    for page in paginator.paginate():
        for item in page.get("Accounts", []):
            if item.get("Status") == "ACTIVE":
                accounts.append(AwsAccount(account_id=require_valid_aws_account_id(item["Id"]), account_name=item.get("Name", "")))
    return accounts


def unique_accounts(accounts: List[AwsAccount]) -> List[AwsAccount]:
    seen = set()
    output: List[AwsAccount] = []
    for account in accounts:
        if account.account_id in seen:
            continue
        seen.add(account.account_id)
        output.append(account)
    return output




def normalize_onboarding_status(status: str, error_message: str = "") -> str:
    """
    Convert Cortex-native statuses into report statuses.

    Cortex Cloud commonly returns STATUS=ENABLED for accounts that are already
    onboarded. Older report code counted only ALREADY_ONBOARDED, causing the
    summary to show 0 onboarded even when 288 rows were ENABLED.
    """
    if error_message:
        return "FAILED"

    s = str(status or "").strip().upper()

    already_values = {
        "ENABLED",
        "ACTIVE",
        "CONNECTED",
        "SUCCESS",
        "SUCCEEDED",
        "ONBOARDED",
        "ALREADY_ONBOARDED",
    }
    pending_values = {
        "PENDING",
        "PENDING_TEMPLATE_DEPLOYMENT",
        "TEMPLATE_CREATED",
        "IN_PROGRESS",
        "CREATING",
        "PROCESSING",
    }
    failed_values = {
        "FAILED",
        "ERROR",
        "DISABLED",
        "DELETED",
        "NOT_CONNECTED",
        "NOT_ONBOARDED",
    }

    if s in already_values:
        return "ALREADY_ONBOARDED"
    if s in pending_values or "PENDING" in s:
        return "PENDING"
    if s in failed_values or "FAILED" in s or "ERROR" in s:
        return "FAILED"
    if s == "MISSING":
        return "MISSING"
    if s.startswith("DRY_RUN") or "DRY_RUN" in s:
        return "DRY_RUN"
    return s or "UNKNOWN"


def report_counts(rows: List[AccountReportRow]) -> Dict[str, int]:
    """Return report summary using normalized status values."""
    total = len(rows)
    normalized = [normalize_onboarding_status(r.onboarding_status, r.error_message) for r in rows]
    return {
        "total": total,
        "already": sum(1 for s in normalized if s == "ALREADY_ONBOARDED"),
        "missing": sum(1 for s in normalized if s == "MISSING"),
        "pending": sum(1 for s in normalized if s == "PENDING"),
        "dry_run": sum(1 for s in normalized if s == "DRY_RUN"),
        "failed": sum(1 for s in normalized if s == "FAILED"),
    }

def write_html_report(rows: List[AccountReportRow], output_prefix: str) -> str:
    html_path = f"{output_prefix}.html"
    counts = report_counts(rows)
    total = counts["total"]
    already = counts["already"]
    missing = counts["missing"]
    pending = counts["pending"]
    failed = counts["failed"]

    def esc(value: Any) -> str:
        return html.escape(str(value or ""))

    table_rows = []
    for row in rows:
        normalized_status = normalize_onboarding_status(row.onboarding_status, row.error_message)
        status_class = "ok" if normalized_status == "ALREADY_ONBOARDED" else "missing" if normalized_status == "MISSING" else "pending" if normalized_status == "PENDING" else "fail" if normalized_status == "FAILED" else "neutral"
        table_rows.append(
            "<tr>"
            f"<td>{esc(row.aws_account_id)}</td>"
            f"<td>{esc(row.account_name)}</td>"
            f"<td><span class='pill {status_class}'>{esc(normalized_status)}</span>"
            f"<div class='raw'>Raw Cortex status: {esc(row.onboarding_status)}</div></td>"
            f"<td>{esc(row.validation_status)}</td>"
            f"<td>{esc(row.cortex_instance_id)}</td>"
            f"<td>{esc(row.template_url)}</td>"
            f"<td>{esc(row.error_message)}</td>"
            f"<td>{esc(row.timestamp)}</td>"
            "</tr>"
        )

    generated = utc_now()
    html_doc = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>Cortex AWS Onboarding Report</title>
  <style>
    body {{ font-family: Arial, Helvetica, sans-serif; margin: 24px; background: #f6f8fb; color: #1f2937; }}
    h1 {{ margin-bottom: 4px; }}
    .meta {{ color: #6b7280; margin-bottom: 20px; }}
    .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 22px; }}
    .card {{ background: white; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px 18px; min-width: 150px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }}
    .num {{ font-size: 28px; font-weight: 700; margin-bottom: 4px; }}
    .label {{ color: #6b7280; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #e5e7eb; }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid #e5e7eb; text-align: left; font-size: 13px; vertical-align: top; }}
    th {{ background: #111827; color: white; position: sticky; top: 0; }}
    tr:hover {{ background: #f9fafb; }}
    .pill {{ display: inline-block; padding: 3px 8px; border-radius: 999px; font-weight: 700; font-size: 12px; }}
    .ok {{ background: #dcfce7; color: #166534; }}
    .missing {{ background: #fee2e2; color: #991b1b; }}
    .pending {{ background: #fef3c7; color: #92400e; }}
    .fail {{ background: #fecaca; color: #7f1d1d; }}
    .neutral {{ background: #e5e7eb; color: #374151; }}
  </style>
</head>
<body>
  <h1>Cortex AWS Onboarding Report</h1>
  <div class=\"meta\">Generated: {esc(generated)}</div>
  <div class=\"cards\">
    <div class=\"card\"><div class=\"num\">{total}</div><div class=\"label\">Total Accounts</div></div>
    <div class=\"card\"><div class=\"num\">{already}</div><div class=\"label\">Already Onboarded</div></div>
    <div class=\"card\"><div class=\"num\">{missing}</div><div class=\"label\">Missing</div></div>
    <div class=\"card\"><div class=\"num\">{pending}</div><div class=\"label\">Pending/Templates</div></div>
    <div class=\"card\"><div class=\"num\">{failed}</div><div class=\"label\">Failed/Errors</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>AWS Account ID</th>
        <th>Account Name</th>
        <th>Onboarding Status</th>
        <th>Validation Status</th>
        <th>Cortex Instance ID</th>
        <th>Template URL</th>
        <th>Error</th>
        <th>Timestamp</th>
      </tr>
    </thead>
    <tbody>
      {''.join(table_rows)}
    </tbody>
  </table>
</body>
</html>
"""
    with open(html_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(html_doc)
    return html_path


def write_reports(rows: List[AccountReportRow], output_prefix: str) -> Tuple[str, str, str]:
    csv_path = f"{output_prefix}.csv"
    json_path = f"{output_prefix}.json"
    fieldnames = [
        "aws_account_id",
        "account_name",
        "onboarding_status",
        "validation_status",
        "template_url",
        "cortex_instance_id",
        "error_message",
        "timestamp",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))

    with open(json_path, "w", encoding="utf-8") as file_handle:
        json.dump([asdict(row) for row in rows], file_handle, indent=2)

    html_path = write_html_report(rows, output_prefix)
    return csv_path, json_path, html_path


def build_cortex_client(args: argparse.Namespace) -> CortexClient:
    base_url = args.cortex_url or os.getenv("CORTEX_API_BASE_URL")
    api_key = os.getenv("CORTEX_API_KEY")
    api_key_id = os.getenv("CORTEX_API_KEY_ID")

    missing = []
    if not base_url:
        missing.append("CORTEX_API_BASE_URL or --cortex-url")
    if not api_key:
        missing.append("CORTEX_API_KEY")
    if not api_key_id:
        missing.append("CORTEX_API_KEY_ID")
    if missing:
        raise RuntimeError("Missing required Cortex setting(s): " + ", ".join(missing))

    return CortexClient(
        base_url=base_url,
        api_key=api_key,
        api_key_id=api_key_id,
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        max_retries=args.retries,
        page_size=args.page_size,
        dump_raw=args.dump_raw,
    )


def load_source_accounts(args: argparse.Namespace) -> List[AwsAccount]:
    if args.input:
        return unique_accounts(read_accounts_txt(args.input))
    if args.source == "aws-org":
        return unique_accounts(get_aws_org_accounts(profile=args.aws_profile, region=args.aws_region))
    return []


def summarize(rows: List[AccountReportRow]) -> None:
    counts = report_counts(rows)

    print("\nSummary")
    print("-------")
    print(f"Total accounts in report: {counts['total']}")
    print(f"Already onboarded:        {counts['already']}")
    print(f"Missing:                  {counts['missing']}")
    print(f"Pending/template created: {counts['pending']}")
    print(f"Dry run:                  {counts['dry_run']}")
    print(f"Failed/errors:            {counts['failed']}")


def run_report(args: argparse.Namespace) -> List[AccountReportRow]:
    cortex = build_cortex_client(args)
    source_accounts = load_source_accounts(args)
    onboarded = cortex.list_onboarded_accounts(instance_id=args.instance_id)
    rows: List[AccountReportRow] = []

    if source_accounts:
        for account in source_accounts:
            raw = onboarded.get(account.account_id)
            if raw:
                onboarding_status = "ALREADY_ONBOARDED"
                validation_status = CortexClient._extract_status(raw)
                cortex_instance_id = CortexClient._extract_instance_id(raw) or str(raw.get("_cortex_instance_id") or "")
                account_name = account.account_name or CortexClient._extract_name(raw) or str(raw.get("_cortex_instance_name") or "")
            else:
                onboarding_status = "MISSING"
                validation_status = "NOT_ONBOARDED"
                cortex_instance_id = ""
                account_name = account.account_name
            rows.append(AccountReportRow(account.account_id, account_name, onboarding_status, validation_status, "", cortex_instance_id, "", utc_now()))
    else:
        for account_id, raw in onboarded.items():
            raw_status = CortexClient._extract_status(raw)
            rows.append(
                AccountReportRow(
                    account_id,
                    CortexClient._extract_name(raw),
                    normalize_onboarding_status(raw_status),
                    raw_status if raw_status else ("ENABLED" if normalize_onboarding_status(raw_status) == "ALREADY_ONBOARDED" else "NOT_VALIDATED"),
                    "",
                    CortexClient._extract_instance_id(raw) or str(raw.get("_cortex_instance_id") or ""),
                    "",
                    utc_now(),
                )
            )
    return rows


def run_onboard(args: argparse.Namespace) -> List[AccountReportRow]:
    cortex = build_cortex_client(args)
    accounts = load_source_accounts(args)
    if not accounts:
        raise RuntimeError("Onboard mode requires --input accounts.txt or --source aws-org.")
    if args.count:
        accounts = accounts[: args.count]

    onboarded = cortex.list_onboarded_accounts(instance_id=args.instance_id)
    rows: List[AccountReportRow] = []

    for account in accounts:
        logging.info("Processing AWS account %s %s", account.account_id, account.account_name)
        if account.account_id in onboarded and not args.force:
            rows.append(AccountReportRow(account.account_id, account.account_name, "ALREADY_ONBOARDED", CortexClient._extract_status(onboarded[account.account_id]), "", CortexClient._extract_instance_id(onboarded[account.account_id]), "", utc_now()))
            continue

        status, template_url, instance_or_error = cortex.create_aws_instance_template(account, args=args, dry_run=args.dry_run)
        error = instance_or_error if status == "FAILED" else ""
        instance_id = "" if status == "FAILED" else instance_or_error

        if args.delay > 0:
            time.sleep(args.delay)

        rows.append(AccountReportRow(account.account_id, account.account_name, status, "TEMPLATE_CREATED_NOT_DEPLOYED" if "PENDING" in status else "NOT_VALIDATED", template_url, instance_id, error, utc_now()))

    return rows


def run_validate(args: argparse.Namespace) -> List[AccountReportRow]:
    cortex = build_cortex_client(args)
    accounts = load_source_accounts(args)
    onboarded = cortex.list_onboarded_accounts(instance_id=args.instance_id)

    if not accounts:
        accounts = [AwsAccount(account_id=account_id, account_name=CortexClient._extract_name(raw)) for account_id, raw in onboarded.items()]
    if args.count:
        accounts = accounts[: args.count]

    rows: List[AccountReportRow] = []
    for account in accounts:
        if account.account_id in onboarded:
            rows.append(AccountReportRow(account.account_id, account.account_name or CortexClient._extract_name(onboarded[account.account_id]), "VALIDATION_ONLY", CortexClient._extract_status(onboarded[account.account_id]), "", CortexClient._extract_instance_id(onboarded[account.account_id]), "", utc_now()))
        else:
            rows.append(AccountReportRow(account.account_id, account.account_name, "VALIDATION_ONLY", "NOT_ONBOARDED", "", "", "", utc_now()))
    return rows


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cortex Cloud AWS onboarding automation using official cloud onboarding APIs")

    parser.add_argument("--mode", choices=["report", "onboard", "validate"], required=True)
    parser.add_argument("--source", choices=["aws-org"], default=None)
    parser.add_argument("--input", help="TXT file with AWS account IDs.")
    parser.add_argument("--count", type=int, help="Limit number of accounts processed.")
    parser.add_argument("--output-prefix", default=f"cortex_aws_onboarding_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    parser.add_argument("--cortex-url", help="Cortex API base URL. Can also use CORTEX_API_BASE_URL.")
    parser.add_argument("--instance-id", help="Optional Cortex Cloud onboarding instance ID for get_accounts.")

    parser.add_argument("--aws-profile", help="Optional AWS profile name for --source aws-org.")
    parser.add_argument("--aws-region", default="us-east-1", help="AWS region for boto3 session. Default: us-east-1.")

    parser.add_argument("--scope", default="ORGANIZATION", choices=["ORGANIZATION", "ACCOUNT"], help="Cortex onboarding scope.")
    parser.add_argument("--scan-mode", default="MANAGED", choices=["MANAGED", "MONITOR"], help="Cortex scan mode.")
    parser.add_argument("--regions", help="Comma-separated AWS regions to include. If omitted, regions scope is not sent.")
    parser.add_argument("--resource-tag", action="append", default=[], help="Custom resource tag key=value. Can be repeated.")

    parser.add_argument("--enable-audit-logs", action="store_true")
    parser.add_argument("--enable-agentless", action="store_true")
    parser.add_argument("--enable-serverless", action="store_true")
    parser.add_argument("--enable-registry", action="store_true")
    parser.add_argument("--enable-dspm", action="store_true")
    parser.add_argument("--enable-xsiam-analytics", action="store_true")

    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between account operations.")

    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true", help="Create template even if account appears already onboarded.")
    parser.add_argument("--validate-report", action="store_true")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification. Avoid except for lab testing.")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--dump-raw", action="store_true", help="Save raw Cortex API responses for troubleshooting.")

    args = parser.parse_args(argv)
    args.resource_tags = parse_key_value_list(args.resource_tag)

    if args.page_size < 1 or args.page_size > 500:
        raise SystemExit("--page-size must be between 1 and 500")

    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    try:
        if args.mode == "report":
            rows = run_report(args)
        elif args.mode == "onboard":
            rows = run_onboard(args)
        elif args.mode == "validate":
            rows = run_validate(args)
        else:
            raise RuntimeError(f"Unsupported mode: {args.mode}")

        csv_path, json_path, html_path = write_reports(rows, args.output_prefix)
        summarize(rows)
        print("\nReports created:")
        print(f"  CSV:  {csv_path}")
        print(f"  JSON: {json_path}")
        print(f"  HTML: {html_path}")
        return 0
    except Exception as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
