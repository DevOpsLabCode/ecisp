"""
Static metadata describing each provider's authentication modes and scope
options, mirroring EnterpriseCloudDiscovery/core/cli_parser.py.

This drives the dynamic scan form in the frontend and is validated again
server-side in jobs.py before a scan is ever launched.
"""

FIELD_TEXT = "text"
# Form-field type constant, not a credential.
FIELD_PASSWORD = "password"  # nosec B105
FIELD_BOOL = "bool"
FIELD_MULTI = "multi"  # space-separated list of strings
FIELD_SELECT = "select"

PROVIDERS = {
    "aws": {
        "label": "Amazon Web Services",
        "authMethods": {
            "profile": {
                "label": "Named profile",
                "fields": [
                    {"name": "profile", "label": "Profile name", "type": FIELD_TEXT, "required": True},
                ],
            },
            "access_keys": {
                "label": "Access keys",
                "fields": [
                    {"name": "aws_access_key_id", "label": "Access Key ID", "type": FIELD_TEXT, "required": True},
                    {"name": "aws_secret_access_key", "label": "Secret Access Key", "type": FIELD_PASSWORD,
                     "required": True},
                    {"name": "aws_session_token", "label": "Session Token", "type": FIELD_PASSWORD, "required": False},
                ],
            },
        },
        "scopeFields": [
            {"name": "regions", "label": "Regions", "type": FIELD_MULTI, "help": "Defaults to all regions"},
            {"name": "excluded_regions", "label": "Exclude regions", "type": FIELD_MULTI},
        ],
    },
    "azure": {
        "label": "Microsoft Azure",
        "authMethods": {
            "cli": {"label": "Azure CLI (az login)", "fields": []},
            "user_account": {
                "label": "User account",
                "fields": [
                    {"name": "tenant_id", "label": "Tenant ID", "type": FIELD_TEXT, "required": True},
                    {"name": "username", "label": "Username", "type": FIELD_TEXT, "required": False},
                    {"name": "password", "label": "Password", "type": FIELD_PASSWORD, "required": False},
                ],
            },
            "user_account_browser": {
                "label": "User account (browser, for MFA)",
                "fields": [
                    {"name": "tenant_id", "label": "Tenant ID", "type": FIELD_TEXT, "required": True},
                ],
            },
            "service_principal": {
                "label": "Service principal",
                "fields": [
                    {"name": "tenant_id", "label": "Tenant ID", "type": FIELD_TEXT, "required": True},
                    {"name": "client_id", "label": "Client ID", "type": FIELD_TEXT, "required": True},
                    {"name": "client_secret", "label": "Client Secret", "type": FIELD_PASSWORD, "required": True},
                ],
            },
            "msi": {"label": "Managed Service Identity", "fields": []},
        },
        "scopeFields": [
            {"name": "subscription_ids", "label": "Subscription IDs", "type": FIELD_MULTI,
             "help": "Leave blank to use the default subscription"},
            {"name": "all_subscriptions", "label": "All accessible subscriptions", "type": FIELD_BOOL},
        ],
    },
    "gcp": {
        "label": "Google Cloud Platform",
        "authMethods": {
            "user_account": {"label": "User account", "fields": []},
            "service_account": {
                "label": "Service account key file",
                "fields": [
                    {"name": "service_account", "label": "Key file path", "type": FIELD_TEXT, "required": True,
                     "help": "Path on the server running this backend, e.g. ./credentials/gcp-audit.json"},
                ],
            },
        },
        "scopeFields": [
            {"name": "project_id", "label": "Project ID", "type": FIELD_TEXT},
            {"name": "folder_id", "label": "Folder ID", "type": FIELD_TEXT},
            {"name": "organization_id", "label": "Organization ID", "type": FIELD_TEXT},
            {"name": "all_projects", "label": "All accessible projects", "type": FIELD_BOOL},
        ],
    },
    "aliyun": {
        "label": "Alibaba Cloud",
        "authMethods": {
            "access_keys": {
                "label": "Access keys",
                "fields": [
                    {"name": "access_key_id", "label": "Access Key ID", "type": FIELD_TEXT, "required": True},
                    {"name": "access_key_secret", "label": "Access Key Secret", "type": FIELD_PASSWORD,
                     "required": True},
                ],
            },
        },
        "scopeFields": [],
    },
    "oci": {
        "label": "Oracle Cloud Infrastructure",
        "authMethods": {
            "profile": {
                "label": "Named profile",
                "fields": [
                    {"name": "profile", "label": "Profile name", "type": FIELD_TEXT, "required": True},
                ],
            },
        },
        "scopeFields": [],
    },
    "do": {
        "label": "DigitalOcean",
        "authMethods": {
            "token": {
                "label": "API token",
                "fields": [
                    {"name": "token", "label": "DO Token", "type": FIELD_PASSWORD, "required": True},
                    {"name": "access_key", "label": "Spaces Access Key (optional)", "type": FIELD_TEXT,
                     "required": False},
                    {"name": "access_secret", "label": "Spaces Secret Key (optional)", "type": FIELD_PASSWORD,
                     "required": False, "help": "Both Spaces fields are required together if either is set"},
                ],
            },
        },
        "scopeFields": [],
    },
    "kubernetes": {
        "label": "Kubernetes",
        "authMethods": {
            "kubeconfig": {
                "label": "kubeconfig",
                "fields": [
                    {"name": "kubernetes_config_file", "label": "kubeconfig path", "type": FIELD_TEXT,
                     "required": False, "help": "Defaults to Kubernetes' default config location"},
                    {"name": "kubernetes_context", "label": "Context", "type": FIELD_TEXT, "required": False},
                    {"name": "kubernetes_cluster_provider", "label": "Managed cluster provider", "type": FIELD_SELECT,
                     "options": ["", "aks", "eks", "gke"], "required": False},
                    {"name": "kubernetes_azure_subscription_id", "label": "AKS subscription ID", "type": FIELD_TEXT,
                     "required": False, "help": "Only used when the managed cluster provider is aks"},
                ],
            },
        },
        "scopeFields": [],
    },
}


def list_providers():
    return [
        {"code": code, "label": meta["label"], "authMethods": meta["authMethods"], "scopeFields": meta["scopeFields"]}
        for code, meta in PROVIDERS.items()
    ]
