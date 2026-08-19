from app.providers_meta import PROVIDERS, list_providers

EXPECTED_PROVIDER_CODES = {"aws", "azure", "gcp", "aliyun", "oci", "do", "kubernetes"}


def test_list_providers_returns_all_known_providers():
    result = list_providers()
    codes = {p["code"] for p in result}
    assert codes == EXPECTED_PROVIDER_CODES


def test_list_providers_shape():
    result = list_providers()
    for entry in result:
        assert set(entry.keys()) == {"code", "label", "authMethods", "scopeFields"}
        assert isinstance(entry["label"], str) and entry["label"]
        assert isinstance(entry["authMethods"], dict) and entry["authMethods"]
        assert isinstance(entry["scopeFields"], list)


def test_every_auth_method_has_fields_list():
    for provider_code, meta in PROVIDERS.items():
        for method_name, method_meta in meta["authMethods"].items():
            assert "label" in method_meta, f"{provider_code}/{method_name} missing label"
            assert "fields" in method_meta, f"{provider_code}/{method_name} missing fields"
            for field in method_meta["fields"]:
                assert "name" in field
                assert "label" in field
                assert "type" in field


def test_aws_has_profile_and_access_key_auth_methods():
    aws = PROVIDERS["aws"]
    assert set(aws["authMethods"]) == {"profile", "access_keys"}
    profile_fields = {f["name"] for f in aws["authMethods"]["profile"]["fields"]}
    assert profile_fields == {"profile"}
    access_key_fields = {f["name"] for f in aws["authMethods"]["access_keys"]["fields"]}
    assert access_key_fields == {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}


def test_kubernetes_cluster_provider_field_has_select_options():
    k8s = PROVIDERS["kubernetes"]
    fields = k8s["authMethods"]["kubeconfig"]["fields"]
    cluster_field = next(f for f in fields if f["name"] == "kubernetes_cluster_provider")
    assert cluster_field["type"] == "select"
    assert cluster_field["options"] == ["", "aks", "eks", "gke"]
