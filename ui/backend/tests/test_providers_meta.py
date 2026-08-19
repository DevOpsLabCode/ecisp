from app.providers_meta import PROVIDERS, all_field_names, auth_field_names, list_providers, scope_field_names

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


class TestAuthFieldNames:
    def test_returns_field_names_for_known_provider_and_method(self):
        assert auth_field_names("aws", "profile") == {"profile"}

    def test_empty_set_for_unknown_provider(self):
        assert auth_field_names("not-a-provider", "profile") == set()

    def test_empty_set_for_unknown_method(self):
        assert auth_field_names("aws", "not-a-method") == set()

    def test_empty_set_for_method_with_no_fields(self):
        assert auth_field_names("azure", "cli") == set()


class TestScopeFieldNames:
    def test_returns_scope_field_names_for_known_provider(self):
        assert scope_field_names("aws") == {"regions", "excluded_regions"}

    def test_empty_set_for_unknown_provider(self):
        assert scope_field_names("not-a-provider") == set()

    def test_empty_set_for_provider_with_no_scope_fields(self):
        assert scope_field_names("aliyun") == set()


def test_all_field_names_is_sorted_and_covers_every_provider():
    names = all_field_names()
    assert names == sorted(names)
    assert "profile" in names  # aws/oci
    assert "tenant_id" in names  # azure
    assert "organization_id" in names  # gcp
    assert "access_key_id" in names  # aliyun
    assert "token" in names  # digitalocean
    assert "kubernetes_context" in names  # kubernetes
