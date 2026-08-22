from app.runtimedefender.responder_install_script import build_responder_install_script


def test_build_responder_install_script_is_a_valid_looking_bash_script():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert "kubectl apply -f -" in script


def test_build_responder_install_script_embeds_the_install_token_in_a_secret():
    script = build_responder_install_script("c1", "my-cluster", "super-secret-token", "http://localhost:8000")
    assert 'token: "super-secret-token"' in script


def test_build_responder_install_script_embeds_the_cluster_id_and_backend_url():
    script = build_responder_install_script("cluster-42", "n", "t", "https://golem.example.com")
    assert 'value: "cluster-42"' in script
    assert 'value: "https://golem.example.com"' in script


def test_build_responder_install_script_includes_the_cluster_name():
    script = build_responder_install_script("c", "production-eks", "t", "http://localhost:8000")
    assert "production-eks" in script


def test_build_responder_install_script_scopes_rbac_to_pods_and_networkpolicies_only():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert 'resources: ["pods"]' in script
    assert 'resources: ["networkpolicies"]' in script
    # Nothing else -- the RBAC grant is exactly these two resource kinds.
    assert script.count("resources:") == 2


def test_build_responder_install_script_uses_a_cluster_role_not_a_namespaced_role():
    # A namespaced Role can't reach pods/networkpolicies in other
    # namespaces, and the pod a containment command names can be anywhere.
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "kind: ClusterRole" in script
    assert "kind: ClusterRoleBinding" in script


def test_build_responder_install_script_polls_the_commands_endpoint_scoped_to_its_own_cluster():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/commands" in script
