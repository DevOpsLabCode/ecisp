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


def test_build_responder_install_script_cluster_role_covers_four_resource_kinds():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    cluster_role = script[script.index("kind: ClusterRole\n") : script.index("kind: ClusterRoleBinding\n")]
    assert 'resources: ["pods"]' in cluster_role
    assert 'resources: ["nodes"]' in cluster_role
    assert 'resources: ["serviceaccounts"]' in cluster_role
    assert 'resources: ["networkpolicies"]' in cluster_role
    # Nothing else in the ClusterRole -- the canary's extra pods/pods-exec
    # verbs live in a separate, namespaced Role instead (see the
    # canary_rbac_is_namespaced test below), deliberately not added here.
    assert cluster_role.count("resources:") == 4


def test_build_responder_install_script_uses_a_cluster_role_not_a_namespaced_role():
    # A namespaced Role can't reach pods/networkpolicies in other
    # namespaces, and the pod a containment command names can be anywhere.
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "kind: ClusterRole" in script
    assert "kind: ClusterRoleBinding" in script


def test_build_responder_install_script_polls_the_commands_endpoint_scoped_to_its_own_cluster():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/commands" in script


def test_build_responder_install_script_pods_rbac_includes_delete_for_kill_process():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert 'verbs: ["get", "list", "patch", "delete"]' in script


def test_build_responder_install_script_handles_kill_process_via_kubectl_delete_pod():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert '"${action}" = "kill_process"' in script
    assert "kubectl delete pod" in script
    assert "--grace-period=0 --force" in script


def test_build_responder_install_script_nodes_rbac_is_get_and_patch_only():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert 'resources: ["nodes"]\n    verbs: ["get", "patch"]' in script


def test_build_responder_install_script_handles_quarantine_node_via_cordon_taint_and_delete():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert '"${action}" = "quarantine_node"' in script
    assert "kubectl cordon" in script
    assert "kubectl taint nodes" in script
    assert "NoSchedule" in script


def test_build_responder_install_script_quarantine_node_never_uses_no_execute():
    # A NoExecute taint would evict every other pod already on the node,
    # not just the one Falco flagged -- see the module docstring.
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "NoExecute" not in script


def test_build_responder_install_script_serviceaccounts_rbac_is_read_only():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert 'resources: ["serviceaccounts"]\n    verbs: ["get"]' in script


def test_build_responder_install_script_resolves_revoke_iam_role_via_serviceaccount_annotation():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert '"${action}" = "revoke_iam"' in script
    assert "spec.serviceAccountName" in script
    assert "eks\\.amazonaws\\.com/role-arn" in script


def test_build_responder_install_script_posts_the_resolved_role_arn_to_resolve_role():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/commands/${id}/resolve-role" in script


def test_build_responder_install_script_never_calls_aws_apis_directly():
    # The in-cluster responder only ever resolves a role ARN via
    # Kubernetes reads -- it must never itself hold or use AWS
    # credentials. A crude but meaningful guardrail: no AWS SDK/CLI
    # invocation anywhere in the generated script.
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "aws " not in script
    assert "boto3" not in script
    assert "sts:" not in script
    assert "iam:" not in script


# ---- coverage: daily NetworkPolicy-enforcement canary (Phase 2) -----------


def test_build_responder_install_script_installs_a_daily_cronjob():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "kind: CronJob" in script
    assert 'schedule: "0 3 * * *"' in script
    assert "concurrencyPolicy: Forbid" in script


def test_build_responder_install_script_canary_creates_two_pods_and_a_deny_all_policy():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "golem-canary-victim-" in script
    assert "golem-canary-prober-" in script
    assert "kubectl run" in script
    assert "golem-io/canary" in script
    assert "policyTypes" in script


def test_build_responder_install_script_canary_probes_before_and_after_the_policy():
    # The pre-policy probe is what stops a broken base network from being
    # misreported as "enforcement verified".
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert script.count("probe") >= 3  # definition + pre-check call + post-policy call


def test_build_responder_install_script_canary_reports_to_the_coverage_endpoint():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/coverage/network-policy" in script


def test_build_responder_install_script_canary_cleanup_uses_a_trap():
    # Cleanup must run whether the test passes, fails, or errors out
    # partway through -- a plain end-of-script call wouldn't survive an
    # early `exit 0` on a failed pre-check.
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "trap cleanup EXIT" in script


def test_build_responder_install_script_canary_rbac_is_namespaced_not_cluster_wide():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert "kind: Role\n" in script
    assert "kind: RoleBinding\n" in script
    assert 'resources: ["pods/exec"]' in script


def test_build_responder_install_script_canary_role_grants_create_and_exec():
    script = build_responder_install_script("c", "n", "t", "http://localhost:8000")
    assert 'verbs: ["create", "get", "list", "delete"]' in script
    assert 'resources: ["pods/exec"]\n    verbs: ["create"]' in script
