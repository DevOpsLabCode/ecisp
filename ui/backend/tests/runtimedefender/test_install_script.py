from app.runtimedefender.install_script import build_install_script


def test_build_install_script_embeds_the_webhook_url_with_token():
    script = build_install_script("cluster-1", "my-cluster", "secret-token", "http://localhost:8000")
    assert "http://localhost:8000/api/runtime-clusters/cluster-1/events?token=secret-token" in script


def test_build_install_script_uses_modern_ebpf_driver():
    script = build_install_script("c", "n", "t", "http://localhost:8000")
    assert "driver.kind=modern_ebpf" in script


def test_build_install_script_is_a_valid_looking_bash_script():
    script = build_install_script("c", "n", "t", "http://localhost:8000")
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert "helm upgrade --install falco falcosecurity/falco" in script


def test_build_install_script_includes_the_cluster_name():
    script = build_install_script("c", "production-eks", "t", "http://localhost:8000")
    assert "production-eks" in script
