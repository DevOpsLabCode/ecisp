from app.runtimedefender.attack_simulation_script import build_simulation_script


def test_build_simulation_script_uses_the_real_event_generator_image():
    script = build_simulation_script("prod-eks")
    assert "--image=falcosecurity/event-generator:latest" in script


def test_build_simulation_script_is_a_valid_looking_bash_script():
    script = build_simulation_script("prod-eks")
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert 'kubectl run "$POD_NAME"' in script


def test_build_simulation_script_includes_the_cluster_name():
    script = build_simulation_script("production-eks")
    assert "production-eks" in script


def test_build_simulation_script_cleans_up_after_itself():
    script = build_simulation_script("prod-eks")
    assert "--rm" in script


def test_build_simulation_script_embeds_no_install_token():
    # Unlike install_script.py, this script never talks to Golem directly --
    # it only triggers syscalls the already-deployed Falco sensor observes.
    script = build_simulation_script("prod-eks")
    assert "token" not in script.lower()
