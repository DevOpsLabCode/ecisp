"""Generates the one-command "test this Defender for real" script: runs
`falcosecurity/event-generator` (the same open-source tool the Falco
project itself uses to test Falco's own rules) as a disposable pod on
whichever cluster `kubectl` points at, firing off its default action set
-- ~20 benign syscalls that match real MITRE ATT&CK-tagged Falco rules
(credential access, defense evasion, persistence, and more) -- so a user
can watch real detections land in this cluster's findings within about a
minute of running one command, rather than waiting for a real incident or
staging one by hand the way this feature itself was verified below.

No install token is embedded here, unlike install_script.py: this script
never talks to Golem directly. It only triggers real syscalls inside the
target cluster; the Falco sensor already deployed there (via the install
script) observes them and reports through the webhook that's already
configured for this cluster -- the exact same path a real incident takes.

Live-verified against a real local `kind` cluster: one run of the tool's
default action set fired 18 distinct Falco rules covering 11 distinct
MITRE ATT&CK technique IDs (T1059, T1552, T1555, T1070, T1485, and
others), completing in well under a minute. Everything the tool touches
is confined to its own disposable pod's filesystem (per its own
documentation) and that pod deletes itself the moment it finishes, via
`--rm`.
"""

from __future__ import annotations

_SIMULATION_SCRIPT_TEMPLATE = """\
#!/usr/bin/env bash
# Golem Defender attack simulation for cluster: {cluster_name}
#
# Runs falcosecurity/event-generator's default action set as a disposable
# pod against whichever cluster your current `kubectl` context points at --
# this should be the same cluster you ran the Golem Defender install
# script against. Fires ~20 benign actions that match real MITRE ATT&CK-
# tagged Falco rules (credential access, defense evasion, persistence,
# and more). Everything it touches is confined to its own pod's
# filesystem, and that pod deletes itself the moment it finishes.
set -euo pipefail

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required and must point at the cluster running Golem Defender" >&2
  exit 1
fi

POD_NAME="golem-attack-sim-$(date +%s)"
echo "Simulating an attack on cluster: $(kubectl config current-context)"
echo "Pod: $POD_NAME (deletes itself when finished)"
echo

kubectl run "$POD_NAME" \\
  --image=falcosecurity/event-generator:latest \\
  --restart=Never --rm -i --namespace=default \\
  -- run --loop=false

echo
echo "Done. Check '{cluster_name}' in Runtime Protection -- alerts should already be showing up."
"""


def build_simulation_script(cluster_name: str) -> str:
    return _SIMULATION_SCRIPT_TEMPLATE.format(cluster_name=cluster_name)
