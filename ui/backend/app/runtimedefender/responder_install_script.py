"""Generates the one-command install script for the Phase 1 in-cluster
responder: a small poll loop that asks Golem for pending containment
commands scoped to this one cluster, and acts on them -- isolate_network
applies/reverses a NetworkPolicy, kill_process deletes the offending pod
outright, quarantine_node cordons and taints the node the pod is running
on before deleting the pod. See the containment build plan for why this
is pull-based (the responder reaches out to the backend, never the other
way around) and why its Kubernetes RBAC is the narrowest grant that can
do the job.

**Why kill_process is `kubectl delete pod`, not a real eBPF process kill**:
the plan's original design leaned toward Tetragon, but Tetragon's
TracingPolicy CRDs are declarative cluster-wide rules ("always kill any
process matching X"), not an imperative "kill this one already-detected
process now" API -- fitting it into this command-queue architecture would
mean generating and applying a fresh TracingPolicy per incident, a far
less proven pattern than NetworkPolicy-per-pod. Deleting the whole pod is
coarser (it takes every container in the pod down, not one surgical
process), but reuses the exact same responder this file already has, and
in practice most workloads are one-process-per-container anyway.

**Why quarantine_node cordons (not taints `NoExecute`) and only evicts the
one named pod**: a `NoExecute` taint evicts *every* pod already running on
that node, not just the one Falco flagged -- a much larger blast radius
than the finding justifies on a shared, multi-tenant node. `cordon` (plus
a `NoSchedule` taint, kept mainly for an auditable record of *why* the
node is cordoned) only stops *new* pods from landing there; the flagged
pod itself is removed with the same direct delete kill_process already
uses, not the Eviction API -- an actively compromised workload shouldn't
wait on PodDisruptionBudget negotiation the way a routine maintenance
drain should.

Deliberately no custom container image to build or publish -- `alpine/k8s`
already bundles `kubectl`, `curl`, and `jq`, the only three tools the poll
loop needs, the same "reuse what already exists" choice `install_script.py`
makes with Falco's own Helm chart.

**Why a ClusterRole, not a namespaced Role**: the pod a containment command
names can be in any namespace on the cluster (wherever the workload that
tripped the Falco rule happens to run), not just the responder's own
namespace -- a namespaced Role can't reach across namespaces at all, so the
RBAC has to be cluster-scoped even though it's still as narrow as possible
on verbs: `get`/`list`/`patch`/`delete` on pods (patch to attach the
one-off isolation label a NetworkPolicy's `podSelector` needs -- Kubernetes
has no way to select a NetworkPolicy target by pod name directly; delete
for kill_process and quarantine_node), `get`/`patch` on nodes (cordon and
taint, quarantine_node only -- nodes are cluster-scoped resources, so this
can't be narrowed to a namespace even in principle), and
`get`/`list`/`create`/`patch`/`delete` on networkpolicies. No access to any
other resource kind, and nothing enqueues a command in the first place
unless an operator has explicitly opted a Falco rule into that specific
action (see `containment_store.upsert_response_rule`).

**Why token substitution instead of `.format()`**: unlike
`install_script.py`'s template, this one is mostly shell (`${VAR}`
parameter expansion) and JSON/YAML (`{...}`) -- both use literal braces
throughout, which `.format()` would try to interpret as fields unless every
one were escaped as `{{`/`}}`. Plain token replacement sidesteps that
entirely; the tokens themselves (`__GOLEM_..._TOKEN__`) are chosen to be
things that could never legitimately appear in a cluster name or install
token.
"""

from __future__ import annotations

_RESPONDER_MANIFEST_TEMPLATE = """\
#!/usr/bin/env bash
# Golem Defender responder install script for cluster: __GOLEM_CLUSTER_NAME_TOKEN__
#
# Deploys the Phase 1 in-cluster responder: a poll loop that asks Golem for
# pending containment commands scoped to this cluster only, and applies or
# reverses a NetworkPolicy in response. Requires Runtime Defender (the
# Falco sensor) already installed -- this only acts on findings it detects.
# An operator must also explicitly opt individual Falco rules into a
# response (see the dashboard's Response Rules page) before this ever does
# anything beyond poll; an unmapped rule still only alerts, exactly as
# before.
set -euo pipefail

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required and must point at the target cluster" >&2
  exit 1
fi

echo "Installing the containment responder onto cluster: $(kubectl config current-context)"

cat <<'GOLEM_RESPONDER_MANIFEST' | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: golem-responder
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: golem-responder
  namespace: golem-responder
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: golem-responder
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "patch", "delete"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "patch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "create", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: golem-responder
subjects:
  - kind: ServiceAccount
    name: golem-responder
    namespace: golem-responder
roleRef:
  kind: ClusterRole
  name: golem-responder
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Secret
metadata:
  name: golem-responder-credentials
  namespace: golem-responder
type: Opaque
stringData:
  token: "__GOLEM_INSTALL_TOKEN_TOKEN__"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: golem-responder
  namespace: golem-responder
spec:
  replicas: 1
  selector:
    matchLabels:
      app: golem-responder
  template:
    metadata:
      labels:
        app: golem-responder
    spec:
      serviceAccountName: golem-responder
      containers:
        - name: responder
          image: alpine/k8s:1.30.4
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          env:
            - name: CLUSTER_ID
              value: "__GOLEM_CLUSTER_ID_TOKEN__"
            - name: CLUSTER_NAME
              value: "__GOLEM_CLUSTER_NAME_TOKEN__"
            - name: BACKEND_URL
              value: "__GOLEM_BACKEND_URL_TOKEN__"
            - name: TOKEN
              valueFrom:
                secretKeyRef:
                  name: golem-responder-credentials
                  key: token
            - name: POLL_INTERVAL_SECONDS
              value: "5"
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -eu
              echo "Golem Defender responder starting for cluster ${CLUSTER_NAME} (${CLUSTER_ID})"

              report_status() {
                curl -sf -X POST -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \\
                  -d "{\\"status\\": \\"${1}\\"}" \\
                  "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/commands/${2}/status" >/dev/null 2>&1 || true
              }

              while true; do
                commands=$(curl -sf -H "Authorization: Bearer ${TOKEN}" \\
                  "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/commands" || echo '[]')

                echo "${commands}" | jq -c '.[]' 2>/dev/null | while IFS= read -r cmd; do
                  id=$(echo "${cmd}" | jq -r '.id')
                  status=$(echo "${cmd}" | jq -r '.status')
                  action=$(echo "${cmd}" | jq -r '.action')
                  ns=$(echo "${cmd}" | jq -r '.namespace')
                  pod=$(echo "${cmd}" | jq -r '.pod_name')

                  if [ "${status}" = "pending" ] && [ "${action}" = "isolate_network" ]; then
                    netpol_p1="{\\"apiVersion\\":\\"networking.k8s.io/v1\\",\\"kind\\":\\"NetworkPolicy\\",\\"metadata\\":{\\"na"
                    netpol_p2="me\\":\\"golem-isolate-${id}\\",\\"namespace\\":\\"${ns}\\",\\"labels\\":{\\"golem.io/managed-by"
                    netpol_p3="\\":\\"golem-defender-responder\\"}},\\"spec\\":{\\"podSelector\\":{\\"matchLabels\\":{\\"golem-"
                    netpol_p4="io/isolated\\":\\"${id}\\"}},\\"policyTypes\\":[\\"Ingress\\",\\"Egress\\"],\\"ingress\\":[],\\"eg"
                    netpol_p5="ress\\":[]}}"
                    netpol_json="${netpol_p1}${netpol_p2}${netpol_p3}${netpol_p4}${netpol_p5}"
                    if kubectl label pod "${pod}" -n "${ns}" "golem-io/isolated=${id}" --overwrite >/dev/null 2>&1 \\
                      && echo "${netpol_json}" | kubectl apply -f - >/dev/null 2>&1; then
                      report_status "applied" "${id}"
                    else
                      report_status "failed" "${id}"
                    fi

                  elif [ "${status}" = "pending" ] && [ "${action}" = "kill_process" ]; then
                    if kubectl delete pod "${pod}" -n "${ns}" --grace-period=0 --force >/dev/null 2>&1; then
                      report_status "applied" "${id}"
                    else
                      report_status "failed" "${id}"
                    fi

                  elif [ "${status}" = "pending" ] && [ "${action}" = "quarantine_node" ]; then
                    node=$(kubectl get pod "${pod}" -n "${ns}" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)
                    if [ -n "${node}" ] \\
                      && kubectl cordon "${node}" >/dev/null 2>&1 \\
                      && kubectl taint nodes "${node}" "golem.io/quarantined=${id}:NoSchedule" \\
                        --overwrite >/dev/null 2>&1 \\
                      && kubectl delete pod "${pod}" -n "${ns}" --grace-period=0 --force >/dev/null 2>&1; then
                      report_status "applied" "${id}"
                    else
                      report_status "failed" "${id}"
                    fi

                  elif [ "${status}" = "release_pending" ]; then
                    kubectl delete networkpolicy "golem-isolate-${id}" -n "${ns}" --ignore-not-found \\
                      >/dev/null 2>&1 || true
                    kubectl label pod "${pod}" -n "${ns}" "golem-io/isolated-" >/dev/null 2>&1 || true
                    report_status "released" "${id}"
                  fi
                done

                sleep "${POLL_INTERVAL_SECONDS:-5}"
              done
GOLEM_RESPONDER_MANIFEST

echo
echo "Done. The containment responder is now polling for cluster: __GOLEM_CLUSTER_NAME_TOKEN__"
echo "It only acts on Falco rules an operator has explicitly opted into a response --"
echo "see the dashboard's Response Rules page to map one."
"""


def build_responder_install_script(cluster_id: str, cluster_name: str, install_token: str, backend_url: str) -> str:
    return (
        _RESPONDER_MANIFEST_TEMPLATE.replace("__GOLEM_CLUSTER_ID_TOKEN__", cluster_id)
        .replace("__GOLEM_CLUSTER_NAME_TOKEN__", cluster_name)
        .replace("__GOLEM_INSTALL_TOKEN_TOKEN__", install_token)
        .replace("__GOLEM_BACKEND_URL_TOKEN__", backend_url)
    )
