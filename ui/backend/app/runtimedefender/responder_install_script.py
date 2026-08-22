"""Generates the one-command install script for the Phase 1 in-cluster
responder: a small poll loop that asks Golem for pending containment
commands scoped to this one cluster, and acts on them -- isolate_network
applies/reverses a NetworkPolicy, kill_process deletes the offending pod
outright, quarantine_node cordons and taints the node the pod is running
on before deleting the pod, and revoke_iam (Tier 4) is only ever
*resolved* here, never applied -- see below. See the containment build
plan for why this is pull-based (the responder reaches out to the
backend, never the other way around) and why its Kubernetes RBAC is the
narrowest grant that can do the job.

**revoke_iam's role in this file stops at resolution**: the in-cluster
responder reads the target pod's `spec.serviceAccountName` (defaulting to
"default" if unset) and that ServiceAccount's
`eks.amazonaws.com/role-arn` annotation -- both plain Kubernetes reads,
needing nothing beyond the `get` this file's RBAC already grants on pods,
now extended to `serviceaccounts` too -- then hands the resolved ARN to
the backend via `resolve-role`. It never calls AWS, never holds an AWS
credential, and never sees whether the actual revocation succeeds; the
separate IAM-revocation component (`iam-responder/`, a different process
with its own AWS credentials and zero Kubernetes access) does that part.
If no IRSA role annotation is found, `revoke_iam` fails once and stays
failed -- unlike quarantine_node, that's not a transient condition worth
retrying, it means the workload isn't using IRSA at all.

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

**The daily canary CronJob (Phase 2, coverage)**: also installed here,
because it's what keeps "isolate_network is configured" and
"isolate_network actually isolates anything" from silently diverging --
on EKS, the default VPC CNI does not enforce Kubernetes NetworkPolicy at
all unless explicitly turned on, so an isolation command can apply
cleanly and do nothing. Once a day it creates two throwaway pods in its
own `golem-responder` namespace (never a customer namespace) -- a victim
running a minimal `busybox httpd`, a prober that tries to reach it --
confirms the prober *can* reach the victim first (so a broken base
network doesn't get misreported as "enforcement verified" by accident),
applies a deny-all NetworkPolicy scoped to the victim's pod, waits a
moment for the CNI to actually apply it, and probes again. Blocked the
second time means enforcement really works (`verified`); still reachable
means it doesn't (`failed`) -- and a run that can't reach a clean
conclusion at all (pods never come up, the pre-policy probe itself
fails) reports `failed` too, on purpose (see
`coverage_store.report_network_policy_enforcement`). Cleanup runs from a
shell `trap ... EXIT`, so it fires whether the test passes, fails, or the
script errors out partway through.

**The other three coverage signals (Falco health, kill_process/
quarantine_node capability)** run inside the poll loop itself, throttled
to roughly once a minute (every 12th cycle at the default 5s interval) --
cheap enough not to need the canary's once-a-day discipline, but not
worth 300 clusters reporting every 5s either. Falco health is a plain
`kubectl get daemonset falco -n falco` status read; the two capability
checks are `kubectl auth can-i delete pods` / `... patch nodes` --
non-destructive RBAC presence checks, never a real workload/node touched
the way the network-policy canary does, since a granted verb has no
CNI-style silent-failure mode to prove separately.

**This introduces a real install-order dependency**: the Falco health
check's RBAC (below) is a namespaced Role bound in the `falco` namespace,
which this script does not create -- only Falco's own install (see
`install_script.py`) does. Installing the responder before Falco means
this `kubectl apply` fails outright (namespace not found) rather than
installing everything else and leaving Falco health silently broken --
consistent with "Requires Runtime Defender (the Falco sensor) already
installed" already being this script's stated prerequisite, just now
enforced at install time instead of discovered later.

Deliberately no custom container image to build or publish -- `alpine/k8s`
already bundles `kubectl`, `curl`, and `jq`, the only three tools the poll
loop needs, the same "reuse what already exists" choice `install_script.py`
makes with Falco's own Helm chart. The canary CronJob reuses the same
image and the same per-cluster Secret token, needing nothing new to
build or ship.

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
can't be narrowed to a namespace even in principle), `get` on
serviceaccounts (revoke_iam's role-ARN resolution only -- no write verbs
at all, since this file only ever reads the annotation, never touches
AWS), `get`/`list`/`create`/`patch`/`delete` on networkpolicies, and
`create` on `selfsubjectaccessreviews` -- the resource `kubectl auth
can-i` itself creates to answer its question, so the capability checks
above need this grant just to *ask* whether a verb is allowed, before
either check ever runs for real.

Two namespaced exceptions to "cluster-scoped only", each for a reason
that's genuinely local to one namespace: the canary CronJob's own extra
verbs (`create`/`delete` on pods, `create` on `pods/exec`), bound only in
`golem-responder` -- it only ever creates its own throwaway pods in its
own namespace, never a customer one, so narrowing costs nothing and
meaningfully shrinks what a compromised responder could do with
`create`/`exec`, verbs the containment tiers above never needed at all.
And the Falco health check's `get` on `daemonsets`, bound only in
`falco` -- there's exactly one DaemonSet this ever needs to read, so
granting `apps/daemonsets` cluster-wide would reach every other
DaemonSet on the cluster for zero additional benefit.

No access to any other resource kind, and nothing enqueues a command in the
first place unless an operator has explicitly opted a Falco rule into
that specific action (see `containment_store.upsert_response_rule`).

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
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    verbs: ["get"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "create", "patch", "delete"]
  - apiGroups: ["authorization.k8s.io"]
    resources: ["selfsubjectaccessreviews"]
    verbs: ["create"]
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
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: golem-responder-canary
  namespace: golem-responder
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create", "get", "list", "delete"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: golem-responder-canary
  namespace: golem-responder
subjects:
  - kind: ServiceAccount
    name: golem-responder
    namespace: golem-responder
roleRef:
  kind: Role
  name: golem-responder-canary
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: golem-responder-falco-health
  namespace: falco
rules:
  - apiGroups: ["apps"]
    resources: ["daemonsets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: golem-responder-falco-health
  namespace: falco
subjects:
  - kind: ServiceAccount
    name: golem-responder
    namespace: golem-responder
roleRef:
  kind: Role
  name: golem-responder-falco-health
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

              report_falco_health() {
                status="$1"
                ready="$2"
                desired="$3"
                if [ -n "${ready}" ]; then
                  body="{\\"status\\": \\"${status}\\", \\"ready\\": ${ready}, \\"desired\\": ${desired}}"
                else
                  body="{\\"status\\": \\"${status}\\"}"
                fi
                curl -sf -X POST -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \\
                  -d "${body}" \\
                  "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/coverage/falco" >/dev/null 2>&1 || true
              }

              check_falco_health() {
                falco_json=$(kubectl get daemonset falco -n falco -o json 2>/dev/null || true)
                if [ -z "${falco_json}" ]; then
                  report_falco_health "unknown" "" ""
                  return
                fi
                ready=$(echo "${falco_json}" | jq -r '.status.numberReady // 0')
                desired=$(echo "${falco_json}" | jq -r '.status.desiredNumberScheduled // 0')
                if [ "${desired}" -gt 0 ] && [ "${ready}" = "${desired}" ]; then
                  report_falco_health "healthy" "${ready}" "${desired}"
                elif [ "${desired}" -gt 0 ]; then
                  report_falco_health "degraded" "${ready}" "${desired}"
                else
                  report_falco_health "unknown" "" ""
                fi
              }

              check_kill_process_capability() {
                status="failed"
                kubectl auth can-i delete pods >/dev/null 2>&1 && status="verified"
                curl -sf -X POST -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \\
                  -d "{\\"status\\": \\"${status}\\"}" \\
                  "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/coverage/kill-process-capability" \\
                  >/dev/null 2>&1 || true
              }

              check_quarantine_node_capability() {
                status="failed"
                kubectl auth can-i patch nodes >/dev/null 2>&1 && status="verified"
                curl -sf -X POST -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \\
                  -d "{\\"status\\": \\"${status}\\"}" \\
                  "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/coverage/quarantine-node-capability" \\
                  >/dev/null 2>&1 || true
              }

              cycle=0
              while true; do
                commands=$(curl -sf -H "Authorization: Bearer ${TOKEN}" \\
                  "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/commands" || echo '[]')

                # Throttled to roughly once a minute (12 cycles at the
                # default 5s poll interval) -- these are cheap, low-risk
                # reads/no-op checks, but 300 clusters reporting every 5s
                # would still be needless steady-state load on the backend
                # for signals that don't need sub-minute freshness.
                cycle=$((cycle + 1))
                if [ $((cycle % 12)) -eq 0 ]; then
                  check_falco_health
                  check_kill_process_capability
                  check_quarantine_node_capability
                fi

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
                    if kubectl delete pod "${pod}" -n "${ns}" --grace-period=0 --force \\
                      --ignore-not-found >/dev/null 2>&1; then
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
                      && kubectl delete pod "${pod}" -n "${ns}" --grace-period=0 --force \\
                        --ignore-not-found >/dev/null 2>&1; then
                      report_status "applied" "${id}"
                    else
                      # quarantine_node retries automatically (see
                      # containment_store.RETRYABLE_ACTIONS) -- this
                      # "failed" report may just increment an attempt
                      # counter server-side rather than going terminal.
                      report_status "failed" "${id}"
                    fi

                  elif [ "${status}" = "pending" ] && [ "${action}" = "revoke_iam" ]; then
                    sa=$(kubectl get pod "${pod}" -n "${ns}" \\
                      -o jsonpath='{.spec.serviceAccountName}' 2>/dev/null || true)
                    sa="${sa:-default}"
                    arn=$(kubectl get serviceaccount "${sa}" -n "${ns}" \\
                      -o jsonpath='{.metadata.annotations.eks\\.amazonaws\\.com/role-arn}' 2>/dev/null || true)
                    if [ -n "${arn}" ] \\
                      && curl -sf -X POST -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \\
                        -d "{\\"role_arn\\": \\"${arn}\\"}" \\
                        "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/commands/${id}/resolve-role" \\
                        >/dev/null 2>&1; then
                      : # resolve-role already moved the command server-side; nothing else to report
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
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: golem-responder-canary
  namespace: golem-responder
spec:
  # Off-peak by default -- change if 3am UTC collides with something else
  # in this cluster. Kept deliberately far from incident-response-critical
  # hours; see coverage_store.py for why this exists at all.
  schedule: "0 3 * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 0
      activeDeadlineSeconds: 180
      template:
        spec:
          serviceAccountName: golem-responder
          restartPolicy: Never
          containers:
            - name: canary
              image: alpine/k8s:1.30.4
              imagePullPolicy: IfNotPresent
              env:
                - name: CLUSTER_ID
                  value: "__GOLEM_CLUSTER_ID_TOKEN__"
                - name: BACKEND_URL
                  value: "__GOLEM_BACKEND_URL_TOKEN__"
                - name: TOKEN
                  valueFrom:
                    secretKeyRef:
                      name: golem-responder-credentials
                      key: token
              command: ["/bin/sh", "-c"]
              args:
                - |
                  set -eu
                  ns="golem-responder"

                  ts=$(date +%s)
                  victim="golem-canary-victim-${ts}"
                  prober="golem-canary-prober-${ts}"
                  netpol_name="golem-canary-deny-${ts}"

                  cleanup() {
                    kubectl delete pod "${victim}" "${prober}" -n "${ns}" --ignore-not-found \\
                      --grace-period=0 --force >/dev/null 2>&1 || true
                    kubectl delete networkpolicy "${netpol_name}" -n "${ns}" --ignore-not-found \\
                      >/dev/null 2>&1 || true
                  }
                  trap cleanup EXIT

                  report() {
                    curl -sf -X POST -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \\
                      -d "{\\"status\\": \\"${1}\\"}" \\
                      "${BACKEND_URL}/api/runtime-clusters/${CLUSTER_ID}/coverage/network-policy" \\
                      >/dev/null 2>&1 || true
                  }

                  wait_running() {
                    pod="${1}"
                    i=0
                    while [ "${i}" -lt 30 ]; do
                      phase=$(kubectl get pod "${pod}" -n "${ns}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
                      [ "${phase}" = "Running" ] && return 0
                      i=$((i + 1))
                      sleep 2
                    done
                    return 1
                  }

                  probe() {
                    victim_ip=$(kubectl get pod "${victim}" -n "${ns}" \\
                      -o jsonpath='{.status.podIP}' 2>/dev/null || true)
                    [ -n "${victim_ip}" ] || return 1
                    kubectl exec "${prober}" -n "${ns}" -- wget -q -T 3 -O /dev/null "http://${victim_ip}:8080/" \\
                      >/dev/null 2>&1
                  }

                  kubectl run "${victim}" -n "${ns}" --image=busybox:1.36 --restart=Never \\
                    --command -- sh -c 'mkdir -p /tmp/www && httpd -f -p 8080 -h /tmp/www' >/dev/null 2>&1
                  kubectl run "${prober}" -n "${ns}" --image=busybox:1.36 --restart=Never \\
                    --command -- sleep 300 >/dev/null 2>&1

                  if ! wait_running "${victim}" || ! wait_running "${prober}"; then
                    report "failed"
                    exit 0
                  fi

                  if ! probe; then
                    report "failed"
                    exit 0
                  fi

                  kubectl label pod "${victim}" -n "${ns}" "golem-io/canary=${ts}" --overwrite >/dev/null 2>&1

                  netpol_p1="{\\"apiVersion\\":\\"networking.k8s.io/v1\\",\\"kind\\":\\"NetworkPolicy\\",\\"metadata\\":{\\"name"
                  netpol_p2="\\":\\"${netpol_name}\\",\\"namespace\\":\\"${ns}\\"},\\"spec\\":{\\"podSelector\\":{\\"matchLabels"
                  netpol_p3="\\":{\\"golem-io/canary\\":\\"${ts}\\"}},\\"policyTypes\\":[\\"Ingress\\",\\"Egress\\"],\\"ingress\\""
                  netpol_p4=":[],\\"egress\\":[]}}"
                  netpol_json="${netpol_p1}${netpol_p2}${netpol_p3}${netpol_p4}"
                  echo "${netpol_json}" | kubectl apply -f - >/dev/null 2>&1

                  sleep 3

                  if probe; then
                    report "failed"
                  else
                    report "verified"
                  fi
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
