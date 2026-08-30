#!/usr/bin/env bash
# In-cluster multi-node correctness tests for Shardscape on kind.
#
#   3-node mesh:  C joins B (not A) and must discover A transitively via gossip;
#                 objects replicate across the whole mesh both directions.
#   partition:    sever A<->B (break Service selectors), write the same key on
#                 both sides, heal, and verify last-write-wins converges.
#
# Prereqs: a kind cluster, kubectl, openssl, and a python venv with boto3 at
# e2e/.venv (see e2e/requirements.txt). Build + load the image, then run:
#   SS_IMG=shardscape:test
#   (docker build -t "$SS_IMG" . && kind load docker-image "$SS_IMG")
#   e2e/k8s/test_multinode.sh
# Set KEEP=1 to leave the namespaces up for inspection.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"
PY="$HERE/../.venv/bin/python"
KEEP="${KEEP:-0}"
NS3=shardscape-3node
NSP=shardscape-part

pf_pids=()
start_pf() {  # ns site localport
  kubectl -n "$1" port-forward "deploy/shardscape-$2" "$3:8014" >"/tmp/pf_$2.log" 2>&1 &
  pf_pids+=($!)
}
wait_local_port() {  # port
  for _ in $(seq 1 40); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- ; return 0; }
    sleep 0.5
  done
  return 1
}
stop_pf() { for p in "${pf_pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; pf_pids=(); }
cleanup() {
  stop_pf
  [ "$KEEP" = 1 ] || kubectl delete ns "$NS3" "$NSP" --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ───────────────────────── 3-node mesh ─────────────────────────
kubectl delete ns "$NS3" --wait=true >/dev/null 2>&1 || true
new_cluster "$NS3"
deploy_node "$NS3" a init   ; wait_node "$NS3" a
deploy_node "$NS3" b join a  ; wait_node "$NS3" b
deploy_node "$NS3" c join b  ; wait_node "$NS3" c   # C joins B, NOT A

# C must discover A transitively (membership gossip).
peers=""
for _ in $(seq 1 12); do
  peers="$(node_status "$NS3" c | sed -n '/peers:/,$p')"
  echo "$peers" | grep -q shardscape-a && echo "$peers" | grep -q shardscape-b && break
  sleep 5
done
echo "$peers" | grep -q shardscape-a || { echo "FAIL: C did not discover A"; exit 1; }
echo "[3node] C (joined only B) discovered A transitively  ✓"

SECRET="$(admin_secret "$NS3" a)"
start_pf "$NS3" a 19001; start_pf "$NS3" c 19003
wait_local_port 19001; wait_local_port 19003
"$PY" "$HERE/_driver.py" mesh "$SECRET" 19001 19003
stop_pf
echo "[3node] cross-mesh replication both directions  ✓"

# ───────────────────────── partition / LWW ─────────────────────────
kubectl delete ns "$NSP" --wait=true >/dev/null 2>&1 || true
new_cluster "$NSP"
deploy_node "$NSP" a init   ; wait_node "$NSP" a
deploy_node "$NSP" b join a  ; wait_node "$NSP" b

SECRET="$(admin_secret "$NSP" a)"
start_pf "$NSP" a 19101; start_pf "$NSP" b 19102
wait_local_port 19101; wait_local_port 19102
"$PY" "$HERE/_driver.py" partition "$SECRET" 19101 19102 "$NSP"
stop_pf
echo "[partition] divergence under partition, LWW converge on heal  ✓"

echo; echo "ALL MULTI-NODE K8S TESTS PASSED"
