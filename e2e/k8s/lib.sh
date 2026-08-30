#!/usr/bin/env bash
# Helpers for in-cluster Shardscape multi-node tests on a kind cluster.
#
# Build + load the image first:
#   (docker build -t "$SS_IMG" . && kind load docker-image "$SS_IMG")
#
# SS_IMG defaults to shardscape:test; override to match what you loaded.
set -euo pipefail
SS_IMG="${SS_IMG:-shardscape:test}"

fqdn() { echo "shardscape-$2.$1.svc.cluster.local"; }   # ns site -> internal FQDN

# emit a node Deployment+Service. mode=init|join ; peer=site to join (join only).
# emptyDir volumes on purpose: deleting a pod exercises full backfill-on-rejoin.
emit_node() {
  local ns=$1 site=$2 mode=$3 peer=${4:-} adv main_args init_block=""
  adv="http://$(fqdn "$ns" "$site"):8015"
  if [ "$mode" = init ]; then
    init_block=$(cat <<EOF
      initContainers:
        - name: init
          image: $SS_IMG
          imagePullPolicy: Never
          command: ["/bin/sh","-c"]
          args: ["test -f /data/config.toml || /usr/local/bin/shardscape init --config /data/config.toml --data-dir /data --cluster-secret \"\$CLUSTER_SECRET\" --location-id $site --s3-addr 0.0.0.0:8014 --internal-addr 0.0.0.0:8015 --advertise $adv"]
          env: [{ name: CLUSTER_SECRET, valueFrom: { secretKeyRef: { name: ss-cluster, key: secret } } }]
          volumeMounts: [{ name: data, mountPath: /data }]
EOF
)
    main_args='["serve","--config","/data/config.toml"]'
  else
    local padv="http://$(fqdn "$ns" "$peer"):8015"
    main_args="[\"/bin/sh\",\"-c\",\"/usr/local/bin/shardscape join $padv --secret \\\"\$CLUSTER_SECRET\\\" --config /data/config.toml --data-dir /data --location-id $site --s3-addr 0.0.0.0:8014 --internal-addr 0.0.0.0:8015 --advertise $adv\"]"
  fi
  cat <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: shardscape-$site, namespace: $ns }
spec:
  replicas: 1
  selector: { matchLabels: { app: shardscape, site: $site } }
  template:
    metadata: { labels: { app: shardscape, site: $site } }
    spec:
$init_block
      containers:
        - name: shardscape
          image: $SS_IMG
          imagePullPolicy: Never
          $( [ "$mode" = init ] && echo "args: $main_args" || echo "command: $main_args" )
          env: [{ name: CLUSTER_SECRET, valueFrom: { secretKeyRef: { name: ss-cluster, key: secret } } }]
          ports: [{ containerPort: 8014, name: s3 }, { containerPort: 8015, name: internal }]
          volumeMounts: [{ name: data, mountPath: /data }]
          readinessProbe: { tcpSocket: { port: s3 }, initialDelaySeconds: 2 }
      volumes: [{ name: data, emptyDir: {} }]
---
apiVersion: v1
kind: Service
metadata: { name: shardscape-$site, namespace: $ns }
spec:
  selector: { app: shardscape, site: $site }
  ports: [{ name: s3, port: 8014, targetPort: s3 }, { name: internal, port: 8015, targetPort: internal }]
EOF
}

new_cluster() {  # ns
  kubectl create ns "$1" >/dev/null 2>&1 || true
  kubectl -n "$1" create secret generic ss-cluster \
    --from-literal=secret="$(openssl rand -hex 32)" >/dev/null 2>&1 || true
}
deploy_node() { emit_node "$@" | kubectl apply -f - >/dev/null; }
wait_node()   { kubectl -n "$1" rollout status "deploy/shardscape-$2" --timeout=180s >/dev/null; }
admin_secret() { kubectl -n "$1" logs -l site="$2" -c init 2>/dev/null | grep 'Admin secret' | awk '{print $4}' | head -1; }
node_status() { kubectl -n "$1" exec "deploy/shardscape-$2" -c shardscape -- /usr/local/bin/shardscape status --config /data/config.toml 2>/dev/null; }
