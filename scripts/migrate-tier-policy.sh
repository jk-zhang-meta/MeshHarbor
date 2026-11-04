#!/bin/bash
# migrate-tier-policy.sh — 2026-05-02
#
# One-shot migration to enforce the cluster tier policy:
#   tickytack + meshharbor-old: utility-worker -> high-perf
#                            (fresh init, old data on utility assumed stale)
#   bauleiter + regal:       high-perf      -> utility-worker
#                            (data restored from $BACKUP_DIR)
#
# Idempotent — safe to re-run after any failure or ssh drop.
# Logs to $LOG. Override BACKUP_DIR / LOG / DEPLOY_PARENT in the env if
# your layout differs from the defaults below.
#
# Run on the build host as a user with kubectl context configured.

set -uo pipefail
BACKUP_DIR="${BACKUP_DIR:-$HOME/migration-backups}"
LOG="${LOG:-$HOME/migration-tier-policy.log}"
DEPLOY_PARENT="${DEPLOY_PARENT:-$HOME}"
exec > >(tee -a "$LOG") 2>&1
echo
echo "=================================================="
echo "=== START $(date) ==="
echo "=================================================="

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
delete_pv() {
  local pv=$1
  if ! kubectl get pv "$pv" >/dev/null 2>&1; then
    echo "PV $pv: absent"
    return 0
  fi
  echo "PV $pv: deleting (clearing finalizers first)"
  kubectl patch pv "$pv" -p '{"metadata":{"finalizers":null}}' --type=merge >/dev/null 2>&1 || true
  kubectl delete pv "$pv" --wait=false >/dev/null 2>&1 || true
  for _ in $(seq 1 15); do
    kubectl get pv "$pv" >/dev/null 2>&1 || return 0
    sleep 1
  done
  echo "WARN: PV $pv still present after 15s"
}

delete_pvc() {
  local ns=$1 pvc=$2
  if ! kubectl -n "$ns" get pvc "$pvc" >/dev/null 2>&1; then
    echo "PVC $ns/$pvc: absent"
    return 0
  fi
  echo "PVC $ns/$pvc: deleting (clearing finalizers first)"
  kubectl -n "$ns" patch pvc "$pvc" -p '{"metadata":{"finalizers":null}}' --type=merge >/dev/null 2>&1 || true
  kubectl -n "$ns" delete pvc "$pvc" --wait=false >/dev/null 2>&1 || true
  for _ in $(seq 1 15); do
    kubectl -n "$ns" get pvc "$pvc" >/dev/null 2>&1 || return 0
    sleep 1
  done
  echo "WARN: PVC $ns/$pvc still present after 15s"
}

# Args: pv_name app_label proj_ns size host_path target_node pvc_name
make_pv() {
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolume
metadata:
  name: $1
  labels: { app: $2, project: $3 }
spec:
  accessModes: [ReadWriteOnce]
  capacity: { storage: $4 }
  hostPath: { path: $5, type: DirectoryOrCreate }
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - { key: kubernetes.io/hostname, operator: In, values: [$6] }
  persistentVolumeReclaimPolicy: Retain
  claimRef:
    apiVersion: v1
    kind: PersistentVolumeClaim
    namespace: $3
    name: $7
EOF
}

# Args: ns pvc_name pv_name size
make_pvc() {
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  namespace: $1
  name: $2
spec:
  accessModes: [ReadWriteOnce]
  resources: { requests: { storage: $4 } }
  volumeName: $3
EOF
}

# Remove the `nodeSelector: kubernetes.io/hostname: ...` block (idempotent).
remove_hostname_pin() {
  local file=$1
  [ -f "$file" ] || return 0
  if ! grep -q 'kubernetes.io/hostname:' "$file"; then
    return 0
  fi
  sed -i '/^      nodeSelector:$/{N;/kubernetes.io\/hostname:/d;}' "$file"
  echo "EDIT $(basename "$file"): removed hostname pin"
}

# Change hostname pin in base/ manifest to a new node (idempotent).
change_hostname_pin() {
  local file=$1 new=$2
  [ -f "$file" ] || return 0
  if ! grep -q 'kubernetes.io/hostname:' "$file"; then
    return 0
  fi
  sed -i "s|kubernetes.io/hostname: k8s-worker-[0-9]\+|kubernetes.io/hostname: $new|g" "$file"
  echo "EDIT $(basename "$file"): hostname pin -> $new"
}

# Commit + push deploy repo if there are unstaged changes.
push_deploy() {
  local dir=$1 msg=$2
  pushd "$dir" >/dev/null
  if git diff --quiet --exit-code; then
    echo "REPO $(basename "$dir"): no changes"
    popd >/dev/null
    return 0
  fi
  git add -A
  git commit -m "$msg" >/dev/null
  branch=$(git rev-parse --abbrev-ref HEAD)
  git push origin "$branch" 2>&1 | tail -1
  echo "REPO $(basename "$dir"): pushed $branch=$(git rev-parse --short HEAD)"
  popd >/dev/null
}

# Wait until a pod (selected by labels in $ns) is Running on $node.
wait_pod_on_node() {
  local ns=$1 selector=$2 node=$3 timeout=${4:-300}
  echo "Waiting up to ${timeout}s for $ns pod ($selector) on $node..."
  for _ in $(seq 1 "$timeout"); do
    local out
    out=$(kubectl -n "$ns" get pods -l "$selector" -o jsonpath='{range .items[*]}{.metadata.name} {.status.phase} {.spec.nodeName}{"\n"}{end}' 2>/dev/null)
    if echo "$out" | grep -q "Running $node"; then
      echo "$ns ($selector) on $node: Running"
      return 0
    fi
    sleep 1
  done
  echo "WARN: $ns ($selector) not Running on $node after ${timeout}s"
  return 1
}

# ======================================================================
# tickytack — to worker-3 (fleet-host-1 HP), fresh init
# ======================================================================
echo
echo "--- tickytack -> fleet-host-1 (worker-3), fresh init ---"
delete_pvc tickytack mongodb-data
delete_pv  tickytack-mongodb-pv
make_pv    tickytack-mongodb-pv mongodb tickytack 5Gi /data/tickytack/mongodb k8s-worker-3 mongodb-data
make_pvc   tickytack mongodb-data tickytack-mongodb-pv 5Gi
remove_hostname_pin "$DEPLOY_PARENT"/tickytack-deploy/k8s/base/deployment-tickytack.yaml
remove_hostname_pin "$DEPLOY_PARENT"/tickytack-deploy/k8s/base/statefulset-mongodb.yaml
push_deploy "$DEPLOY_PARENT"/tickytack-deploy 'feat(scheduling): unpin worker-1; tier=high-performance overlay handles placement (M5 migration)'

# ======================================================================
# meshharbor-old — to worker-2 (fleet-host-2 HP), fresh init
# ======================================================================
echo
echo "--- meshharbor-old -> fleet-host-2 (worker-2), fresh init ---"
delete_pvc meshharbor mongodb-data
delete_pvc meshharbor meshharbor-uploads
delete_pv  meshharbor-mongodb-pv
delete_pv  meshharbor-uploads-pv
make_pv    meshharbor-mongodb-pv mongodb meshharbor 5Gi /data/meshharbor/mongodb k8s-worker-2 mongodb-data
make_pv    meshharbor-uploads-pv meshharbor  meshharbor 5Gi /data/meshharbor/uploads k8s-worker-2 meshharbor-uploads
make_pvc   meshharbor mongodb-data    meshharbor-mongodb-pv 5Gi
make_pvc   meshharbor meshharbor-uploads meshharbor-uploads-pv 5Gi
for f in "$DEPLOY_PARENT"/meshharbor-deploy/k8s/base/deployment-janus.yaml \
         "$DEPLOY_PARENT"/meshharbor-deploy/k8s/base/deployment-redis.yaml \
         "$DEPLOY_PARENT"/meshharbor-deploy/k8s/base/deployment-meshharbor.yaml \
         "$DEPLOY_PARENT"/meshharbor-deploy/k8s/base/statefulset-mongodb.yaml; do
  remove_hostname_pin "$f"
done
push_deploy "$DEPLOY_PARENT"/meshharbor-deploy 'feat(scheduling): unpin worker-1; tier=high-performance overlay handles placement (M5 migration)'

# ======================================================================
# bauleiter — to worker-1 (buildhost utility), data restored from backup
# ======================================================================
echo
echo "--- bauleiter -> buildhost (worker-1), with mongo + uploads restore ---"
delete_pvc bauleiter mongodb-data
delete_pvc bauleiter bauleiter-uploads
delete_pv  bauleiter-mongodb-pv
delete_pv  bauleiter-uploads-pv
make_pv    bauleiter-mongodb-pv  mongodb   bauleiter 1Gi /data/arse/mongodb           k8s-worker-1 mongodb-data
make_pv    bauleiter-uploads-pv  bauleiter bauleiter 1Gi /data/arse/bauleiter-uploads k8s-worker-1 bauleiter-uploads
make_pvc   bauleiter mongodb-data      bauleiter-mongodb-pv  1Gi
make_pvc   bauleiter bauleiter-uploads bauleiter-uploads-pv 1Gi
change_hostname_pin "$DEPLOY_PARENT"/bauleiter-deploy/k8s/base/deployment-bauleiter.yaml k8s-worker-1
change_hostname_pin "$DEPLOY_PARENT"/bauleiter-deploy/k8s/base/statefulset-mongodb.yaml  k8s-worker-1

# Append tier=utility patch to bauleiter overlay (deferred earlier).
KUST="$DEPLOY_PARENT"/bauleiter-deploy/k8s/overlays/prod/kustomization.yaml
if [ -f /tmp/tier-patch.tmpl ] && ! grep -q '^patches:' "$KUST"; then
  sed 's/TIER_VALUE/utility/g' /tmp/tier-patch.tmpl >> "$KUST"
  echo "OVERLAY bauleiter-deploy: added tier=utility patch"
fi

push_deploy "$DEPLOY_PARENT"/bauleiter-deploy 'feat(scheduling): repin worker-1 + tier=utility (M5 migration fleet-host-1->buildhost)'

wait_pod_on_node bauleiter app=mongodb k8s-worker-1 300

# Restore bauleiter mongo
DUMP="$BACKUP_DIR/bauleiter-mongo.dump.gz"
if [ -f "$DUMP" ] && [ "$(stat -c%s "$DUMP")" -gt 100 ]; then
  echo "Restoring bauleiter mongo dump..."
  : "${MONGO_ADMIN_USER:?set MONGO_ADMIN_USER for mongorestore}"
  : "${MONGO_ADMIN_PASS:?set MONGO_ADMIN_PASS for mongorestore}"
  kubectl -n bauleiter exec -i mongodb-0 -- mongorestore \
    --username="$MONGO_ADMIN_USER" --password="$MONGO_ADMIN_PASS" \
    --authenticationDatabase=admin \
    --gzip --archive --drop \
    < "$DUMP"
  echo "bauleiter mongo: restored"
else
  echo "bauleiter mongo backup empty/missing; skipping restore"
fi

# Restore bauleiter uploads (skip if backup is trivial — original was 92 bytes / empty)
TAR="$BACKUP_DIR/bauleiter-uploads.tar.gz"
if [ -f "$TAR" ] && [ "$(stat -c%s "$TAR")" -gt 200 ]; then
  echo "Restoring bauleiter uploads..."
  kubectl -n bauleiter cp "$TAR" deploy/bauleiter:/tmp/u.tar.gz
  kubectl -n bauleiter exec deploy/bauleiter -- tar -xzf /tmp/u.tar.gz -C /
  kubectl -n bauleiter exec deploy/bauleiter -- rm -f /tmp/u.tar.gz
  echo "bauleiter uploads: restored"
else
  echo "bauleiter uploads backup trivial/missing; skipping restore"
fi

# ======================================================================
# regal — to worker-1 (buildhost utility), data restored from backup
# ======================================================================
echo
echo "--- regal -> buildhost (worker-1), with data + uploads restore ---"
delete_pvc regal regalbg-data
delete_pvc regal regalbg-uploads
delete_pv  regal-regalbg-data-pv
delete_pv  regal-regalbg-uploads-pv
make_pv    regal-regalbg-data-pv    regalbg regal 1Gi /data/arse/regalbg-data    k8s-worker-1 regalbg-data
make_pv    regal-regalbg-uploads-pv regalbg regal 1Gi /data/arse/regalbg-uploads k8s-worker-1 regalbg-uploads
make_pvc   regal regalbg-data    regal-regalbg-data-pv    1Gi
make_pvc   regal regalbg-uploads regal-regalbg-uploads-pv 1Gi
change_hostname_pin "$DEPLOY_PARENT"/regal-deploy/k8s/base/deployment-regalbg.yaml k8s-worker-1
push_deploy "$DEPLOY_PARENT"/regal-deploy 'feat(scheduling): repin worker-1 (M5 migration fleet-host-1->buildhost)'

wait_pod_on_node regal app=regalbg k8s-worker-1 300

# Restore regal data
TAR="$BACKUP_DIR/regal-data.tar.gz"
if [ -f "$TAR" ] && [ "$(stat -c%s "$TAR")" -gt 200 ]; then
  echo "Restoring regal data (~30 KB)..."
  kubectl -n regal cp "$TAR" deploy/regalbg:/tmp/d.tar.gz
  kubectl -n regal exec deploy/regalbg -- tar -xzf /tmp/d.tar.gz -C /
  kubectl -n regal exec deploy/regalbg -- rm -f /tmp/d.tar.gz
  echo "regal data: restored"
fi

# Restore regal uploads (40 MB — the meaningful payload)
TAR="$BACKUP_DIR/regal-uploads.tar.gz"
if [ -f "$TAR" ] && [ "$(stat -c%s "$TAR")" -gt 200 ]; then
  echo "Restoring regal uploads (~40 MB)..."
  kubectl -n regal cp "$TAR" deploy/regalbg:/tmp/u.tar.gz
  kubectl -n regal exec deploy/regalbg -- tar -xzf /tmp/u.tar.gz -C /
  kubectl -n regal exec deploy/regalbg -- rm -f /tmp/u.tar.gz
  echo "regal uploads: restored"
fi

# ======================================================================
# Final state
# ======================================================================
echo
echo "=================================================="
echo "=== END $(date) ==="
echo "=================================================="
echo "Final pod placement:"
for ns in tickytack meshharbor bauleiter regal; do
  echo "--- $ns ---"
  kubectl -n "$ns" get pods -o wide --no-headers 2>/dev/null \
    | awk '{printf "  %-32s %-12s %s\n", $1, $3, $7}'
done
echo
echo "PV nodeAffinity:"
kubectl get pv -o jsonpath='{range .items[*]}{.metadata.name}{"  -> "}{.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values[0]}{"  ("}{.status.phase}{")\n"}{end}' \
  | grep -E 'tickytack|meshharbor|bauleiter|regal' | sort
