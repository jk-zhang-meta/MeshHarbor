#!/bin/bash
# migrate-tier-policy-recover.sh — 2026-05-04
#
# Recovery from the partial migration: scale workloads to 0 so pods
# release their PVC mounts, force-clear stuck Terminating PVCs/PVs,
# recreate PVs on the correct nodes, then let ArgoCD scale back up.
#
# Idempotent — safe to re-run.

set -uo pipefail
LOG="${LOG:-$HOME/migration-recover.log}"
BACKUP_DIR="${BACKUP_DIR:-$HOME/migration-backups}"
exec > >(tee -a "$LOG") 2>&1
echo
echo "=================================================="
echo "=== RECOVER START $(date) ==="
echo "=================================================="

force_delete_pvc() {
  local ns=$1 pvc=$2
  if ! kubectl -n "$ns" get pvc "$pvc" >/dev/null 2>&1; then
    echo "PVC $ns/$pvc: absent"
    return 0
  fi
  echo "PVC $ns/$pvc: clearing finalizers + force delete"
  kubectl -n "$ns" patch pvc "$pvc" -p '{"metadata":{"finalizers":null}}' --type=merge >/dev/null 2>&1 || true
  kubectl -n "$ns" delete pvc "$pvc" --grace-period=0 --force --wait=false >/dev/null 2>&1 || true
  for _ in $(seq 1 15); do
    kubectl -n "$ns" get pvc "$pvc" >/dev/null 2>&1 || return 0
    kubectl -n "$ns" patch pvc "$pvc" -p '{"metadata":{"finalizers":null}}' --type=merge >/dev/null 2>&1 || true
    sleep 1
  done
  echo "WARN: PVC $ns/$pvc still present"
}

force_delete_pv() {
  local pv=$1
  if ! kubectl get pv "$pv" >/dev/null 2>&1; then
    echo "PV $pv: absent"
    return 0
  fi
  echo "PV $pv: clearing finalizers + force delete"
  kubectl patch pv "$pv" -p '{"metadata":{"finalizers":null}}' --type=merge >/dev/null 2>&1 || true
  kubectl delete pv "$pv" --grace-period=0 --force --wait=false >/dev/null 2>&1 || true
  for _ in $(seq 1 15); do
    kubectl get pv "$pv" >/dev/null 2>&1 || return 0
    kubectl patch pv "$pv" -p '{"metadata":{"finalizers":null}}' --type=merge >/dev/null 2>&1 || true
    sleep 1
  done
  echo "WARN: PV $pv still present"
}

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

scale_down() {
  local ns=$1 kind=$2 name=$3
  if kubectl -n "$ns" get "$kind"/"$name" >/dev/null 2>&1; then
    echo "Scale $ns/$kind/$name -> 0"
    kubectl -n "$ns" scale "$kind" "$name" --replicas=0 >/dev/null 2>&1 || true
  fi
}

force_kill_pod() {
  local ns=$1 pod=$2
  if kubectl -n "$ns" get pod "$pod" >/dev/null 2>&1; then
    echo "Force kill $ns/$pod"
    kubectl -n "$ns" delete pod "$pod" --grace-period=0 --force >/dev/null 2>&1 || true
  fi
}

wait_pvc_bound() {
  local ns=$1 pvc=$2
  for _ in $(seq 1 30); do
    local s
    s=$(kubectl -n "$ns" get pvc "$pvc" -o jsonpath='{.status.phase}' 2>/dev/null)
    [ "$s" = "Bound" ] && { echo "PVC $ns/$pvc: Bound"; return 0; }
    sleep 2
  done
  echo "WARN: PVC $ns/$pvc not Bound after 60s"
}

# ======================================================================
# tickytack — old ReplicaSet pod on worker-1 needs to die
# ======================================================================
echo
echo "--- tickytack: clean up old worker-1 pod ---"
for p in $(kubectl -n tickytack get pods -o jsonpath='{range .items[?(@.spec.nodeName=="k8s-worker-1")]}{.metadata.name} {end}'); do
  force_kill_pod tickytack "$p"
done
# Delete old (bad) ReplicaSet pod that's CrashLoopBackOff to force fresh schedule
for p in $(kubectl -n tickytack get pods -o jsonpath='{range .items[?(@.status.phase=="Failed")]}{.metadata.name} {end}'); do
  force_kill_pod tickytack "$p"
done

# ======================================================================
# meshharbor-old — recreate uploads PV/PVC on worker-2 + clean old worker-1 pods
# ======================================================================
echo
echo "--- meshharbor-old: recreate uploads PV/PVC + clean worker-1 pods ---"
for p in $(kubectl -n meshharbor get pods -o jsonpath='{range .items[?(@.spec.nodeName=="k8s-worker-1")]}{.metadata.name} {end}'); do
  force_kill_pod meshharbor "$p"
done
force_delete_pvc meshharbor meshharbor-uploads
force_delete_pv  meshharbor-uploads-pv
make_pv  meshharbor-uploads-pv meshharbor meshharbor 5Gi /data/meshharbor/uploads k8s-worker-2 meshharbor-uploads
make_pvc meshharbor meshharbor-uploads meshharbor-uploads-pv 5Gi
wait_pvc_bound meshharbor meshharbor-uploads

# ======================================================================
# bauleiter — scale to 0, clear PVCs/PVs, recreate on worker-1, restore
# ======================================================================
echo
echo "--- bauleiter: scale-down + recreate on worker-1 ---"
scale_down bauleiter deployment bauleiter
scale_down bauleiter statefulset mongodb
echo "Waiting for bauleiter pods to terminate..."
for _ in $(seq 1 30); do
  count=$(kubectl -n bauleiter get pods --no-headers 2>/dev/null | wc -l)
  [ "$count" -eq 0 ] && { echo "bauleiter: no pods"; break; }
  sleep 2
done

force_delete_pvc bauleiter mongodb-data
force_delete_pvc bauleiter bauleiter-uploads
force_delete_pv  bauleiter-mongodb-pv
force_delete_pv  bauleiter-uploads-pv

make_pv  bauleiter-mongodb-pv  mongodb   bauleiter 1Gi /data/arse/mongodb           k8s-worker-1 mongodb-data
make_pv  bauleiter-uploads-pv  bauleiter bauleiter 1Gi /data/arse/bauleiter-uploads k8s-worker-1 bauleiter-uploads
make_pvc bauleiter mongodb-data      bauleiter-mongodb-pv 1Gi
make_pvc bauleiter bauleiter-uploads bauleiter-uploads-pv 1Gi
wait_pvc_bound bauleiter mongodb-data
wait_pvc_bound bauleiter bauleiter-uploads

echo "Triggering ArgoCD reconcile by re-pushing bauleiter-deploy (no-op rebase)..."
# ArgoCD's auto-sync should reconcile within ~60s after we deleted+recreated
# everything. If StatefulSet is still scaled to 0, force a sync by bumping
# replicas back. Actually ArgoCD will see desired replicas=1 in Git and
# reconcile. But the live SS was scaled to 0 imperatively — ArgoCD selfHeal
# should put it back. Wait + verify.
echo "Waiting for ArgoCD selfHeal to scale bauleiter back up..."
for _ in $(seq 1 60); do
  ss_replicas=$(kubectl -n bauleiter get statefulset mongodb -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")
  d_replicas=$(kubectl -n bauleiter get deployment bauleiter -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")
  if [ "$ss_replicas" != "0" ] && [ "$d_replicas" != "0" ]; then
    echo "bauleiter: replicas restored (ss=$ss_replicas, deploy=$d_replicas)"
    break
  fi
  sleep 5
done
# Force scale up if ArgoCD didn't (selfHeal sometimes lazy)
kubectl -n bauleiter scale statefulset mongodb --replicas=1 >/dev/null 2>&1 || true
kubectl -n bauleiter scale deployment bauleiter --replicas=1 >/dev/null 2>&1 || true

echo "Waiting for bauleiter mongodb-0 on worker-1..."
for _ in $(seq 1 60); do
  s=$(kubectl -n bauleiter get pod mongodb-0 -o jsonpath='{.status.phase}{" "}{.spec.nodeName}' 2>/dev/null)
  [ "$s" = "Running k8s-worker-1" ] && { echo "bauleiter mongodb-0: Running on worker-1"; break; }
  sleep 5
done

# Restore mongo
DUMP="$BACKUP_DIR"/bauleiter-mongo.dump.gz
if [ -f "$DUMP" ] && [ "$(stat -c%s "$DUMP")" -gt 100 ]; then
  echo "Restoring bauleiter mongo..."
  kubectl -n bauleiter exec -i mongodb-0 -- mongorestore \
    --username="${MONGO_ADMIN_USER:?set MONGO_ADMIN_USER}" \
    --password="${MONGO_ADMIN_PASS:?set MONGO_ADMIN_PASS}" \
    --authenticationDatabase=admin \
    --gzip --archive --drop \
    < "$DUMP" 2>&1 | tail -10
  echo "bauleiter mongo: done"
fi

# ======================================================================
# regal — scale to 0, clear PVCs/PVs, recreate on worker-1, restore
# ======================================================================
echo
echo "--- regal: scale-down + recreate on worker-1 ---"
scale_down regal deployment regalbg
echo "Waiting for regal pods to terminate..."
for _ in $(seq 1 30); do
  count=$(kubectl -n regal get pods --no-headers 2>/dev/null | wc -l)
  [ "$count" -eq 0 ] && { echo "regal: no pods"; break; }
  sleep 2
done

force_delete_pvc regal regalbg-data
force_delete_pvc regal regalbg-uploads
force_delete_pv  regal-regalbg-data-pv
force_delete_pv  regal-regalbg-uploads-pv

make_pv  regal-regalbg-data-pv    regalbg regal 1Gi /data/arse/regalbg-data    k8s-worker-1 regalbg-data
make_pv  regal-regalbg-uploads-pv regalbg regal 1Gi /data/arse/regalbg-uploads k8s-worker-1 regalbg-uploads
make_pvc regal regalbg-data    regal-regalbg-data-pv    1Gi
make_pvc regal regalbg-uploads regal-regalbg-uploads-pv 1Gi
wait_pvc_bound regal regalbg-data
wait_pvc_bound regal regalbg-uploads

# ArgoCD selfHeal scales back to 1
for _ in $(seq 1 30); do
  d_replicas=$(kubectl -n regal get deployment regalbg -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")
  [ "$d_replicas" != "0" ] && { echo "regal: replicas restored ($d_replicas)"; break; }
  sleep 5
done
kubectl -n regal scale deployment regalbg --replicas=1 >/dev/null 2>&1 || true

echo "Waiting for regalbg on worker-1..."
for _ in $(seq 1 60); do
  s=$(kubectl -n regal get pods -l app=regalbg -o jsonpath='{.items[0].status.phase}{" "}{.items[0].spec.nodeName}' 2>/dev/null)
  [ "$s" = "Running k8s-worker-1" ] && { echo "regalbg: Running on worker-1"; break; }
  sleep 5
done

# Restore regal data + uploads
TAR="$BACKUP_DIR"/regal-data.tar.gz
if [ -f "$TAR" ] && [ "$(stat -c%s "$TAR")" -gt 200 ]; then
  echo "Restoring regal data..."
  kubectl -n regal cp "$TAR" deploy/regalbg:/tmp/d.tar.gz 2>&1 | tail -5
  kubectl -n regal exec deploy/regalbg -- tar -xzf /tmp/d.tar.gz -C / 2>&1 | tail -5
  kubectl -n regal exec deploy/regalbg -- rm -f /tmp/d.tar.gz
  echo "regal data: done"
fi
TAR="$BACKUP_DIR"/regal-uploads.tar.gz
if [ -f "$TAR" ] && [ "$(stat -c%s "$TAR")" -gt 200 ]; then
  echo "Restoring regal uploads (~40 MB)..."
  kubectl -n regal cp "$TAR" deploy/regalbg:/tmp/u.tar.gz 2>&1 | tail -5
  kubectl -n regal exec deploy/regalbg -- tar -xzf /tmp/u.tar.gz -C / 2>&1 | tail -5
  kubectl -n regal exec deploy/regalbg -- rm -f /tmp/u.tar.gz
  echo "regal uploads: done"
fi

# ======================================================================
# Final state
# ======================================================================
echo
echo "=================================================="
echo "=== RECOVER END $(date) ==="
echo "=================================================="
for ns in tickytack meshharbor bauleiter regal; do
  echo "--- $ns ---"
  kubectl -n "$ns" get pods,pvc -o wide --no-headers 2>/dev/null \
    | awk '{printf "  %-40s %s\n", $1, $2"  "$3"  "$NF}'
done
echo
echo "PV nodeAffinity:"
kubectl get pv -o jsonpath='{range .items[*]}{.metadata.name}{"  -> "}{.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values[0]}{"  ("}{.status.phase}{")\n"}{end}' \
  | grep -E 'tickytack|meshharbor|bauleiter|regal' | sort
