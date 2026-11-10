"""Give the CENTRAL coturn workers a `/stats` endpoint so the `eu-central`
region joins the relay dashboard (stats follow-up A).

The PoPs serve `/stats` from their `derp-relay` container; the central
fleet had nothing equivalent, so the Observability card read "not
monitored". This adds the SAME producer as a sidecar to each
`coturn-worker-N` Deployment (the API image ships the `derp-relay`
binary), and enables coturn's prometheus exporter so the sidecar can
report TURN allocations/sessions instead of nulls.

Both changes need a pod restart, so they are applied together — one
worker at a time, waiting for rollout between — and each worker's restart
drops only ITS live TURN allocations (clients hold 3 A records; overlay
carriers rebuild). Run during a quiet window.

Idempotent: re-running skips workers that already carry the sidecar and a
`prometheus` line.

Usage (on a host with cluster access):
    IMAGE=registry.meshharbor.itachi.fans/meshharbor:<tag> \
    DERP_TICKET_PUBLIC_KEY=<base64 pubkey> \
    python3 scripts/coturn-stats-sidecar.py [--workers 1,2,3] [--dry-run]

Then point the region at the sidecars (deploy-repo configmap):
    "stats_urls": ["http://<node-1>:9645/stats", ...]
"""

import argparse
import json
import os
import subprocess
import sys

NS = "coturn"
SIDECAR_NAME = "stats"
STATS_PORT = int(os.environ.get("STATS_PORT", "9645"))
REGION = os.environ.get("REGION", "eu-central")
# The registry pull secret lives in the meshharbor namespace; the coturn
# namespace needs its own copy to pull the API image.
PULL_SECRET = os.environ.get("PULL_SECRET", "regcred")
PULL_SECRET_SRC_NS = os.environ.get("PULL_SECRET_SRC_NS", "meshharbor")


def kubectl(*args, capture=True, check=True):
    cmd = ["kubectl", *args]
    return subprocess.run(
        cmd, capture_output=capture, text=True, check=check
    ).stdout.strip()


def ensure_pull_secret(dry_run: bool) -> None:
    """Copy the registry pull secret into the coturn namespace (once)."""
    try:
        kubectl("-n", NS, "get", "secret", PULL_SECRET)
        print(f"  pull secret {PULL_SECRET}: present")
        return
    except subprocess.CalledProcessError:
        pass
    print(f"  pull secret {PULL_SECRET}: copying from {PULL_SECRET_SRC_NS}")
    if dry_run:
        return
    raw = kubectl(
        "-n", PULL_SECRET_SRC_NS, "get", "secret", PULL_SECRET, "-o", "json"
    )
    doc = json.loads(raw)
    doc["metadata"] = {"name": PULL_SECRET, "namespace": NS}
    subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=json.dumps(doc),
        text=True,
        check=True,
    )


def enable_prometheus(worker: str, dry_run: bool) -> bool:
    """Add `prometheus` to the worker's turnserver.conf. Returns True when
    the config changed (⇒ the pod must restart to pick it up)."""
    cm = f"coturn-worker-{worker}-config"
    conf = kubectl(
        "-n", NS, "get", "cm", cm, "-o", r"jsonpath={.data.turnserver\.conf}"
    )
    if any(line.strip() == "prometheus" for line in conf.splitlines()):
        print(f"  {cm}: prometheus already enabled")
        return False
    # The exporter binds localhost:9641 — the sidecar scrapes it over the
    # shared host network; nothing is exposed off-box.
    new_conf = conf.rstrip("\n") + "\nprometheus\n"
    print(f"  {cm}: enabling prometheus exporter")
    if dry_run:
        return True
    patch = [{"op": "replace", "path": "/data/turnserver.conf", "value": new_conf}]
    subprocess.run(
        ["kubectl", "-n", NS, "patch", "cm", cm, "--type=json", "-p", json.dumps(patch)],
        check=True,
    )
    return True


def sidecar_patch(image: str, pubkey: str) -> dict:
    return {
        "spec": {
            "template": {
                "spec": {
                    "imagePullSecrets": [{"name": PULL_SECRET}],
                    "containers": [
                        {
                            "name": SIDECAR_NAME,
                            "image": image,
                            "command": ["/usr/local/bin/derp-relay"],
                            "env": [
                                # hostNetwork pod: bind the node's PRIVATE
                                # address, never 0.0.0.0 — /stats (and the
                                # relay's /derp) stay on the cluster net.
                                {
                                    "name": "NODE_IP",
                                    "valueFrom": {
                                        "fieldRef": {"fieldPath": "status.hostIP"}
                                    },
                                },
                                {"name": "DERP_BIND", "value": f"$(NODE_IP):{STATS_PORT}"},
                                {"name": "REGION", "value": REGION},
                                {"name": "DERP_TICKET_PUBLIC_KEY", "value": pubkey},
                                {"name": "RUST_LOG", "value": "info"},
                            ],
                            "resources": {
                                "requests": {"cpu": "10m", "memory": "32Mi"},
                                "limits": {"memory": "128Mi"},
                            },
                        }
                    ],
                }
            }
        }
    }


def has_sidecar(deploy: str) -> bool:
    names = kubectl(
        "-n",
        NS,
        "get",
        "deploy",
        deploy,
        "-o",
        "jsonpath={.spec.template.spec.containers[*].name}",
    ).split()
    return SIDECAR_NAME in names


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", default="1,2,3")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    image = os.environ.get("IMAGE")
    pubkey = os.environ.get("DERP_TICKET_PUBLIC_KEY")
    if not image or not pubkey:
        return "IMAGE and DERP_TICKET_PUBLIC_KEY are required"

    print(f"image={image} region={REGION} port={STATS_PORT} dry_run={args.dry_run}")
    ensure_pull_secret(args.dry_run)

    for w in [x.strip() for x in args.workers.split(",") if x.strip()]:
        deploy = f"coturn-worker-{w}"
        print(f"== {deploy}")
        conf_changed = enable_prometheus(w, args.dry_run)
        if has_sidecar(deploy):
            print("  sidecar: already present")
            if not conf_changed:
                continue
            # Config-only change: the pod must still restart to reload.
            if not args.dry_run:
                subprocess.run(
                    ["kubectl", "-n", NS, "rollout", "restart", f"deploy/{deploy}"],
                    check=True,
                )
        else:
            print("  sidecar: adding")
            if not args.dry_run:
                subprocess.run(
                    [
                        "kubectl",
                        "-n",
                        NS,
                        "patch",
                        "deploy",
                        deploy,
                        "-p",
                        json.dumps(sidecar_patch(image, pubkey)),
                    ],
                    check=True,
                )
        if args.dry_run:
            continue
        # One worker at a time: a failed rollout must not cascade.
        subprocess.run(
            ["kubectl", "-n", NS, "rollout", "status", f"deploy/{deploy}", "--timeout=180s"],
            check=True,
        )
        node_ip = kubectl(
            "-n",
            NS,
            "get",
            "pods",
            "-l",
            f"instance={deploy}",
            "-o",
            "jsonpath={.items[0].status.hostIP}",
        )
        print(f"  ready — stats at http://{node_ip}:{STATS_PORT}/stats")

    print("\nDone. Region config:")
    print('  "stats_urls": [')
    for w in [x.strip() for x in args.workers.split(",") if x.strip()]:
        try:
            ip = kubectl(
                "-n",
                NS,
                "get",
                "pods",
                "-l",
                f"instance=coturn-worker-{w}",
                "-o",
                "jsonpath={.items[0].status.hostIP}",
            )
            print(f'    "http://{ip}:{STATS_PORT}/stats",')
        except subprocess.CalledProcessError:
            pass
    print("  ]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
