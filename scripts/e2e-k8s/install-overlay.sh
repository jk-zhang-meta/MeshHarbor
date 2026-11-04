#!/bin/bash
# One-shot installer that copies the e2e overlay template into the
# deploy repo on the build host. Run from the local repo root:
#   bash scripts/e2e-k8s/install-overlay.sh
# Then commit + push the deploy repo if you want gitops to track it
# (recommended: don't auto-sync via ArgoCD — keep manual-apply).
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
DEPLOY_REPO="${DEPLOY_REPO:-$HOME/roomler-ai-deploy}"
DST="$DEPLOY_REPO/k8s/overlays/e2e"

if [ ! -d "$DEPLOY_REPO" ]; then
  echo "deploy repo not found at $DEPLOY_REPO" >&2
  exit 1
fi

mkdir -p "$DST"
# FR-114 — NEVER overwrite a file the deploy copy already has. That copy is
# the live truth and has moved on from this template: the roomler2 Deployment
# (its `pwrunner` sidecar), the e2e config, the secrets, MinIO, the
# kustomization. A blind `cp` reverted all of them and took the nightly lane
# down. New files (the agent-e2e four) are copied; an existing file that
# differs from the template is only REPORTED, for a human to merge.
NEW_FILES=0
for src in "$REPO_ROOT/scripts/e2e-k8s/overlay-template/"*.yaml; do
  f=$(basename "$src")
  if [ ! -e "$DST/$f" ]; then
    cp -v "$src" "$DST/$f"
    NEW_FILES=$((NEW_FILES + 1))
  elif ! cmp -s "$src" "$DST/$f"; then
    echo "kept $f — the deploy copy differs from the template; merge by hand if the template's change is wanted"
  fi
done
echo "copied $NEW_FILES new file(s)"

# Auto-track the current prod image — the e2e overlay should
# always validate the same image that's live on roomler.ai (per the
# user's "pin to current prod tag" decision in the plan). Read it
# from the prod overlay's kustomization.yaml and substitute it
# into the e2e kustomization.yaml. Idempotent — re-running the
# installer bumps the pin in place.
#
# FR-114 — pin ONE image, never every `newTag:` line: the overlay pins two
# images, and stamping the prod server's tag onto `roomlerd-e2e` would point
# the agents at a tag that image never had. And pin the NAME with the tag:
# since FR-73 prod pulls from ghcr.io while the e2e copy still named
# registry.roomler.ai, so a tag-only pin named a tag that registry never had —
# the ImagePullBackOff `scripts/e2e-nightly.sh` §1b records (2026-09-06).
# A line ending in \r (a Windows checkout read by a Linux awk, as under WSL)
# still matches: the \r is ignored, then put back.
pin_image() {
  local name="$1" tag="$2" new_name="${3:-}" file="$DST/kustomization.yaml"
  awk -v want="$name" -v tag="$tag" -v nname="$new_name" '
    { line = $0; cr = ""; if (sub(/\r$/, "", line)) cr = "\r" }
    line ~ /^[^ \t#-]/ { hit = 0 }
    line ~ /- name: / { hit = (line ~ ("- name: " want "$")) }
    hit && nname != "" && line ~ /newName:/ { sub(/newName:.*/, "newName: " nname, line) }
    hit && line ~ /newTag:/ { sub(/newTag:.*/, "newTag: " tag, line) }
    { print line cr }' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}
# "<newName> <newTag>" of one image's entry in a kustomization, or nothing.
read_pin() {
  awk -v want="$2" '
    { sub(/\r$/, "") }
    /^[^ \t#-]/ { hit = 0 }
    /- name: / { hit = ($0 ~ ("- name: " want "$")) }
    hit && /newName:/ { n = $2 }
    hit && /newTag:/ { t = $2 }
    END { if (n != "" && t != "") print n, t }' "$1"
}
read -r PROD_NAME PROD_TAG <<<"$(read_pin "$DEPLOY_REPO/k8s/overlays/prod/kustomization.yaml" gjovanov/roomler-ai)"
if [ -n "$PROD_TAG" ]; then
  pin_image gjovanov/roomler-ai "$PROD_TAG" "$PROD_NAME"
  echo "Pinned e2e overlay to the prod image: $PROD_NAME:$PROD_TAG"
else
  echo "WARNING: could not auto-detect the prod image; edit $DST/kustomization.yaml manually" >&2
fi

# FR-114 — the agent-e2e image is pinned to the dated tag that was pushed
# (`AGENT_E2E_TAG=agent-e2e-<YYYYMMDD>-<sha7>`), never `latest`, so a night's
# agent is a known build. Unset = leave whatever the deploy copy pins.
if [ -n "${AGENT_E2E_TAG:-}" ]; then
  pin_image gjovanov/roomlerd-e2e "$AGENT_E2E_TAG"
  echo "Pinned the agent-e2e image to: $AGENT_E2E_TAG"
fi
# A kept kustomization (the deploy copy) lists only what it listed before:
# name what the agent-e2e harness still needs added there by hand.
for f in secret-agent-e2e-bootstrap.yaml job-agent-e2e-seed.yaml service-agent-e2e.yaml statefulset-agent-e2e.yaml; do
  grep -qE "^\s*- $f\s*$" "$DST/kustomization.yaml" || echo "WARNING: $f is not in $DST/kustomization.yaml's resources" >&2
done
grep -q 'name: gjovanov/roomlerd-e2e' "$DST/kustomization.yaml" \
  || echo "WARNING: $DST/kustomization.yaml has no images: entry for gjovanov/roomlerd-e2e" >&2

# Copy regcred from the prod namespace if not already present in
# roomler-ai-e2e. Without it the roomler2 deployment can't pull from
# `registry.roomler.ai`. Idempotent — `kubectl apply` is safe to
# re-run; `2>/dev/null || true` swallows the no-op case.
if kubectl get namespace roomler-ai-e2e >/dev/null 2>&1; then
  if ! kubectl -n roomler-ai-e2e get secret regcred >/dev/null 2>&1; then
    if kubectl -n roomler-ai get secret regcred >/dev/null 2>&1; then
      echo "Copying regcred secret from roomler-ai to roomler-ai-e2e"
      kubectl -n roomler-ai get secret regcred -o yaml \
        | sed 's/namespace: roomler-ai$/namespace: roomler-ai-e2e/' \
        | kubectl apply -f - >/dev/null
    else
      echo "WARNING: regcred missing in roomler-ai too; image pulls will fail" >&2
    fi
  fi

  # Cycle 4 Chunk 1: we ACTIVELY route outbound mail through Mailpit
  # via the SMTP backend (configmap sets MESHHARBOR__EMAIL__SMTP_HOST +
  # SMTP_PORT). EmailService::from_settings prefers SendGrid when
  # api_key is non-empty, so we must NOT copy the prod SendGrid key
  # into the e2e secret — doing so would silently route every send
  # to the real SendGrid account instead of Mailpit. The patch that
  # previously copied MESHHARBOR__EMAIL__API_KEY from prod is removed
  # here. If you want to test the SendGrid path explicitly, set it
  # back manually with `kubectl -n roomler-ai-e2e patch secret ...`.
  :
fi

echo
echo "Installed $DST"
echo
echo "Next steps:"
echo "  1. cd $DEPLOY_REPO && git add k8s/overlays/e2e && git commit -m 'feat(e2e): overlay'"
echo "  2. (Optional) git push  — ArgoCD does NOT watch this overlay."
echo "  3. kubectl apply -k $DST/"
echo "  4. bash scripts/e2e-k8s.sh smoke"
