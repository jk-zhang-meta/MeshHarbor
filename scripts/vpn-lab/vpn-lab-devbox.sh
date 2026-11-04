#!/bin/bash
# vpn-lab-devbox.sh — dev-box half of the VPN cycle lab: timestamped 1 s pings
# toward the corp laptop's overlay IPs in BOTH orgs + local overlay snapshots.
# Runs locally (Git Bash), no fleet-exec dependency; writes into $OUT.
#
# Usage: vpn-lab-devbox.sh <out-dir> <duration-s> [target ...]
# The fleet device name the sampler greps for in `roomler peers` output comes
# from $LAB_TARGET (default "winhost-a") so no real hostname is baked in here.
set -u
OUT="${1:?out dir}"; DUR="${2:?duration seconds}"; shift 2
TARGETS=("${@:-100.65.4.28 100.65.0.5}")
[ $# -eq 0 ] && TARGETS=(100.65.4.28 100.65.0.5)
MESHHARBOR="/c/Program Files/MeshHarbor/meshharbor.exe"
LAB_TARGET="${LAB_TARGET:-winhost-a}"
mkdir -p "$OUT"

end=$(( $(date +%s) + DUR ))

ping_loop() {
  local t="$1" csv="$OUT/ping-${1//./_}.csv"
  while [ "$(date +%s)" -lt "$end" ]; do
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    # Windows ping.exe; TTL= marks success in any locale, first NNms is the RTT.
    local out rtt
    out=$(ping -n 1 -w 1000 "$t" 2>/dev/null)
    if grep -q "TTL=" <<<"$out"; then
      rtt=$(grep -o '[0-9]\+ms' <<<"$out" | head -1 | tr -d ms)
      echo "$ts,Success,${rtt:-0}" >> "$csv"
    else
      echo "$ts,TimedOut,-1" >> "$csv"
    fi
    sleep 1
  done
}

sampler_loop() {
  local f="$OUT/roomler-samples.txt" i=0
  while [ "$(date +%s)" -lt "$end" ]; do
    echo "=== $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) status" >> "$f"
    "$MESHHARBOR" status 2>&1 | grep -iE "version|srflx|warm|direct sock" >> "$f"
    if [ $((i % 3)) -eq 0 ]; then
      echo "=== $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) peers" >> "$f"
      "$MESHHARBOR" peers 2>&1 | grep -E "${LAB_TARGET}|org:" >> "$f"
    fi
    i=$((i + 1))
    sleep 10
  done
}

for t in "${TARGETS[@]}"; do ping_loop "$t" & done
sampler_loop &
wait
echo "dev-box runner done: $OUT"
