#!/bin/bash
# run-lab.sh — one command = one VPN-cycle experiment against the corp laptop.
#
# Deploys/refreshes vpn-lab.ps1 on the laptop (raw.githubusercontent, branch-
# aware), launches the cycle DETACHED there (SYSTEM scheduled task — survives
# control-WS churn), runs the dev-box measurement half locally, then collects
# both sides and extracts the outage windows per org.
#
# Usage: run-lab.sh <count> <hold-s> <rest-s> [branch]
set -euo pipefail
COUNT="${1:-2}"; HOLD="${2:-180}"; REST="${3:-120}"; BRANCH="${4:-vpn-lab}"
# The installed CLI, not a build tree: `C:\rwexec` was a scratch worktree that
# no longer exists, and the lab is normally driven from a checkout with no
# built agent at all. Overridable for a host that installed elsewhere.
EXEC="${EXEC:-/c/Program Files/MeshHarbor/meshharbor.exe}"
# Fleet device names the lab drives. Override to the real names at runtime so
# no hostname is committed. LAB_TARGET = the laptop's `meshharbor exec` device
# name; DEVBOX_NAME = how the dev box shows up in `meshharbor peers` output.
LAB_TARGET="${LAB_TARGET:-WINHOST-A}"; export LAB_TARGET
DEVBOX_NAME="${DEVBOX_NAME:-devbox}"
RUNID=$(date -u +%Y%m%d-%H%M%S)
OUT="${VPNLAB_OUT:-$HOME/vpnlab}/$RUNID"
RAW="https://raw.githubusercontent.com/jk-zhang-meta/MeshHarbor/$BRANCH/scripts/vpn-lab/vpn-lab.ps1"
mkdir -p "$OUT"

psexec() { # run an encoded PS command on the target host, CLIXML noise stripped
  local enc; enc=$(printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)
  "$EXEC" exec "$LAB_TARGET" --timeout "${2:-60000}" -- "powershell -NoProfile -EncodedCommand $enc" 2>&1 |
    grep -vE "CLIXML|^<Objs"
}

echo "== deploy ($BRANCH) =="
# Best-effort: an IN-VPN laptop reaches github via the corp egress (usually
# blocked), and the on-box copy is normally already current — warn and continue.
psexec "New-Item -ItemType Directory -Path 'C:\ProgramData\meshharbor\vpnlab' -Force | Out-Null;
try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 20 -Uri '$RAW' -OutFile 'C:\ProgramData\meshharbor\vpnlab\vpn-lab.ps1' } catch { \"deploy fetch failed (\$(\$_.Exception.Message)) — using the existing copy\" };
(Get-Item 'C:\ProgramData\meshharbor\vpnlab\vpn-lab.ps1' -ErrorAction SilentlyContinue).Length" 120000 || echo "deploy step unreachable — continuing with the existing on-box copy"

# Clock skew between the two halves, measured BEFORE the cycle and recorded
# with the run. The two sides timestamp from their own unsynchronised clocks,
# so every cross-host comparison — "who lost the path first", "did the far end
# recover before we convicted" — is meaningless without it.
#
# This is not hypothetical. Measured 2026-08-25: CORPLAP-1 sat **21.4 s behind**
# the dev box, stable across three samples. That skew alone manufactured a
# reading in which the laptop appeared to still be reaching the dev box while
# the dev box's own carrier had gone one-way — an impossible pair of facts that
# cost real time to chase, and which simply vanished once both series were put
# on one clock. Per-END durations were never affected (each is computed inside
# a single host's clock); only the alignment between them was.
#
# NTP is not a fix to rely on here: the corp laptop's clock is managed by a
# domain policy this lab does not control, so the correct move is to MEASURE
# the offset per run rather than assume it away. Half the round-trip bounds the
# error; the RTT is printed so a reader can judge the sample.
echo "== clock skew (laptop - devbox) =="
SKEW_T0=$(date -u +%s.%N)
LAPTOP_MS=$(psexec "[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()" 60000 | grep -oE "^[0-9]{13}" | head -1)
SKEW_T1=$(date -u +%s.%N)
if [ -n "${LAPTOP_MS:-}" ]; then
  awk -v a="$SKEW_T0" -v b="$LAPTOP_MS" -v c="$SKEW_T1" \
    'BEGIN { mid=(a+c)/2
             printf "skew_seconds %+.2f\nrtt_seconds %.2f\nnote add skew_seconds to laptop timestamps to read them on devbox time\n", \
               b/1000-mid, c-a }' | tee "$OUT/clock-skew.txt"
else
  echo "skew_seconds UNKNOWN — laptop clock unreadable; cross-host alignment is NOT valid for this run" |
    tee "$OUT/clock-skew.txt"
fi

echo "== launch detached run $RUNID =="
psexec "\$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\meshharbor\vpnlab\vpn-lab.ps1 -Cmd cycle -Count $COUNT -HoldSec $HOLD -RestSec $REST -RunId $RUNID';
\$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5);
Register-ScheduledTask -TaskName 'meshharbor-vpnlab-run' -Action \$a -Trigger \$t -User 'SYSTEM' -RunLevel Highest -Force | Out-Null;
Start-ScheduledTask -TaskName 'meshharbor-vpnlab-run'; 'LAUNCHED $RUNID'" 60000

# Total = optional normalize (disc+rest) + N*(connect~30s+hold+disc~15s+rest)
# + the 90 s post-transition sampler window + slack
TOTAL=$(( REST + COUNT * (HOLD + REST + 60) + 240 ))
echo "== local measurement for ${TOTAL}s → $OUT =="
"$(dirname "$0")/vpn-lab-devbox.sh" "$OUT" "$TOTAL" &
LOCAL_PID=$!
sleep "$TOTAL"
wait "$LOCAL_PID" || true

echo "== collect from $LAB_TARGET =="
# Each pull is best-effort: the laptop's control WS is often still recovering
# right after a run (that recovery IS part of what the run measures) — a
# failed pull must not abort the local analysis. Re-collect later via the
# same Get-Content calls; the run dir persists on the box.
RD="C:\\ProgramData\\meshharbor\\vpnlab\\run-$RUNID"
psexec "Get-Content '$RD\\events.csv' -ErrorAction SilentlyContinue" 60000 > "$OUT/pc-events.csv" || true
for t in 100_65_4_2 100_65_0_6; do
  psexec "Get-Content '$RD\\ping-$t.csv' -ErrorAction SilentlyContinue" 90000 > "$OUT/pc-ping-$t.csv" || true
done
# `derp drops` is in the pattern because the far end's unrouted counter is the
# ONLY per-node evidence of "a peer relayed to us while we held another
# carrier" — the demote-follow's input. Its absence left the 08-25 run's laptop
# half silent on exactly the question that run was measuring, while the dev-box
# half (read live) answered it. The counters are cumulative, so the value is in
# the DIFF across samples — which is why every sample must be kept.
psexec "Get-Content '$RD\\meshharbor-samples.txt' -ErrorAction SilentlyContinue | Select-String -Pattern '=== |version|srflx|warm|derp drops|${DEVBOX_NAME}|org:' | ForEach-Object { \$_.Line }" 90000 > "$OUT/pc-meshharbor-samples.txt" || true
psexec "Get-Content '$RD\\trac-connect.log' -ErrorAction SilentlyContinue" 60000 > "$OUT/pc-trac.log" || true

echo "== outage windows (>=3 consecutive lost pings) =="
# Reprinted next to the windows, not just stashed in the run dir: the `pc-*`
# rows below are on the LAPTOP's clock and the rest are on the dev box's, and
# this is the exact spot where someone lines them up by eye.
if [ -s "$OUT/clock-skew.txt" ]; then
  sed 's/^/  [clock] /' "$OUT/clock-skew.txt"
  echo "  [clock] pc-* rows are LAPTOP time; the others are DEVBOX time — do not compare directly"
fi
# Measured LAST-OK -> FIRST-OK in wall clock, with the sample count reported
# SEPARATELY. They are not the same number: a lost `ping -n 1 -w 1000` costs
# ~2 s, not 1 s, so labelling the count as seconds understates a real outage by
# about half — the 08-25 run printed "12 s" for a 25 s hole and had to be
# recomputed by hand. Same 1:1 trap as reading timeout counts off a ping trace.
for f in "$OUT"/pc-ping-*.csv "$OUT"/ping-*.csv; do
  [ -s "$f" ] || continue
  echo "-- $(basename "$f")"
  awk -F, '
    function ep(t) { gsub(/[-:TZ]/, " ", t); split(t, a, " ")
                     return mktime(a[1]" "a[2]" "a[3]" "a[4]" "a[5]" "int(a[6])) }
    $2!="Success" { if (!s) { s=$1; lastok=prev } ; n++ ; prev=$1 ; next }
    { if (n>=3) printf "  %s -> %s = %d s wall (%d lost pings)\n", \
        lastok, $1, ep($1) - ep(lastok), n ; s="" ; n=0 ; prev=$1 }
    END { if (n>=3) printf "  %s -> end, still down (%d lost pings)\n", lastok, n }' "$f"
done
echo "== events =="
cat "$OUT/pc-events.csv" 2>/dev/null || true
echo "RUN $RUNID collected at $OUT"
