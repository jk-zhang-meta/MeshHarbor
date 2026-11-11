#!/usr/bin/env bash
# Run ONE meshharbor-tests integration test inside a disposable network
# namespace, for the tests whose fixture needs addresses the host must not
# carry (public "ingress/exit" aliases on a real NIC) and a private
# MongoDB/Redis. Nothing outside the namespace is touched: no route, address
# or firewall change on the host, and the databases live in a temp dir that is
# removed afterwards.
#
# Linux, root (unshare -n). The WSL kernel has no `dummy` link type, so the NIC
# is one end of a veth pair.
#
# usage: scripts/netns-integration-test.sh <test-binary> <test-path> [alias,alias,...] [VAR=value ...]
#   <test-binary>  the meshharbor_tests-<hash> executable
#                  (`cargo test -p meshharbor-tests --lib --no-run` prints it)
#   <test-path>    exact test path, e.g.
#                  business_isolation_tests::legacy_three_relay_runtime_recovers_automatically_after_middle_restart
#   aliases        comma-separated IPv4 addresses added /32 to the namespace NIC
#   VAR=value      environment for the test process
# env:
#   MONGOD (default: mongod), REDIS_SERVER (default: redis-server)
#   MONGO_EXTRA    extra mongod arguments, e.g. "--setParameter ttlMonitorSleepSecs=1"
#
# The test runs with --include-ignored, so a test marked #[ignore] for needing
# this harness is exercised here and nowhere else.
set -euo pipefail

[ "$#" -ge 2 ] || { sed -n '2,24p' "$0"; exit 2; }
BIN=$1
TEST=$2
ALIASES=${3:-}
shift $(($# >= 3 ? 3 : 2))
[ -x "$BIN" ] || { echo "not an executable test binary: $BIN" >&2; exit 2; }
MONGOD=${MONGOD:-mongod}
REDIS_SERVER=${REDIS_SERVER:-redis-server}
DB=$(mktemp -d /var/tmp/mh-netns-test-XXXXXX)
trap 'rm -rf "$DB"' EXIT

unshare -n env "$@" BIN="$BIN" TEST="$TEST" ALIASES="$ALIASES" DB="$DB" \
    MONGOD="$MONGOD" REDIS_SERVER="$REDIS_SERVER" MONGO_EXTRA="${MONGO_EXTRA:-}" \
    bash -c '
  set -u
  ip link set lo up
  ip link add mh0 type veth peer name mh1
  ip link set mh1 up
  ip link set mh0 up
  ip addr add 10.77.0.1/24 dev mh0
  for a in $(echo "$ALIASES" | tr , " "); do ip addr add "$a/32" dev mh0; done
  ip -4 -br addr show
  # shellcheck disable=SC2086
  "$MONGOD" --dbpath "$DB" --port 27019 --bind_ip 127.0.0.1 --fork \
      --pidfilepath "$DB/mongod.pid" --logpath "$DB/mongod.log" \
      --wiredTigerCacheSizeGB 1 $MONGO_EXTRA >/dev/null
  (cd "$DB" && "$REDIS_SERVER" --port 6379 --bind 127.0.0.1 --daemonize yes \
      --save "" --appendonly no --pidfile "$DB/redis.pid" --logfile "$DB/redis.log")
  sleep 2
  rc=0
  RUST_MIN_STACK=${RUST_MIN_STACK:-8388608} "$BIN" "$TEST" --exact --include-ignored \
      --nocapture --test-threads=1 || rc=$?
  # Only the processes this namespace started, by pid file: the host may run a
  # MongoDB/Redis with the same command line.
  kill "$(cat "$DB/mongod.pid")" "$(cat "$DB/redis.pid")" 2>/dev/null || true
  sleep 1
  exit $rc
'
