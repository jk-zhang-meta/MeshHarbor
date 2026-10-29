#!/usr/bin/env bash
# Refresh one already-managed app. Initial mount/image deployment is separate.
set -euo pipefail
umask 077
die() { echo "GeoIP refresh: $*" >&2; exit 1; }
[[ $# == 2 && $1 == --config ]] || die 'usage: refresh.sh --config ROOT_OWNED_0600_FILE'
config=$2
[[ -f $config && ! -L $config && $(stat -c '%u:%a' "$config") == 0:600 ]] || die 'unsafe config owner/mode/type'
DATA_ROOT= CONTAINER= READY_URL= FETCH_SCRIPT= LOCK_FILE=
declare -A seen
while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || $line == \#* ]] && continue
    [[ $line =~ ^(DATA_ROOT|CONTAINER|READY_URL|FETCH_SCRIPT|LOCK_FILE)=([A-Za-z0-9_./:-]+)$ ]] || die 'invalid config entry'
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    [[ ! ${seen[$key]+yes} ]] || die 'duplicate config key'
    seen[$key]=1
    printf -v "$key" '%s' "$value"
done < "$config"
[[ ${#seen[@]} == 5 && $CONTAINER == meshharbor-test-app-1 ]] || die 'incomplete config or unexpected app'
[[ $READY_URL == http://127.0.0.1:18081/health/ready ]] || die 'unexpected readiness URL'
for path in "$DATA_ROOT" "$FETCH_SCRIPT" "$LOCK_FILE"; do
    [[ $path == /* && $path != *'/../'* && $path != */.. && $path != *','* ]] || die 'invalid absolute path'
done
[[ -d $DATA_ROOT && ! -L $DATA_ROOT && $(realpath "$DATA_ROOT") == "$DATA_ROOT" ]] || die 'data root is not a canonical directory'
[[ $(stat -c '%u' "$DATA_ROOT") == 0 ]] || die 'unexpected data root owner'
[[ -f $FETCH_SCRIPT && ! -L $FETCH_SCRIPT && $(stat -c '%u' "$FETCH_SCRIPT") == 0 ]] || die 'unsafe fetch script'
[[ $((8#$(stat -c '%a' "$DATA_ROOT") & 8#022)) == 0 && $((8#$(stat -c '%a' "$FETCH_SCRIPT") & 8#022)) == 0 ]] || die 'writable data root/fetch script'
[[ ! -L $LOCK_FILE ]] || die 'symlink lock refused'
lock_parent=$(dirname "$LOCK_FILE")
[[ $(realpath "$lock_parent") == "$lock_parent" && $(stat -c '%u' "$lock_parent") == 0 && $((8#$(stat -c '%a' "$lock_parent") & 8#022)) == 0 ]] || die 'unsafe lock parent'
mount_at=/usr/share/roomler/geoip-managed
db_name=dbip-country-lite.mmdb
prov_name=dbip-country-lite.provenance.txt
snapshot() {
    docker inspect "$CONTAINER" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert len(d)==1
c=d[0]; root=sys.argv[1]; dest=sys.argv[2]
assert type(c["State"]["Running"]) is bool
m=[m for m in c["Mounts"] if m["Destination"]==dest]
assert len(m)==1 and m[0]["Type"]=="bind" and m[0]["Source"]==root and m[0]["RW"] is False
env=[e for e in c["Config"]["Env"] if e.startswith("ROOMLER__STATS__GEOIP_MMDB=")]
assert env==["ROOMLER__STATS__GEOIP_MMDB="+dest+"/current/dbip-country-lite.mmdb"]
values=[c["Id"],c["Image"],c["State"]["StartedAt"],str(int(c["State"]["Running"]))]
assert all(isinstance(v,str) and v and "|" not in v and "\n" not in v for v in values)
print("|".join(values))
' "$DATA_ROOT" "$mount_at"
}
initial=$(snapshot) || die 'app identity/mount/env inspection failed'
IFS='|' read -r app_id image_id started running <<< "$initial"
[[ $running == 1 ]] || die 'app is not running'
[[ $app_id =~ ^[a-f0-9]{64}$ && $image_id =~ ^sha256:[a-f0-9]{64}$ ]] || die 'invalid immutable app identity'
mkdir -p "$DATA_ROOT/releases"
[[ ! -L $DATA_ROOT/releases && $(stat -c '%u' "$DATA_ROOT/releases") == 0 && $((8#$(stat -c '%a' "$DATA_ROOT/releases") & 8#022)) == 0 ]] || die 'unsafe releases directory'
candidate=$(mktemp -d "$DATA_ROOT/.candidate.XXXXXX")
cleanup_candidate() {
    [[ -e $candidate || -L $candidate ]] || return 0
    [[ ${candidate%/*} == "$DATA_ROOT" && ${candidate##*/} =~ ^\.candidate\.[a-zA-Z0-9]{6}$ &&
       -d $candidate && ! -L $candidate && $(stat -c '%u' "$candidate") == 0 ]] || {
        echo 'GeoIP refresh: refusing cleanup of an unexpected candidate path' >&2
        return 1
    }
    # Only this invocation's exact mktemp directory; releases are never removed.
    rm -rf --one-file-system -- "$candidate"
}
trap 'status=$?; trap - EXIT INT TERM; cleanup_candidate || status=1; exit "$status"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# This fetch helper may exit zero without staging anything. Never reuse current.
env -u GEOIP_BASE_URL -u GITHUB_OUTPUT -u GITHUB_ACTIONS bash "$FETCH_SCRIPT" "$candidate"
[[ -s $candidate/$db_name && -s $candidate/$prov_name ]] || die 'fetch produced no complete candidate'
[[ ! -L $candidate/$db_name && ! -L $candidate/$prov_name ]] || die 'symlink candidate refused'
chmod 0755 "$candidate"
digest=$(sha256sum "$candidate/$db_name"); digest=${digest%% *}
grep -Fqx "sha256:  $digest  ($db_name, $(stat -c '%s' "$candidate/$db_name") bytes)" "$candidate/$prov_name" || die 'candidate provenance mismatch'
validate() {
    docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
        --user 65534:65534 --memory 128m --cpus 0.5 --pids-limit 32 \
        --mount "type=bind,src=$1,dst=/candidate,readonly" \
        --entrypoint /usr/local/bin/meshharbor-geoip-check "$image_id" "/candidate/$db_name" |
        python3 -c '
import json,sys
d=json.load(sys.stdin)
assert isinstance(d,dict) and d.get("valid") is True and d.get("status")=="current"
assert d.get("database_type")=="DBIP-Country-Lite"
assert type(d.get("build_epoch")) is int and 0<d["build_epoch"]<2**63
assert type(d.get("age_secs")) is int and 0<=d["age_secs"]<=120*86400
assert d.get("max_age_secs")==120*86400
print(d["build_epoch"])
'
}
epoch=$(validate "$candidate") || die 'candidate MMDB validation failed'
# Download can proceed concurrently, but activation shares the app deployment lock.
exec 9>"$LOCK_FILE"
flock -x -w 30 9 || die 'app update lock timeout'
[[ $(snapshot) == "$initial" ]] || die 'app changed during download/validation'
[[ -L $DATA_ROOT/current ]] || die 'initial managed dataset must be installed separately'
old=$(readlink "$DATA_ROOT/current")
[[ $old =~ ^releases/[a-f0-9]{64}$ && -d $DATA_ROOT/$old && ! -L $DATA_ROOT/$old ]] || die 'invalid current release'
old_digest=${old#releases/}
old_actual=$(sha256sum "$DATA_ROOT/$old/$db_name"); old_actual=${old_actual%% *}
[[ $old_actual == "$old_digest" ]] || die 'current release digest mismatch'
[[ -f $DATA_ROOT/$old/build_epoch && ! -L $DATA_ROOT/$old/build_epoch ]] || die 'current release epoch manifest missing'
[[ $(stat -c '%u' "$DATA_ROOT/$old/build_epoch") == 0 && $((8#$(stat -c '%a' "$DATA_ROOT/$old/build_epoch") & 8#022)) == 0 ]] || die 'unsafe current epoch manifest'
old_epoch=$(cat "$DATA_ROOT/$old/build_epoch")
[[ $old_epoch =~ ^[1-9][0-9]{0,10}$ ]] || die 'invalid current epoch manifest'
(( epoch >= old_epoch )) || die 'dataset epoch downgrade refused'
if [[ $digest == "$old_digest" ]]; then
    echo "GeoIP refresh: unchanged sha256=$digest build_epoch=$epoch; no restart"
    exit 0
fi
release="releases/$digest"
if [[ -e $DATA_ROOT/$release || -L $DATA_ROOT/$release ]]; then
    [[ -d $DATA_ROOT/$release && ! -L $DATA_ROOT/$release ]] || die 'invalid existing release'
    [[ -f $DATA_ROOT/$release/build_epoch && ! -L $DATA_ROOT/$release/build_epoch && $(cat "$DATA_ROOT/$release/build_epoch") == "$epoch" ]] || die 'existing release epoch manifest mismatch'
    [[ -s $DATA_ROOT/$release/$prov_name && ! -L $DATA_ROOT/$release/$prov_name && ! -L $DATA_ROOT/$release/$db_name ]] || die 'existing release bundle incomplete'
    existing=$(sha256sum "$DATA_ROOT/$release/$db_name"); existing=${existing%% *}
    [[ $existing == "$digest" ]] || die 'existing release digest mismatch'
    grep -Fqx "sha256:  $digest  ($db_name, $(stat -c '%s' "$DATA_ROOT/$release/$db_name") bytes)" "$DATA_ROOT/$release/$prov_name" || die 'existing release provenance mismatch'
    [[ $(validate "$DATA_ROOT/$release") == "$epoch" ]] || die 'existing release metadata mismatch'
else
    printf '%s\n' "$epoch" > "$candidate/build_epoch"
    chmod 0444 "$candidate/$db_name" "$candidate/$prov_name" "$candidate/build_epoch"
    chmod 0555 "$candidate"
    mv -T "$candidate" "$DATA_ROOT/$release"
fi
switch_to() {
    local link
    link=$(mktemp -u "$DATA_ROOT/.current.XXXXXXXX")
    ln -s "$1" "$link" || return $?
    mv -Tf "$link" "$DATA_ROOT/current" || {
        local status=$?
        rm -f -- "$link"
        return "$status"
    }
}
same_app() {
    local now
    now=$(snapshot) || return 1
    [[ $now == "$app_id|$image_id|"* ]]
}
ready() {
    local attempt health
    for ((attempt=0; attempt<30; attempt++)); do
        same_app || return 1
        [[ $(snapshot) == *'|1' ]] || return 1
        health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$app_id") || return 1
        if [[ $health == healthy ]] && curl -fsS --max-time 2 "$READY_URL" >/dev/null; then
            return 0
        fi
        sleep 2
    done
    return 1
}
restart_ready() {
    local before after before_start
    before=$(snapshot) || return 1
    [[ $before == "$app_id|$image_id|"* ]] || return 1
    before_start=${before#"$app_id|$image_id|"}; before_start=${before_start%|*}
    docker restart "$app_id" >/dev/null || return $?
    after=$(snapshot) || return 1
    [[ $after == "$app_id|$image_id|"* && $after == *'|1' && $after != "$app_id|$image_id|$before_start|"* ]] || return 1
    ready
}
active=false
activated=false
finish() {
    status=$?
    trap - EXIT INT TERM
    if $active; then
        if ! $activated && [[ $(readlink "$DATA_ROOT/current") == "$old" ]]; then
            echo 'GeoIP refresh: activation was not committed; previous dataset unchanged' >&2
        elif same_app && [[ $(readlink "$DATA_ROOT/current") == "$release" ]] &&
           switch_to "$old" && restart_ready; then
            echo "GeoIP refresh: activation failed; rollback verified sha256=$old_digest" >&2
        else
            echo 'GeoIP refresh: CRITICAL rollback could not be verified; preserve releases and inspect exact app' >&2
        fi
        [[ $status != 0 ]] || status=1
    fi
    cleanup_candidate || status=1
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[[ $(snapshot) == "$initial" ]] || die 'app changed before activation'
active=true
switch_to "$release"
activated=true
restart_ready
active=false
echo "GeoIP refresh: activated sha256=$digest build_epoch=$epoch app=$app_id"
