#!/usr/bin/env bash
#
# fr97-caps-census.sh — FR-97 P0d: count the fleet's capability words by OS (and
# by native architecture, from agents new enough to report it). READ-ONLY.
#
# What a device advertises in its hello (`AgentCaps`) is a promise; FR-97 P0c
# removes the words an OS cannot keep. This is the count that shows it: AC15 asks
# for one taken before P0c ships and one after the last phase, with no word
# left on an OS that cannot serve it.
#
# Run on the build host, where kubectl reaches the cluster:
#   scripts/fr97-caps-census.sh [days]      # agents seen in the last N days (30)
#
# The database URL is read from the roomler2 pod's environment and handed to
# mongosh in mongodb-0 over stdin: it is never printed, and it never appears in
# an argument list on the build host. Only counts come out: no names, no ids.
set -euo pipefail
NS="${MESHHARBOR_NS:-roomler-ai}"
DAYS="${1:-30}"
case "$DAYS" in '' | *[!0-9]*) echo "days must be a number" >&2; exit 2 ;; esac

url="$(kubectl -n "$NS" exec deploy/roomler2 -- printenv MESHHARBOR__DATABASE__URL)"
name="$(kubectl -n "$NS" exec deploy/roomler2 -- printenv MESHHARBOR__DATABASE__NAME)"
[ -n "$url" ] || { echo "could not read the database URL" >&2; exit 3; }
case "$name" in '' | *[!A-Za-z0-9_-]*) echo "unexpected database name" >&2; exit 3 ;; esac

# The aggregation. Agents not tombstoned and seen within the window; one row per
# (list, OS, word). `arch` is the native architecture the hello carries since
# FR-97 P0d; older agents read "unreported".
js="$(cat <<EOF
const db2 = db.getSiblingDB("${name}");
const since = new Date(Date.now() - ${DAYS} * 86400 * 1000);
const live = { deleted_at: null, last_seen_at: { \$gte: since } };
print("# agents seen in the last ${DAYS} days, not removed");
db2.agents.aggregate([
  { \$match: live },
  { \$group: { _id: { os: "\$os", arch: { \$ifNull: ["\$arch", "unreported"] } }, n: { \$sum: 1 } } },
  { \$sort: { "_id.os": 1, "_id.arch": 1 } },
]).forEach(r => print(["agents", r._id.os, r._id.arch, r.n].join("\t")));
const lists = ["audio", "clipboard", "input", "apps", "layout", "files", "video",
  "transports", "codecs", "hw_encoders", "permissions", "multi_org", "rpc"];
for (const f of lists) {
  db2.agents.aggregate([
    { \$match: live },
    { \$unwind: "\$capabilities." + f },
    { \$group: { _id: { os: "\$os", w: "\$capabilities." + f }, n: { \$sum: 1 } } },
    { \$sort: { "_id.os": 1, "_id.w": 1 } },
  ]).forEach(r => print([f, r._id.os, r._id.w, r.n].join("\t")));
}
// FR-97 P0c — the honest "no": each withheld feature as key:code.
db2.agents.aggregate([
  { \$match: live },
  { \$project: { os: 1, u: { \$objectToArray: { \$ifNull: ["\$capabilities.unavailable", {}] } } } },
  { \$unwind: "\$u" },
  { \$group: { _id: { os: "\$os", w: { \$concat: ["\$u.k", ":", { \$ifNull: ["\$u.v.code", "?"] }] } }, n: { \$sum: 1 } } },
  { \$sort: { "_id.os": 1, "_id.w": 1 } },
]).forEach(r => print(["unavailable", r._id.os, r._id.w, r.n].join("\t")));
for (const b of ["supports_clipboard", "supports_file_transfer", "has_input_permission"]) {
  db2.agents.aggregate([
    { \$match: Object.assign({}, live, { ["capabilities." + b]: true }) },
    { \$group: { _id: "\$os", n: { \$sum: 1 } } },
    { \$sort: { _id: 1 } },
  ]).forEach(r => print([b, r._id, "true", r.n].join("\t")));
}
EOF
)"

# First stdin line: the URL (read by sh, never echoed); the rest: the script.
{ printf '%s\n' "$url"; printf '%s\n' "$js"; } |
  kubectl -n "$NS" exec -i mongodb-0 -- sh -c 'IFS= read -r u; exec mongosh --quiet "$u" --file /dev/stdin' |
  { printf 'list\tos\tword\tcount\n'; cat; }
