#!/bin/sh
# FR-90 P2h-1 — the archive replica image's entrypoint (Dockerfile.hive-archive):
# enroll once, then run.
#
# The first start, with no config on the volume, enrolls with an
# ADMINISTRATOR's enrollment token (single use, 10 minutes) as an archive
# replica: `roomlerd enroll --archive-replica` writes the replica's posture with
# the enrolled config. Every later start runs from the volume, and needs no token.
#
#   MESHHARBOR_SERVER        the Roomler server to enroll against (first start only)
#   MESHHARBOR_ENROLL_TOKEN  an ADMINISTRATOR's enrollment token (first start only;
#                         never an ephemeral key's: an ephemeral device is deleted
#                         once it falls silent)
#   MESHHARBOR_NAME          the device's name in the org (default: the hostname)
#   MESHHARBOR_DATA          the volume (default /data)
#
# ⚠️ The token is never printed, and a failed enrollment writes nothing: the
# next start tries again with a new token.
set -eu

data="${MESHHARBOR_DATA:-/data}"
config="$data/config.toml"

if [ ! -s "$config" ]; then
    : "${MESHHARBOR_SERVER:?is required on the first start: the Roomler server to enroll against}"
    : "${MESHHARBOR_ENROLL_TOKEN:?is required on the first start: an ADMINISTRATOR's enrollment token}"
    name="${MESHHARBOR_NAME:-${HOSTNAME:-$(cat /proc/sys/kernel/hostname)}}"
    echo "hive-archive: enrolling '$name' against $MESHHARBOR_SERVER as an archive replica"
    roomlerd --config "$config" enroll \
        --server "$MESHHARBOR_SERVER" \
        --token "$MESHHARBOR_ENROLL_TOKEN" \
        --name "$name" \
        --archive-replica \
        --install-method container \
        --install-scope system
fi

exec roomlerd --config "$config" run
