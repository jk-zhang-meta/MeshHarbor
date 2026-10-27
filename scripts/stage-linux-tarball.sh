#!/usr/bin/env sh
# RETIRED-NAME-ANCHOR-BEGIN
# FR-46: the ARCHIVE name is now `roomlerd-…`. Every consumer was measured first —
# the extractor uses `--strip-components=1` so the internal dir name is inert, and no
# picker keys on the prefix. What stays frozen here is `usr/lib/meshharbor` (the
# RPATH baked into the shipped binary by patchelf, which must move in lockstep with
# it, not before) and `usr/share/doc/meshharbor`. docs/fr/FR-46
# Stage the Linux payload and tar it — the distro-agnostic install path for
# hosts with no dpkg/apt (Fedora, RHEL, SUSE, Arch …), which otherwise cannot
# install ANY published artifact and so can never self-update.
#
# The tree MUST mirror the `.deb` asset map in agents/roomlerd/Cargo.toml:
# same payload, same destinations, so the two formats install identically and
# `docs/linux-self-update.md`'s installer can be format-agnostic below the
# extraction. Run from the repo root, AFTER the lane's bundle step has
# populated agents/roomlerd/vendor-ffmpeg/.
#
# Usage: scripts/stage-linux-tarball.sh <version> <target-triple>
#   e.g. scripts/stage-linux-tarball.sh 0.3.0-rc.371 x86_64-unknown-linux-gnu
set -eu

version="${1:?version}"
triple="${2:?target triple}"
name="meshharbor-${version}-${triple}"
root="/tmp/${name}"

pkg=agents/roomlerd
rm -rf "$root"

# Binaries. `roomler-shim` installs UNDER the user-facing name: it re-execs
# `roomlerd cli`, so a stale shim can never version-skew from the daemon.
install -D -m755 target/release/meshharbord    "$root/usr/bin/meshharbord"
install -D -m755 target/release/roomler-shim "$root/usr/bin/meshharbor"

# Bundled libs (FFmpeg on x86_64, libvpx everywhere) — the payload is
# self-contained by design: stock distros ship ABI-incompatible versions, and
# the binary's RPATH points at this directory.
libs=0
for lib in "$pkg"/vendor-ffmpeg/*.so.*; do
    [ -e "$lib" ] || break
    # RETIRED-NAME-ANCHOR(2): RPATH directory baked into the binary; the
    # staged tree must match it or the tarball cannot load its own FFmpeg.
    install -D -m644 "$lib" "$root/usr/lib/meshharbor/$(basename "$lib")"
    libs=$((libs + 1))
done
if [ "$libs" -eq 0 ] && [ -z "${HEADLESS:-}" ]; then
    echo "::error::no bundled libs staged — run the lane's bundle step first" >&2
    exit 1
fi

# Units ship in the tarball but the INSTALLER only writes them when absent —
# an upgrade must never revert a unit the operator edited.
install -D -m644 "$pkg/packaging/linux/meshharbord.service" "$root/usr/lib/systemd/system/meshharbord.service"
install -D -m644 "$pkg/packaging/linux/meshharbor.service"  "$root/usr/lib/systemd/user/meshharbor.service"
# FR-96 — the update half of a per-user install (disabled until install.sh enables it).
for u in meshharbor-update.service meshharbor-update.timer meshharbor-update.path; do
    install -D -m644 "$pkg/packaging/linux/$u" "$root/usr/lib/systemd/system/$u"
done
install -D -m644 "$pkg/packaging/linux/README.Debian"    "$root/usr/share/doc/meshharbor/README.Debian"

# ⚠️ Files only, owned by root in the archive. A plain `tar czf` of the tree
# records every DIRECTORY too (usr/, usr/bin/, usr/lib/ …) with the builder's
# own uid (1001 on the CI runner). Extracting as root restores the archive's
# owner, and GNU tar applies a directory entry's metadata to a directory that
# already exists. Up to 0.4.126, install.sh's `sudo tar -C /` therefore made
# /usr, /usr/bin and /usr/lib the property of whichever local account held uid
# 1001. With no directory entries, extraction creates only missing parents,
# root's, and never touches an existing directory.
(cd /tmp && find "$name" \( -type f -o -type l \) -print | LC_ALL=C sort \
    | tar --owner=0 --group=0 --numeric-owner --no-recursion -czf "${name}.tar.gz" -T -)
mv "/tmp/${name}.tar.gz" .
sha256sum "${name}.tar.gz" | awk '{print $1"  "$2}' > "${name}.tar.gz.sha256"

echo "staged ${libs} lib(s); $(du -h "${name}.tar.gz" | cut -f1) -> ${name}.tar.gz"
tar tzf "${name}.tar.gz" | sed "s|^|  |"
# RETIRED-NAME-ANCHOR-END
