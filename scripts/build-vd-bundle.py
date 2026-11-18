#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""FR-120 P3 — build the virtual-desktop runtime the Linux packages carry.

A headless host whose account cannot install packages still gets a desktop on
Connect: the daemon starts this bundle's X server (`virtual_desktop::Bundle`).
The bundle is assembled from Ubuntu 20.04 (focal) binary packages, so it needs
glibc 2.31 or newer and nothing else from the host:

    vd/bin/{Xvfb,xkbcomp,twm,xterm}
    vd/lib/       every shared library they need except glibc's own
    vd/share/X11/{xkb,locale}   keymaps, libX11's locale data
    vd/share/fonts     DejaVu Sans Mono, for the terminal
    vd/share/doc/<package>/copyright

Every binary and library gets a RUNPATH ($ORIGIN/../lib, $ORIGIN), so nothing
is put on LD_LIBRARY_PATH, which would leak into every program started from
the desktop's terminal.

Xvfb runs `<XkbBinDirectory>/xkbcomp` to compile its keymap, and that
directory is compiled in as /usr/bin, which a bare host lacks. The bundle
rewrites that one string to "." and the daemon starts Xvfb with `bin/` as its
working directory, so it runs the bundle's own xkbcomp.

Usage: build-vd-bundle.py <amd64|arm64> <out>/meshharbor-vd.so.tar.xz

The package carries the result as usr/lib/meshharbor/meshharbor-vd.so.tar.xz
(one file: see `virtual_desktop::Bundle` for why), unpacked by the daemon.
"""

import hashlib
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

MIRRORS = {
    "amd64": "http://archive.ubuntu.com/ubuntu",
    "arm64": "http://ports.ubuntu.com/ubuntu-ports",
}
TRIPLETS = {"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}
SUITES = ["focal", "focal-updates"]  # later suites win
COMPONENTS = ["main", "universe"]
ROOTS = ["xvfb", "x11-xkb-utils", "twm", "xterm", "xkb-data"]
BINARIES = {"Xvfb": "usr/bin/Xvfb", "xkbcomp": "usr/bin/xkbcomp",
            "twm": "usr/bin/twm", "xterm": "usr/bin/xterm"}
# Never followed: the host provides them, or they are not code we run.
SKIP_PACKAGES = {
    "libc6", "libgcc-s1", "libgcc1", "libcrypt1", "debconf", "dpkg", "perl-base",
    "lsb-base", "x11-common", "xserver-common", "libgl1-mesa-dri", "libglx-mesa0",
    "libllvm10", "libllvm11", "libllvm12", "xbitmaps", "xauth", "libdrm-common",
}
# glibc's own libraries come from the host, always.
GLIBC = re.compile(r"^(libc|libm|libdl|libpthread|librt|libutil|libresolv|libanl|"
                   r"libnsl|libBrokenLocale|ld-linux[-a-z0-9_]*)\.so(\.\d+)*$")


def fetch(url: str) -> bytes:
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 — a mirror hiccup, retried
            if attempt == 3:
                raise
            print(f"retry {url}: {e}", file=sys.stderr)
    raise AssertionError


def packages_index(arch: str) -> dict:
    pkgs: dict = {}
    for suite in SUITES:
        for comp in COMPONENTS:
            url = f"{MIRRORS[arch]}/dists/{suite}/{comp}/binary-{arch}/Packages.xz"
            text = lzma.decompress(fetch(url)).decode("utf-8", "replace")
            for stanza in text.split("\n\n"):
                fields = {}
                key = None
                for line in stanza.splitlines():
                    if line.startswith((" ", "\t")) and key:
                        fields[key] += "\n" + line
                    elif ":" in line:
                        key, _, val = line.partition(":")
                        fields[key] = val.strip()
                if "Package" in fields:
                    pkgs[fields["Package"]] = fields
    return pkgs


def depends(fields: dict) -> list:
    out = []
    for key in ("Pre-Depends", "Depends"):
        for alt in filter(None, (d.strip() for d in fields.get(key, "").split(","))):
            out.append([re.split(r"[ (:]", a.strip())[0] for a in alt.split("|")])
    return out


def closure(pkgs: dict) -> list:
    seen, todo = [], list(ROOTS)
    while todo:
        name = todo.pop()
        if name in seen or name in SKIP_PACKAGES:
            continue
        if name not in pkgs:
            raise SystemExit(f"package {name} not in the index")
        seen.append(name)
        for alts in depends(pkgs[name]):
            pick = next((a for a in alts if a in pkgs or a in SKIP_PACKAGES), None)
            if pick is None:
                print(f"note: {name}: no candidate for {alts}", file=sys.stderr)
                continue
            todo.append(pick)
    return seen


def needed(path: str) -> list:
    out = subprocess.run(["readelf", "-d", path], capture_output=True, text=True).stdout
    return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", out)


def main() -> None:
    arch, out_path = sys.argv[1], os.path.abspath(sys.argv[2])
    triplet = TRIPLETS[arch]
    pkgs = packages_index(arch)
    names = closure(pkgs)
    print(f"{len(names)} packages: {' '.join(sorted(names))}")
    work = tempfile.mkdtemp(prefix=f"vd-bundle-{arch}-")
    stage = os.path.join(work, "stage")
    os.makedirs(stage)
    for name in names:
        f = pkgs[name]
        data = fetch(f"{MIRRORS[arch]}/{f['Filename']}")
        if hashlib.sha256(data).hexdigest() != f["SHA256"]:
            raise SystemExit(f"{name}: SHA256 mismatch")
        deb = os.path.join(work, os.path.basename(f["Filename"]))
        with open(deb, "wb") as fh:
            fh.write(data)
        subprocess.run(["dpkg-deb", "-x", deb, stage], check=True)
        os.remove(deb)

    vd = os.path.join(work, "vd")
    for d in ("bin", "lib", "share/X11", "share/doc"):
        os.makedirs(os.path.join(vd, d))
    for name, rel in BINARIES.items():
        shutil.copy2(os.path.join(stage, rel), os.path.join(vd, "bin", name))

    # Every library the binaries need, transitively, except glibc's.
    lib_dirs = [os.path.join(stage, p) for p in
                (f"usr/lib/{triplet}", f"lib/{triplet}", "usr/lib", "lib")]
    todo = [os.path.join(vd, "bin", b) for b in BINARIES]
    done = set()
    while todo:
        for so in needed(todo.pop()):
            if so in done or GLIBC.match(so):
                continue
            src = next((os.path.join(d, so) for d in lib_dirs
                        if os.path.exists(os.path.join(d, so))), None)
            if src is None:
                raise SystemExit(f"no package in the closure provides {so}")
            dst = os.path.join(vd, "lib", so)
            shutil.copyfile(os.path.realpath(src), dst)
            done.add(so)
            todo.append(dst)
    for b in BINARIES:
        subprocess.run(["patchelf", "--set-rpath", "$ORIGIN/../lib",
                        os.path.join(vd, "bin", b)], check=True)
    for so in done:
        subprocess.run(["patchelf", "--set-rpath", "$ORIGIN",
                        os.path.join(vd, "lib", so)], check=True)

    # Xvfb: XkbBinDirectory "/usr/bin" -> "." (see the module docstring).
    xvfb = os.path.join(vd, "bin", "Xvfb")
    blob = open(xvfb, "rb").read()
    hits = [m.start() for m in re.finditer(rb"(?<=\x00)/usr/bin\x00", blob)]
    if len(hits) != 1:
        raise SystemExit(f"Xvfb: expected one '/usr/bin' string, found {len(hits)}")
    blob = blob[:hits[0]] + b".\x00\x00\x00\x00\x00\x00\x00" + blob[hits[0] + 8:]
    with open(xvfb, "wb") as fh:
        fh.write(blob)

    shutil.copytree(os.path.join(stage, "usr/share/X11/xkb"),
                    os.path.join(vd, "share/X11/xkb"), symlinks=True)
    # libX11's locale database: a bare host has none, and the daemon points
    # XLOCALEDIR here only when the host lacks its own.
    shutil.copytree(os.path.join(stage, "usr/share/X11/locale"),
                    os.path.join(vd, "share/X11/locale"), symlinks=True)
    # A readable terminal font: X's built-in "fixed" is 6x13 pixels, unreadable
    # on a 1920x1080 desktop. The daemon points fontconfig here only when the
    # host has no configuration of its own.
    os.makedirs(os.path.join(vd, "share/fonts"))
    for ttf in ("DejaVuSansMono.ttf", "DejaVuSansMono-Bold.ttf"):
        shutil.copy2(os.path.join(stage, "usr/share/fonts/truetype/dejavu", ttf),
                     os.path.join(vd, "share/fonts", ttf))
    for name in names:
        cp = os.path.join(stage, "usr/share/doc", name, "copyright")
        if os.path.isfile(cp):
            os.makedirs(os.path.join(vd, "share/doc", name))
            shutil.copy2(cp, os.path.join(vd, "share/doc", name, "copyright"))
    with open(os.path.join(vd, "share/doc/SOURCES"), "w") as fh:
        for name in sorted(names):
            fh.write(f"{name} {pkgs[name]['Version']} {arch} (Ubuntu focal)\n")

    with tarfile.open(out_path, "w:xz") as tar:
        tar.add(vd, arcname="vd")
    shutil.rmtree(work)
    print(f"wrote {out_path} ({os.path.getsize(out_path) // 1024} KiB), "
          f"{len(done)} libraries")


if __name__ == "__main__":
    main()
