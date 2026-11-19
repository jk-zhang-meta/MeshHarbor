#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""FR-120 P4 — build the embedded desktop: Xfce 4.20 on its own glibc.

The Linux packages carry this as ONE file, usr/lib/meshharbor/meshharbor-vd.so.tar.xz
(see `virtual_desktop::Bundle` for why one file), which the daemon unpacks.
Every host, root or not, any glibc, then gets the same full desktop.

Built from Debian 13 (trixie) binary packages, glibc INCLUDED: every program
runs through the bundle's own dynamic loader,

    root/usr/lib/<triplet>/ld-linux-*.so.* --library-path <libs>
        --preload lib/mhvd-shim.so --argv0 <name> root/usr/bin/<name>

started by a wrapper in bin/. `mhvd-shim.c` keeps the bundle out of every
host program the desktop starts (it restores the host environment on exec)
and redirects the desktop's compiled-in /usr paths to the bundle.

Layout:
    vd/bin/          wrappers (ELF programs) and links (scripts)
    vd/lib/          mhvd-shim.so
    vd/root/usr/...  the packages' files; root/etc/{xdg,fonts}
    vd/etc/          templates (D-Bus session config)
    vd/relocate.list files whose @MHVD_ROOT@ the daemon replaces on unpack
    vd/DESKTOP       marker: this bundle carries a full desktop

Usage: build-desktop-bundle.py <outdir>   (writes meshharbor-vd-{amd64,arm64}.tar.xz)
Runs on an amd64 Debian/Ubuntu host with gcc and gcc-aarch64-linux-gnu: the
generated files (schemas, pixbuf loader cache, zh_CN locale, and every cache a
package's trigger builds on a real system: the MIME database, the icon theme
caches, the GIO module cache, the desktop-file MIME cache, the GTK input
method cache) are made by the amd64 bundle's own tools and reused for arm64,
whose formats are the same. dpkg never runs here, so nothing else would make
them, and a host's own copies must never be what makes the desktop work.
"""

import hashlib
import lzma
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ARCHES = {
    "amd64": ("x86_64-linux-gnu", "ld-linux-x86-64.so.2", "gcc"),
    "arm64": ("aarch64-linux-gnu", "ld-linux-aarch64.so.1", "aarch64-linux-gnu-gcc"),
}
REPOS = [
    ("http://deb.debian.org/debian", "trixie"),
    ("http://deb.debian.org/debian", "trixie-updates"),
    ("http://security.debian.org/debian-security", "trixie-security"),
]
ROOTS = [
    # X server + keymaps
    "xvfb", "x11-xkb-utils", "xkb-data",
    # Xfce 4.20
    "xfce4-session", "xfwm4", "xfdesktop4", "xfce4-panel", "xfce4-settings",
    "xfconf", "thunar", "xfce4-terminal", "xfce4-whiskermenu-plugin",
    "xfce4-appfinder", "xfce4-taskmanager", "xfce4-notifyd", "mousepad",
    "ristretto", "exo-utils", "libxfce4ui-utils",
    # session bus
    "dbus-daemon", "dbus-x11", "dbus-session-bus-common",
    # look: icons, theme, fonts, SVG icons, MIME
    "elementary-xfce-icon-theme", "adwaita-icon-theme", "hicolor-icon-theme",
    "greybird-gtk-theme", "fonts-wqy-microhei", "fonts-dejavu-core",
    "librsvg2-common", "shared-mime-info",
    # build-time tools (schemas, pixbuf cache, locales), removed afterwards
    "libglib2.0-bin", "libgdk-pixbuf2.0-bin", "libc-bin", "locales",
]
BUILD_ONLY_DIRS = ["usr/share/i18n"]
# Dependencies never followed: init, packaging, accounts, services that make
# no sense in a desktop a daemon starts, and the heavy GPU stack.
SKIP = {
    "perl-base", "perl", "perl-modules-5.40", "debconf", "dpkg", "ucf",
    "sensible-utils", "coreutils", "dash", "bash", "util-linux", "mount",
    "sysvinit-utils", "procps", "base-files", "base-passwd", "lsb-base",
    "adduser", "passwd", "login", "init-system-helpers", "systemd",
    "systemd-sysv", "libpam-systemd", "udev", "polkitd", "pkexec",
    "at-spi2-core", "xdg-user-dirs", "tumbler", "dbus-user-session",
    "dbus-system-bus-common", "dbus", "xauth", "x11-common", "xserver-common",
    "libgl1-mesa-dri", "mesa-libgallium", "libglx-mesa0", "desktop-base",
    "xfce4-power-manager", "light-locker", "xfce4-screensaver", "xscreensaver",
    "gvfs", "gvfs-backends", "gvfs-daemons", "udisks2", "upower", "colord",
    "policykit-1", "libpam-modules", "libpam-modules-bin", "libpam-runtime",
    "python3", "pinentry-curses", "gnupg", "xfonts-base", "debianutils",
    "media-types", "tzdata", "netbase", "readline-common",
}
KEEP_LOCALES = {"zh_CN"}
# The hidpi variant alone is 57 MiB unpacked; a virtual display is 96 dpi.
DROP_ICON_THEMES = {"elementary-xfce-dark", "elementary-xfce-darker", "elementary-xfce-darkest",
                    "elementary-xfce-hidpi"}


def fetch(url):
    # A mirror drops connections now and then (RemoteDisconnected mid-build,
    # 2026-11-19): back off and try again rather than lose the whole build.
    for i in range(8):
        try:
            with urllib.request.urlopen(url, timeout=180) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            if i == 7:
                raise
            print(f"retry {i + 1} {url}: {e}", file=sys.stderr)
            time.sleep(min(60, 2 ** i))


def index(arch):
    pkgs = {}
    for base, suite in REPOS:
        for comp in ["main"]:
            url = f"{base}/dists/{suite}/{comp}/binary-{arch}/Packages.xz"
            try:
                text = lzma.decompress(fetch(url)).decode("utf-8", "replace")
            except Exception as e:  # noqa: BLE001
                print(f"note: {url}: {e}", file=sys.stderr)
                continue
            for st in text.split("\n\n"):
                f, key = {}, None
                for line in st.splitlines():
                    if line.startswith((" ", "\t")) and key:
                        f[key] += "\n" + line
                    elif ":" in line:
                        key, _, v = line.partition(":")
                        f[key] = v.strip()
                if "Package" in f:
                    f["_base"] = base
                    pkgs[f["Package"]] = f  # later repos (updates, security) win
                    for prov in f.get("Provides", "").split(","):
                        p = re.split(r"[ (]", prov.strip())[0]
                        if p:
                            pkgs.setdefault("@" + p, f)
    return pkgs


def deps(f):
    out = []
    for key in ("Pre-Depends", "Depends"):
        for alt in filter(None, (d.strip() for d in f.get(key, "").split(","))):
            out.append([re.split(r"[ (:]", a.strip())[0] for a in alt.split("|")])
    return out


def closure(pkgs):
    seen, todo = {}, list(ROOTS)
    while todo:
        name = todo.pop()
        if name in SKIP or name in seen:
            continue
        f = pkgs.get(name) or pkgs.get("@" + name)
        if f is None:
            print(f"note: no package for {name}", file=sys.stderr)
            continue
        real = f["Package"]
        if real in seen or real in SKIP:
            continue
        seen[real] = f
        for alts in deps(f):
            pick = next((a for a in alts if a in SKIP or a in pkgs or ("@" + a) in pkgs), None)
            if pick:
                todo.append(pick)
    return seen


def is_elf(p):
    try:
        with open(p, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def extract(arch, pkgs, stage):
    os.makedirs(stage)
    for name, f in sorted(pkgs.items()):
        data = fetch(f"{f['_base']}/{f['Filename']}")
        if hashlib.sha256(data).hexdigest() != f["SHA256"]:
            raise SystemExit(f"{name}: SHA256 mismatch")
        deb = os.path.join(stage, "..", f"{name}.deb")
        with open(deb, "wb") as fh:
            fh.write(data)
        subprocess.run(["dpkg-deb", "-x", deb, stage], check=True)
        os.remove(deb)


def assemble(arch, stage, vd, pkgs):
    triplet, ldso, cc = ARCHES[arch]
    root = os.path.join(vd, "root")
    os.makedirs(root)
    for top in ("usr", "etc"):
        if os.path.isdir(os.path.join(stage, top)):
            shutil.copytree(os.path.join(stage, top), os.path.join(root, top), symlinks=True)
    # Trim what a desktop never reads.
    for rel in ["usr/share/doc", "usr/share/man", "usr/share/info", "usr/share/lintian",
                "usr/share/bug", "usr/share/gtk-doc", "usr/share/help", "usr/include",
                "usr/share/bash-completion", "usr/share/zsh", "usr/lib/systemd",
                "usr/lib/aspell", "usr/lib/emacsen-common", "usr/lib/python3",
                "usr/share/emacsen-common", "usr/share/aspell", "usr/share/doc-base",
                "usr/share/python3", "usr/share/perl5", "usr/share/applications/screensavers",
                "etc/init.d", "etc/systemd", "etc/default", "etc/cron.d", "etc/logrotate.d"]:
        shutil.rmtree(os.path.join(root, rel), ignore_errors=True)
    loc = os.path.join(root, "usr/share/locale")
    if os.path.isdir(loc):
        for d in os.listdir(loc):
            if os.path.isdir(os.path.join(loc, d)) and d not in KEEP_LOCALES:
                shutil.rmtree(os.path.join(loc, d))
    icons = os.path.join(root, "usr/share/icons")
    for d in DROP_ICON_THEMES:
        shutil.rmtree(os.path.join(icons, d), ignore_errors=True)
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if fn.endswith((".a", ".la", ".pc", ".h")):
                os.remove(os.path.join(dirpath, fn))

    # Absolute symlinks (fontconfig's conf.d, locale.alias) would point into
    # the HOST: make every one whose target the bundle carries relative.
    for dirpath, dirs, files in os.walk(root):
        for fn in dirs + files:
            p = os.path.join(dirpath, fn)
            t = os.readlink(p) if os.path.islink(p) else ""
            if t.startswith("/") and os.path.lexists(root + t):
                os.remove(p)
                os.symlink(os.path.relpath(root + t, dirpath), p)
    # Autostart entries that hand the program to systemd first
    # (`systemctl --user start x.service || exec /usr/lib/...`) would start
    # the HOST's unit, outside this session: run the program itself.
    adir = os.path.join(root, "etc/xdg/autostart")
    for fn in sorted(os.listdir(adir)) if os.path.isdir(adir) else []:
        f = os.path.join(adir, fn)
        text = open(f).read()
        fixed = re.sub(r'^Exec=sh -c "systemctl --user start \S+ 2>/dev/null \|\| exec ([^"]+)"$',
                       r"Exec=\1", text, flags=re.M)
        if fixed != text:
            with open(f, "w") as fh:
                fh.write(fixed)

    ld = f"usr/lib/{triplet}/{ldso}"
    if not os.path.exists(os.path.join(root, ld)):
        raise SystemExit(f"{arch}: no dynamic loader at {ld}")
    # Library path: the standard dirs plus every RUNPATH a bundled ELF names.
    libdirs = [f"usr/lib/{triplet}", "usr/lib"]
    for dirpath, _, files in os.walk(os.path.join(root, "usr")):
        for fn in files:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p) or not is_elf(p):
                continue
            out = subprocess.run(["readelf", "-d", p], capture_output=True, text=True).stdout
            for m in re.findall(r"(?:RUNPATH|RPATH)\)\s+Library r(?:un)?path: \[([^\]]+)\]", out):
                for d in m.split(":"):
                    if d.startswith("/usr/"):
                        d = d[1:]
                        if d not in libdirs and os.path.isdir(os.path.join(root, d)):
                            libdirs.append(d)

    # Wrappers for every program in usr/bin and usr/sbin.
    bindir = os.path.join(vd, "bin")
    os.makedirs(bindir)
    libpath = ":".join("$MHVD_ROOT/" + d for d in libdirs)
    for sub in ("usr/bin", "usr/sbin"):
        d = os.path.join(root, sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if not os.path.isfile(p) or os.path.exists(os.path.join(bindir, fn)):
                continue
            target = os.path.realpath(p)
            if is_elf(target):
                rel = os.path.relpath(target, root)
                w = os.path.join(bindir, fn)
                with open(w, "w") as fh:
                    fh.write(WRAPPER.format(ld=ld, libpath=libpath, rel=rel))
                os.chmod(w, 0o755)
            else:
                os.symlink(os.path.relpath(p, bindir), os.path.join(bindir, fn))

    # The shim, for this architecture.
    os.makedirs(os.path.join(vd, "lib"))
    subprocess.run([cc, "-O2", "-Wall", "-fPIC", "-shared", "-Wno-nonnull-compare", "-o",
                    os.path.join(vd, "lib/mhvd-shim.so"), os.path.join(HERE, "mhvd-shim.c"),
                    "-ldl"], check=True)

    # Xvfb runs <XkbBinDirectory>/xkbcomp, compiled in as /usr/bin: point it
    # at its working directory, which the daemon makes bin/ (the wrapper).
    xvfb = os.path.join(root, "usr/bin/Xvfb")
    blob = open(xvfb, "rb").read()
    hits = [m.start() for m in re.finditer(rb"(?<=\x00)/usr/bin\x00", blob)]
    if len(hits) != 1:
        raise SystemExit(f"Xvfb: expected one '/usr/bin' string, found {len(hits)}")
    blob = blob[:hits[0]] + b".\x00\x00\x00\x00\x00\x00\x00" + blob[hits[0] + 8:]
    with open(xvfb, "wb") as fh:
        fh.write(blob)

    # D-Bus session config template.
    os.makedirs(os.path.join(vd, "etc"))
    with open(os.path.join(vd, "etc/session.conf"), "w") as fh:
        fh.write(SESSION_CONF)
    with open(os.path.join(vd, "DESKTOP"), "w") as fh:
        fh.write("xfce4-session\n")
    with open(os.path.join(vd, "ENV"), "w") as fh:
        fh.write(f"TRIPLET={triplet}\nLD={ld}\nLIBS={':'.join(libdirs)}\n")
    # Provenance and licenses.
    os.makedirs(os.path.join(vd, "share/doc"), exist_ok=True)
    with open(os.path.join(vd, "share/doc/SOURCES"), "w") as fh:
        for name in sorted(pkgs):
            fh.write(f"{name} {pkgs[name]['Version']} {arch} (Debian trixie)\n")
    for name in pkgs:
        cp = os.path.join(stage, "usr/share/doc", name, "copyright")
        if os.path.isfile(cp):
            os.makedirs(os.path.join(vd, "share/doc", name), exist_ok=True)
            shutil.copy2(cp, os.path.join(vd, "share/doc", name, "copyright"))
    return root, triplet, ld, libdirs


def run_bundled(vd, root, ld, libdirs, prog, args, env=None):
    libs = ":".join(os.path.join(root, d) for d in libdirs)
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([os.path.join(root, ld), "--library-path", libs,
                           os.path.join(root, prog)] + args, check=True,
                          capture_output=True, text=True, env=e)


def generate(vd, root, triplet, ld, libdirs):
    """Schemas, pixbuf loader cache, zh_CN locale — with the bundle's tools."""
    gen = {}
    schemas = os.path.join(root, "usr/share/glib-2.0/schemas")
    run_bundled(vd, root, ld, libdirs, "usr/lib/" + triplet + "/glib-2.0/glib-compile-schemas"
                if os.path.exists(os.path.join(root, "usr/lib", triplet, "glib-2.0/glib-compile-schemas"))
                else "usr/bin/glib-compile-schemas", [schemas])
    gen["schemas"] = open(os.path.join(schemas, "gschemas.compiled"), "rb").read()
    ldir = os.path.join(root, "usr/lib", triplet, "gdk-pixbuf-2.0/2.10.0")
    loaders = sorted(os.path.join(ldir, "loaders", f) for f in os.listdir(os.path.join(ldir, "loaders"))
                     if f.endswith(".so"))
    q = os.path.join(root, "usr/lib", triplet, "gdk-pixbuf-2.0/gdk-pixbuf-query-loaders")
    qrel = os.path.relpath(q, root) if os.path.exists(q) else "usr/bin/gdk-pixbuf-query-loaders"
    out = run_bundled(vd, root, ld, libdirs, qrel, loaders).stdout
    gen["pixbuf"] = out.replace(root, "@MHVD_ROOT@")
    locdir = os.path.join(root, "usr/lib/locale")
    os.makedirs(locdir, exist_ok=True)
    run_bundled(vd, root, ld, libdirs, "usr/bin/localedef",
                ["--no-archive", "-i", "zh_CN", "-f", "UTF-8",
                 os.path.join(locdir, "zh_CN.UTF-8")],
                env={"I18NPATH": os.path.join(root, "usr/share/i18n")})
    gen["locale"] = os.path.join(locdir, "zh_CN.UTF-8")
    gen.update(generate_trigger_caches(vd, root, triplet, ld, libdirs))
    check_icons_decode(vd, root, ld, libdirs, out)
    return gen


def generate_trigger_caches(vd, root, triplet, ld, libdirs):
    """What dpkg triggers build on a real system. Without the MIME database
    GLib cannot tell an SVG from text, every icon fails to load, and
    xfce4-panel aborts (a GTK assertion) on a host that has no
    shared-mime-info of its own: the desktop restarted until the daemon gave
    up, and the session was a black screen."""
    gen = {}
    share = os.path.join(root, "usr/share")
    run_bundled(vd, root, ld, libdirs, "usr/bin/update-mime-database", [os.path.join(share, "mime")])
    if not os.path.isfile(os.path.join(share, "mime/mime.cache")):
        sys.exit("update-mime-database wrote no mime.cache")
    gen["mime"] = os.path.join(share, "mime")
    apps = os.path.join(share, "applications")
    run_bundled(vd, root, ld, libdirs, "usr/bin/update-desktop-database", [apps])
    gen["mimeinfo"] = open(os.path.join(apps, "mimeinfo.cache"), "rb").read()
    gen["icon_caches"] = {}
    icons = os.path.join(share, "icons")
    for theme in sorted(os.listdir(icons)):
        tdir = os.path.join(icons, theme)
        if os.path.isfile(os.path.join(tdir, "index.theme")):
            run_bundled(vd, root, ld, libdirs, "usr/bin/gtk-update-icon-cache",
                        ["--force", "--quiet", "--ignore-theme-index", tdir])
            gen["icon_caches"][theme] = open(os.path.join(tdir, "icon-theme.cache"), "rb").read()
    if "hicolor" not in gen["icon_caches"] or "Adwaita" not in gen["icon_caches"]:
        sys.exit(f"icon caches missing: {sorted(gen['icon_caches'])}")
    gio = os.path.join(root, "usr/lib", triplet, "gio/modules")
    run_bundled(vd, root, ld, libdirs, "usr/bin/gio-querymodules", [gio])
    gen["giomodules"] = (gio_module_names(gio), open(os.path.join(gio, "giomodule.cache"), "rb").read())
    imdir = os.path.join(root, "usr/lib", triplet, "gtk-3.0/3.0.0/immodules")
    query = next(q for q in (os.path.join(root, "usr/lib", triplet, d, "gtk-query-immodules-3.0")
                             for d in ("libgtk-3-0t64", "libgtk-3-0")) if os.path.exists(q))
    mods = sorted(os.path.join(imdir, f) for f in os.listdir(imdir) if f.endswith(".so"))
    out = run_bundled(vd, root, ld, libdirs, os.path.relpath(query, root), mods).stdout
    if not mods or any(os.path.basename(m) not in out for m in mods):
        sys.exit("gtk-query-immodules-3.0 did not list every module")
    gen["immodules"] = out.replace(root, "@MHVD_ROOT@")
    return gen


def gio_module_names(gio):
    return sorted(f for f in os.listdir(gio) if f.endswith(".so"))


def check_icons_decode(vd, root, ld, libdirs, pixbuf_cache):
    """The bundle alone decodes an SVG icon: its own MIME database and pixbuf
    loaders, nothing from the build host (XDG dirs pointed at the bundle)."""
    tmp = tempfile.mkdtemp(prefix="vd-check-")
    try:
        cache = os.path.join(tmp, "loaders.cache")
        with open(cache, "w") as fh:
            fh.write(pixbuf_cache)
        svg = os.path.join(root, "usr/share/icons/Adwaita/scalable/status/image-missing.svg")
        png = os.path.join(tmp, "out.png")
        env = {"XDG_DATA_DIRS": os.path.join(root, "usr/share"), "XDG_DATA_HOME": tmp,
               "HOME": tmp, "GDK_PIXBUF_MODULE_FILE": cache}
        try:
            run_bundled(vd, root, ld, libdirs, "usr/bin/gdk-pixbuf-thumbnailer",
                        ["-s", "32", svg, png], env=env)
        except subprocess.CalledProcessError as e:
            sys.exit(f"the bundle cannot decode an SVG icon by itself: {e.stderr.strip()}")
        if not os.path.isfile(png) or os.path.getsize(png) == 0:
            sys.exit("the bundle cannot decode an SVG icon by itself (no output)")
        print("check: the bundle decodes an SVG icon with its own MIME database and loaders")
    finally:
        shutil.rmtree(tmp)


def place_generated(vd, root, triplet, gen, src_triplet):
    with open(os.path.join(root, "usr/share/glib-2.0/schemas/gschemas.compiled"), "wb") as fh:
        fh.write(gen["schemas"])
    cache = os.path.join(root, "usr/lib", triplet, "gdk-pixbuf-2.0/2.10.0/loaders.cache")
    with open(cache, "w") as fh:
        fh.write(gen["pixbuf"].replace(src_triplet, triplet))
    dst = os.path.join(root, "usr/lib/locale/zh_CN.UTF-8")
    if os.path.abspath(gen["locale"]) != os.path.abspath(dst):
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(gen["locale"], dst)
    # The trigger caches (arch-independent but for paths, made once).
    share = os.path.join(root, "usr/share")
    mime = os.path.join(share, "mime")
    if os.path.abspath(gen["mime"]) != os.path.abspath(mime):
        shutil.rmtree(mime, ignore_errors=True)
        shutil.copytree(gen["mime"], mime, symlinks=True)
    with open(os.path.join(share, "applications/mimeinfo.cache"), "wb") as fh:
        fh.write(gen["mimeinfo"])
    for theme, data in gen["icon_caches"].items():
        tdir = os.path.join(share, "icons", theme)
        if not os.path.isdir(tdir):
            sys.exit(f"{triplet}: icon theme {theme} missing")
        c = os.path.join(tdir, "icon-theme.cache")
        with open(c, "wb") as fh:
            fh.write(data)
        # GTK ignores a cache older than its theme directory.
        newest = max(os.stat(d).st_mtime for d, _, _ in os.walk(tdir))
        os.utime(c, (newest + 2, newest + 2))
    gio = os.path.join(root, "usr/lib", triplet, "gio/modules")
    names, data = gen["giomodules"]
    if gio_module_names(gio) != names:
        sys.exit(f"{triplet}: GIO modules differ from the generating arch: {gio_module_names(gio)} vs {names}")
    with open(os.path.join(gio, "giomodule.cache"), "wb") as fh:
        fh.write(data)
    imcache = os.path.join(root, "usr/lib", triplet, "gtk-3.0/3.0.0/immodules.cache")
    with open(imcache, "w") as fh:
        fh.write(gen["immodules"].replace(src_triplet, triplet))
    with open(os.path.join(vd, "relocate.list"), "w") as fh:
        fh.write(os.path.relpath(cache, vd) + "\n" + os.path.relpath(imcache, vd) + "\netc/session.conf\n")
    for rel in BUILD_ONLY_DIRS:
        shutil.rmtree(os.path.join(root, rel), ignore_errors=True)


WRAPPER = """#!/bin/sh
# FR-120 P4 — run the bundle's program on the bundle's own glibc.
V=$(cd "${{0%/*}}/.." && pwd -P)
: "${{MHVD_ROOT:=$V/root}}"; : "${{MHVD_BIN:=$V/bin}}"; : "${{MHVD_SHIM:=$V/lib/mhvd-shim.so}}"
: "${{MHVD_LD:=$MHVD_ROOT/{ld}}}"; : "${{MHVD_LIBS:={libpath}}}"
export MHVD_ROOT MHVD_BIN MHVD_SHIM MHVD_LD MHVD_LIBS
exec "$MHVD_LD" --library-path "$MHVD_LIBS" --preload "$MHVD_SHIM" --argv0 "$0" "$MHVD_ROOT/{rel}" "$@"
"""

SESSION_CONF = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <keep_umask/>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <servicedir>@MHVD_ROOT@/usr/share/dbus-1/services</servicedir>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""


def main():
    out = os.path.abspath(sys.argv[1])
    os.makedirs(out, exist_ok=True)
    gen, src_triplet = None, None
    for arch in ("amd64", "arm64"):
        pkgs = closure(index(arch))
        print(f"{arch}: {len(pkgs)} packages")
        work = tempfile.mkdtemp(prefix=f"desk-{arch}-", dir=os.environ.get("TMPDIR"))
        stage, vd = os.path.join(work, "stage"), os.path.join(work, "vd")
        extract(arch, pkgs, stage)
        root, triplet, ld, libdirs = assemble(arch, stage, vd, pkgs)
        if gen is None:
            gen, src_triplet = generate(vd, root, triplet, ld, libdirs), triplet
            gen["locale_copy"] = os.path.join(work, "zh_CN.UTF-8")
            shutil.copytree(gen["locale"], gen["locale_copy"])
            gen["locale"] = gen["locale_copy"]
        place_generated(vd, root, triplet, gen, src_triplet)
        dest = os.path.join(out, f"meshharbor-vd-{arch}.tar.xz")
        with tarfile.open(dest, "w:xz", preset=9) as tar:
            tar.add(vd, arcname="vd")
        size = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(vd)
                   for f in fs if not os.path.islink(os.path.join(d, f)))
        print(f"wrote {dest}: {os.path.getsize(dest) >> 20} MiB packed, {size >> 20} MiB unpacked")
        if arch == "arm64":
            shutil.rmtree(work)
        else:
            amd_work = work
    shutil.rmtree(amd_work)


if __name__ == "__main__":
    main()
