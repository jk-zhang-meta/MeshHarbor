#!/usr/bin/env python3
"""Install X18 product icons and derive the desktop recording indicator.

    python3 scripts/gen-tray-icons.py                   # desktop (default)
    python3 scripts/gen-tray-icons.py --target setup    # setup wizard
    python3 scripts/gen-tray-icons.py --output-dir /tmp/meshharbor-icons

Product PNG/ICO and the transparent tray template are copied byte-for-byte
from design/x18/assets after checking their manifest hashes. No brand mark is
redrawn here. Desktop recording uses the approved colour mark with the existing
white-ringed red dot; it remains a non-template image (tray.rs).

Python's standard library suffices for setup. Desktop additionally needs the
system libcairo used by the X18 renderer, solely for the offscreen red dot.
--assets selects an alternative X18 asset directory; --output-dir allows an
isolated regeneration without touching the installed source-tree icons.
"""

import argparse
import ctypes as c
import ctypes.util
import hashlib
import json
import math
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGETS = {
    "desktop": ROOT / "agents/meshharbor-desktop/icons",
    "setup": ROOT / "agents/meshharbor-setup/icons",
}
PRODUCT = "linux/hicolor/512x512/apps/meshharbor-desktop.png"
ICO = "windows/meshharbor.ico"
TRAY = "template/tray/black-48.png"
RECORDING = "linux/hicolor/48x48/apps/meshharbor-desktop.png"


def approved(assets, manifest, name):
    data = (assets / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest["files"][name]:
        raise ValueError("X18 manifest hash mismatch: " + name)
    return data


def recording_mark(source, output):
    """Use the approved colour pixels; paint only the FR-85 status overlay."""
    library = ctypes.util.find_library("cairo")
    if not library:
        raise RuntimeError("desktop recording icon needs system libcairo (X18 renderer)")
    cairo = c.CDLL(library)
    signatures = {
        "cairo_image_surface_create_from_png": ([c.c_char_p], c.c_void_p),
        "cairo_surface_status": ([c.c_void_p], c.c_int),
        "cairo_image_surface_get_width": ([c.c_void_p], c.c_int),
        "cairo_image_surface_get_height": ([c.c_void_p], c.c_int),
        "cairo_create": ([c.c_void_p], c.c_void_p),
        "cairo_status": ([c.c_void_p], c.c_int),
        "cairo_set_source_rgb": ([c.c_void_p, c.c_double, c.c_double, c.c_double], None),
        "cairo_arc": ([c.c_void_p] + [c.c_double] * 5, None),
        "cairo_fill": ([c.c_void_p], None),
        "cairo_surface_write_to_png": ([c.c_void_p, c.c_char_p], c.c_int),
        "cairo_destroy": ([c.c_void_p], None),
        "cairo_surface_destroy": ([c.c_void_p], None),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(cairo, name)
        function.argtypes, function.restype = arguments, result
    surface = cairo.cairo_image_surface_create_from_png(str(source).encode())
    context = None
    try:
        if cairo.cairo_surface_status(surface):
            raise RuntimeError("cannot decode approved recording PNG")
        width = cairo.cairo_image_surface_get_width(surface)
        height = cairo.cairo_image_surface_get_height(surface)
        if (width, height) != (48, 48):
            raise ValueError("recording source must be the approved 48px asset")
        context = cairo.cairo_create(surface)
        radius = width * .22
        ring = max(1.0, width * .05)
        center = width - radius - ring - 1
        for size, color in [(radius + ring, (1.0, 1.0, 1.0)),
                            (radius, (229 / 255, 57 / 255, 53 / 255))]:
            cairo.cairo_set_source_rgb(context, *color)
            cairo.cairo_arc(context, center, center, size, 0, 2 * math.pi)
            cairo.cairo_fill(context)
        if cairo.cairo_status(context) or cairo.cairo_surface_write_to_png(surface, str(output).encode()):
            raise RuntimeError("cannot render recording icon")
    finally:
        if context:
            cairo.cairo_destroy(context)
        cairo.cairo_surface_destroy(surface)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", choices=sorted(TARGETS), default="desktop")
    parser.add_argument("--assets", type=pathlib.Path, default=ROOT / "design/x18/assets")
    parser.add_argument("--output-dir", type=pathlib.Path)
    args = parser.parse_args(argv)
    assets = args.assets.resolve()
    output = (args.output_dir or TARGETS[args.target]).resolve()
    if output == assets or assets in output.parents:
        parser.error("output must not overwrite approved X18 assets")
    manifest = json.loads((assets / "manifest.json").read_text())
    # Validate all required inputs before touching an existing product icon.
    files = {"icon.png": approved(assets, manifest, PRODUCT),
             "icon.ico": approved(assets, manifest, ICO)}
    if args.target == "desktop":
        files["tray.png"] = approved(assets, manifest, TRAY)
        approved(assets, manifest, RECORDING)
        if not ctypes.util.find_library("cairo"):
            parser.error("desktop recording icon needs system libcairo (X18 renderer)")
    output.mkdir(parents=True, exist_ok=True)
    if args.target == "desktop":
        recording_mark(assets / RECORDING, output / "tray-recording.png")
    for name, data in files.items():
        (output / name).write_bytes(data)
    print(f"{args.target} -> {output}")
    for name in [*files, *(["tray-recording.png"] if args.target == "desktop" else [])]:
        data = (output / name).read_bytes()
        dimensions = struct.unpack_from(">II", data, 16) if name.endswith(".png") else None
        print(f"  {name}: {dimensions or 'ICO'} {len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
