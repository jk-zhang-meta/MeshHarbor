#!/usr/bin/env python3
"""Render the selected X18 SVG into portable icon containers with librsvg/cairo.

Usage: python3 design/x18/generate-assets.py --output /absolute/new/directory
The output directory must not already exist. Existing source/assets are untouched.
"""
import argparse
import ctypes as c
import ctypes.util
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import xml.etree.ElementTree as ET

SOURCE = Path(__file__).resolve().with_name('beacon-harbor.svg')
SIZES = (16, 24, 32, 48, 64, 128, 256, 512)
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
ICNS_TYPES = ((b'icp4', 16), (b'icp5', 32), (b'icp6', 64),
              (b'ic07', 128), (b'ic08', 256), (b'ic09', 512), (b'ic10', 1024),
              (b'ic11', 32), (b'ic12', 64), (b'ic13', 256), (b'ic14', 512))


class Rectangle(c.Structure):
    _fields_ = [('x', c.c_double), ('y', c.c_double),
                ('width', c.c_double), ('height', c.c_double)]


def library(name):
    path = c.util.find_library(name)
    if not path:
        raise RuntimeError('required open-source system library not found: ' + name)
    return c.CDLL(path)


# Keep the library APIs explicit: all graphics operations are offscreen.
cairo = library('cairo')
rsvg = library('rsvg-2')
gobject = library('gobject-2.0')
ptr = c.c_void_p
cairo.cairo_image_surface_create.argtypes = [c.c_int, c.c_int, c.c_int]
cairo.cairo_image_surface_create.restype = ptr
cairo.cairo_create.argtypes = [ptr]
cairo.cairo_create.restype = ptr
cairo.cairo_set_source_rgb.argtypes = [ptr, c.c_double, c.c_double, c.c_double]
cairo.cairo_paint.argtypes = [ptr]
cairo.cairo_surface_write_to_png.argtypes = [ptr, c.c_char_p]
cairo.cairo_surface_write_to_png.restype = c.c_int
cairo.cairo_destroy.argtypes = [ptr]
cairo.cairo_surface_destroy.argtypes = [ptr]
rsvg.rsvg_handle_new_from_file.argtypes = [c.c_char_p, c.POINTER(ptr)]
rsvg.rsvg_handle_new_from_file.restype = ptr
rsvg.rsvg_handle_render_document.argtypes = [ptr, ptr, c.POINTER(Rectangle), c.POINTER(ptr)]
rsvg.rsvg_handle_render_document.restype = c.c_int
gobject.g_object_unref.argtypes = [ptr]


def render(handle, size, path, maskable=False):
    surface = cairo.cairo_image_surface_create(0, size, size)  # ARGB32
    context = cairo.cairo_create(surface)
    try:
        if maskable:
            cairo.cairo_set_source_rgb(context, 23 / 255, 57 / 255, 50 / 255)
            cairo.cairo_paint(context)
            # The original foreground stays within the maskable safe circle;
            # the background fills the entire square for arbitrary OS masks.
            viewport = Rectangle(size * .14, size * .14, size * .72, size * .72)
        else:
            viewport = Rectangle(0, 0, size, size)
        error = ptr()
        if not rsvg.rsvg_handle_render_document(handle, context, c.byref(viewport), c.byref(error)):
            raise RuntimeError('SVG rendering failed')
        path.parent.mkdir(parents=True, exist_ok=True)
        if cairo.cairo_surface_write_to_png(surface, str(path).encode()) != 0:
            raise RuntimeError('PNG write failed: ' + str(path))
    finally:
        cairo.cairo_destroy(context)
        cairo.cairo_surface_destroy(surface)


def ico(images):
    sizes = sorted(images)
    offset = 6 + 16 * len(sizes)
    entries = []
    for size in sizes:
        data = images[size]
        side = 0 if size == 256 else size
        entries.append(struct.pack('<BBBBHHII', side, side, 0, 0, 1, 32, len(data), offset))
        offset += len(data)
    return struct.pack('<HHH', 0, 1, len(sizes)) + b''.join(entries) + b''.join(images[s] for s in sizes)


def icns(images):
    chunks = []
    for kind, size in ICNS_TYPES:
        data = images[size]
        chunks.append(kind + struct.pack('>I', len(data) + 8) + data)
    content = b''.join(chunks)
    return b'icns' + struct.pack('>I', len(content) + 8) + content


def template_svg(color):
    ET.register_namespace('', 'http://www.w3.org/2000/svg')
    svg = ET.fromstring(SOURCE.read_bytes())
    background = next(el for el in svg if el.tag.endswith('rect'))
    svg.remove(background)
    for element in svg.iter():
        for attr in ('fill', 'stroke'):
            if element.get(attr, '').startswith('#'):
                element.set(attr, color)
    return ET.tostring(svg, encoding='utf-8', xml_declaration=True) + b'\n'


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output
    if not out.is_absolute() or out.exists():
        raise ValueError('output must be a new absolute path')
    out.mkdir(parents=True)
    error = ptr()
    handle = rsvg.rsvg_handle_new_from_file(str(SOURCE).encode(), c.byref(error))
    if not handle:
        raise RuntimeError('cannot open source SVG')
    try:
        save(out / 'meshharbor.svg', SOURCE.read_bytes())
        save(out / 'web/favicon.svg', SOURCE.read_bytes())
        save(out / 'template/meshharbor-template.svg', template_svg('#000000'))
        save(out / 'template/meshharbor-template-light.svg', template_svg('#FFFFFF'))
        for variant, svg_name in [('black', 'meshharbor-template.svg'),
                                  ('white', 'meshharbor-template-light.svg')]:
            template = rsvg.rsvg_handle_new_from_file(
                str(out / 'template' / svg_name).encode(), c.byref(error))
            if not template:
                raise RuntimeError('cannot open generated template SVG')
            try:
                for size in (16, 24, 32, 48, 64):
                    render(template, size, out / f'template/tray/{variant}-{size}.png')
                if variant == 'black':
                    render(template, 16, out / 'template/macos/MeshHarborTemplate.png')
                    render(template, 32, out / 'template/macos/MeshHarborTemplate@2x.png')
            finally:
                gobject.g_object_unref(template)
        images = {}
        with tempfile.TemporaryDirectory(prefix='.x18-render-', dir=out.parent) as temporary:
            for size in sorted(set(SIZES + (180, 192, 1024))):
                png = Path(temporary) / (str(size) + '.png')
                render(handle, size, png)
                images[size] = png.read_bytes()
        for size in SIZES:
            save(out / f'linux/hicolor/{size}x{size}/apps/meshharbor-desktop.png', images[size])
        save(out / 'windows/meshharbor.ico', ico({s: images[s] for s in ICO_SIZES}))
        save(out / 'macos/meshharbor.icns', icns(images))
        save(out / 'web/favicon.ico', ico({s: images[s] for s in (16, 32, 48)}))
        for filename, size in [('apple-touch-icon.png', 180), ('icon-192.png', 192), ('icon-512.png', 512)]:
            save(out / 'web' / filename, images[size])
        for size in (192, 512):
            render(handle, size, out / f'web/maskable-{size}.png', maskable=True)
        save(out / 'README.md', '''# MeshHarbor icon assets — direction A

These files are generated from `../beacon-harbor.svg` by
`../generate-assets.py` using system librsvg, cairo and Python 3's standard
library. Generate into a new absolute directory, for example:

    python3 design/x18/generate-assets.py --output /tmp/meshharbor-icons

`manifest.json` binds the source and every generated file by SHA-256.
The same source and renderer versions produce byte-identical output.

- `windows/meshharbor.ico`: 16, 24, 32, 48, 64, 128, 256 px.
- `macos/meshharbor.icns`: standard 16 through 1024 px and @2x chunks.
- `linux/hicolor/<size>x<size>/apps/meshharbor-desktop.png`: icon theme
  assets for the existing desktop entry's `Icon=meshharbor-desktop`.
- `web/`: favicon, touch, PWA and maskable assets. Maskable variants fill the
  background and inset the mark within the safe circle.
- `template/`: transparent single-color SVGs, black macOS Template PNGs and
  black/white tray PNGs for light/dark surfaces.

These are review-stage files. Packaging, desktop and web integration happen
after the R3 integration baseline is approved. Platform-native rendering,
installation, trademark and production deployment have not been verified.
'''.encode('utf-8'))
        files = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(out.rglob('*')) if p.is_file()}
        manifest = {'source': SOURCE.name, 'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                    'renderer': 'librsvg + cairo', 'files': files}
        save(out / 'manifest.json', (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())
        print(json.dumps({'output': str(out), 'files': len(files) + 1, 'source_sha256': manifest['source_sha256']}))
    finally:
        gobject.g_object_unref(handle)


if __name__ == '__main__':
    main()
