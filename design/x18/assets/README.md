# MeshHarbor icon assets — direction A

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
