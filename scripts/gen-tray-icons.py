#!/usr/bin/env python3
"""Generate the desktop companion's and the setup wizard's icons from the
product's brand mark.

Why this exists: the icons shipped as 1x1 PLACEHOLDERS (67-byte PNGs). Windows
tolerated them; macOS did not — `tao`'s tray setup panics before the app
window ever appears:

    invalid icon: The specified dimensions (1x1) don't match the number of
    pixels supplied by the `rgba` argument (0)

and a panic in that callback "cannot unwind", so the process aborts. The
companion could not start on macOS at all. The setup wizard carried the same
1x1 placeholders for its whole life (its build.rs still writes them when the
files are missing), so the one EXE a new user double-clicks had a blank icon
in Explorer and the taskbar — FR-84 S2 gave it a real one.

Generated rather than hand-drawn so regenerating is a command rather than an
afternoon in a paint program. The mark is the web favicon as it was before the
2026-10 logo (a #1565C0 rounded square with a white R): the native icon sets
have not moved to the new logo, so `ui/public/favicon.svg` no longer matches.

    python3 scripts/gen-tray-icons.py                   # the companion (default)
    python3 scripts/gen-tray-icons.py --target setup    # the setup wizard

Requires Pillow. `desktop` writes agents/meshharbor-desktop/icons/ (app icon,
menu-bar template, the tray while a recording runs, .ico). `setup` writes
agents/meshharbor-setup/icons/ — the same R on GREEN (#2E7D32), so a wizard and
a companion side by side in a taskbar are told apart at a glance; app icon +
.ico only, the wizard has no tray. CI asserts both sets are real (ci.yml
"Assert the icons are real").
"""

import argparse
import pathlib
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - developer tooling
    sys.exit("this needs Pillow:  pip install pillow")

ROOT = pathlib.Path(__file__).resolve().parent.parent
BRAND = (21, 101, 192, 255)  # #1565C0, from the pre-2026-10 favicon.svg
SETUP = (46, 125, 50, 255)  # #2E7D32 — the wizard's green (operator, 2026-09-25)
WHITE = (255, 255, 255, 255)
RED = (229, 57, 53, 255)  # #E53935 — the dot on the tray while recording (FR-85)

# target → (output dir, background, whether a menu-bar/tray icon is written)
TARGETS = {
    "desktop": (ROOT / "agents/meshharbor-desktop/icons", BRAND, True),
    "setup": (ROOT / "agents/meshharbor-setup/icons", SETUP, False),
}

# The classic Windows sizes, in one file. 256 is stored with a width byte of
# 0 — what the CI guard looks for.
ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)]

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "C:/Windows/Fonts/arialbd.ttf",
]

# 4x supersample, then LANCZOS down — the rounded corners and the R's bowl
# both alias badly at 22px otherwise, which is exactly the size the menu bar
# renders at.
SS = 4


def _font(px: int):
    for path in FONT_CANDIDATES:
        if pathlib.Path(path).exists():
            return ImageFont.truetype(path, px)
    return None


def _mark(size: int, fg, bg):
    """The brand mark: rounded square `bg`, letter R in `fg`."""
    n = size * SS
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # The pre-2026-10 favicon.svg used rx=6 on a 32px box — keep that ratio.
    d.rounded_rectangle([0, 0, n - 1, n - 1], radius=int(n * 6 / 32), fill=bg)

    font = _font(int(n * 0.66))
    if font is None:
        # No font anywhere: fall back to a ring so the icon is still a valid,
        # recognisable shape rather than a blank square.
        inset = int(n * 0.28)
        d.ellipse([inset, inset, n - inset, n - inset], fill=(0, 0, 0, 0))
    else:
        # `anchor="mm"` centres on the glyph's own box, which is what makes the
        # R sit optically centred rather than baseline-aligned.
        d.text((n / 2, n / 2 - int(n * 0.04)), "R", font=font, fill=fg, anchor="mm")
    return img.resize((size, size), Image.LANCZOS)


def _recording_mark(size: int):
    """FR-85 — the tray while a recording runs: the mark in full colour with
    a red dot at the bottom right, ringed in white so it reads on the blue
    mark and on a light or a dark menu bar or taskbar alike."""
    img = _mark(size, WHITE, BRAND)
    n = size * SS
    dot = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(dot)
    r = int(n * 0.22)  # the red dot's radius
    ring = max(SS, int(n * 0.05))  # the white ring around it
    c = n - r - ring - 1  # touching the bottom-right corner
    d.ellipse([c - r - ring, c - r - ring, c + r + ring, c + r + ring], fill=WHITE)
    d.ellipse([c - r, c - r, c + r, c + r], fill=RED)
    img.alpha_composite(dot.resize((size, size), Image.LANCZOS))
    return img


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--target",
        choices=sorted(TARGETS),
        default="desktop",
        help="which icon set to write (default: desktop, the companion)",
    )
    args = ap.parse_args(argv)
    out, bg, with_tray = TARGETS[args.target]
    out.mkdir(parents=True, exist_ok=True)

    # App icon — full colour.
    _mark(512, WHITE, bg).save(out / "icon.png")
    written = ["icon.png"]

    if with_tray:
        # Menu-bar icon. macOS TEMPLATE images use the alpha channel only and
        # are tinted by the system, so this is black-on-transparent: one asset
        # that is correct in both the light and the dark menu bar. 44px =
        # 22pt @2x.
        tray = _mark(44, (0, 0, 0, 0), (0, 0, 0, 255))
        tray.save(out / "tray.png")
        written.append("tray.png")

        # FR-85 — the tray while a recording runs. NOT a template: the
        # system tints a template to the menu bar, and this one has to stay
        # red. meshharbor-desktop swaps it in (tray.rs) and back out after.
        _recording_mark(44).save(out / "tray-recording.png")
        written.append("tray-recording.png")

    # Windows wants the classic sizes in one file.
    _mark(256, WHITE, bg).save(out / "icon.ico", sizes=ICO_SIZES)
    written.append("icon.ico")

    print(f"{args.target} -> {out}")
    for f in written:
        p = out / f
        with Image.open(p) as im:
            print(f"  {f}: {im.size[0]}x{im.size[1]} {im.mode}, {p.stat().st_size} bytes")


if __name__ == "__main__":
    main()
