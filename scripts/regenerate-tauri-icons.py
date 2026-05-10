#!/usr/bin/env python3
"""Regenerate Tauri app launcher icons from coincync-mark.png.

Replaces the default green-square Tauri placeholders with the CoinCync mark.
Generates PNG sizes for Windows Store + Linux + macOS targets and a
multi-resolution Windows .ico embedded into the exe at build time.
"""
import sys
from pathlib import Path
from PIL import Image

SOURCE = Path("coincync-wallet/src/assets/coincync-mark.png")

PNG_TARGETS = {
    "icon.png": 512,
    "32x32.png": 32,
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "Square30x30Logo.png": 30,
    "Square44x44Logo.png": 44,
    "Square71x71Logo.png": 71,
    "Square89x89Logo.png": 89,
    "Square107x107Logo.png": 107,
    "Square142x142Logo.png": 142,
    "Square150x150Logo.png": 150,
    "Square284x284Logo.png": 284,
    "Square310x310Logo.png": 310,
    "StoreLogo.png": 50,
}

ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]

def crop_square(im: Image.Image) -> Image.Image:
    w, h = im.size
    side = min(w, h)
    left = (w - side) // 2
    top = (h - side) // 2
    return im.crop((left, top, left + side, top + side))

def write_icons(icons_dir: Path, master: Image.Image):
    icons_dir.mkdir(parents=True, exist_ok=True)
    for name, size in PNG_TARGETS.items():
        out = master.resize((size, size), Image.LANCZOS)
        out.save(icons_dir / name, optimize=True)
        print(f"  wrote {name} ({size}x{size})")
    ico_imgs = [master.resize((s, s), Image.LANCZOS) for s in ICO_SIZES]
    ico_imgs[0].save(
        icons_dir / "icon.ico",
        format="ICO",
        sizes=[(s, s) for s in ICO_SIZES],
    )
    print(f"  wrote icon.ico ({','.join(str(s) for s in ICO_SIZES)})")

def main():
    if not SOURCE.exists():
        sys.exit(f"source not found: {SOURCE}")
    src = Image.open(SOURCE).convert("RGBA")
    master = crop_square(src).resize((1024, 1024), Image.LANCZOS)
    print(f"source {SOURCE} {src.size} -> master {master.size}")
    targets = [
        Path("coincync-wallet/src-tauri/icons"),
        Path("miner-gui/src-tauri/icons"),
    ]
    for t in targets:
        if t.parent.exists():
            print(f"\n[{t}]")
            write_icons(t, master)
        else:
            print(f"\nskipped (no parent dir): {t}")

if __name__ == "__main__":
    main()
