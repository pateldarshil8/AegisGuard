"""Generates installer\\aegisguard.ico (blue shield) with Pillow. Run by build.ps1."""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).with_name("aegisguard.ico")
S = 1024  # draw large, then downscale for smooth edges


def shield(inset: float = 0.0):
    k = S / 64
    pts = [(32, 4), (58, 14), (54, 40), (32, 60), (10, 40), (6, 14)]
    return [(x * k, y * k) for x, y in pts]


def main() -> None:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon(shield(), fill="#2f6fed")
    k = S / 64
    inner = [(32, 16), (46, 22), (44, 38), (32, 48), (20, 38), (18, 22)]
    d.polygon([(x * k, y * k) for x, y in inner], fill="#ffffff")
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.resize((256, 256), Image.LANCZOS).save(OUT, format="ICO", sizes=sizes)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
