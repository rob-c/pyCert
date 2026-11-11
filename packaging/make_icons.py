"""Render packaging/icons/pycertwiz.svg as PNGs (and a macOS .icns).

    QT_QPA_PLATFORM=offscreen python packaging/make_icons.py OUTDIR

Writes OUTDIR/pycertwiz-<size>.png for 16..1024 and, on macOS (iconutil),
OUTDIR/pyCertWiz.icns.
"""

import shutil
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

SIZES = (16, 32, 48, 64, 128, 256, 512, 1024)


def render(svg: Path, size: int) -> QImage:
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    QSvgRenderer(str(svg)).render(painter, QRectF(0, 0, size, size))
    painter.end()
    return image


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "build/icons")
    out.mkdir(parents=True, exist_ok=True)
    _app = QGuiApplication([sys.argv[0]])
    svg = Path(__file__).with_name("icons") / "pycertwiz.svg"
    for size in SIZES:
        render(svg, size).save(str(out / f"pycertwiz-{size}.png"))
    if sys.platform == "darwin" and shutil.which("iconutil"):
        iconset = out / "pyCertWiz.iconset"
        iconset.mkdir(exist_ok=True)
        for size in (16, 32, 128, 256, 512):
            render(svg, size).save(str(iconset / f"icon_{size}x{size}.png"))
            render(svg, size * 2).save(str(iconset / f"icon_{size}x{size}@2x.png"))
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(out / "pyCertWiz.icns")], check=True)
    print(f"icons written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
