"""Generates the notification icons in internal/ui/static/img/notify/.

Square images; chat clients crop them to a circle (Teams "Person" style,
Slack accessories round the corners). Drawn at 4x and downscaled for
smooth edges. Needs Pillow:

    python3 scripts/gen-notify-icons.py internal/ui/static/img/notify
"""

import math
import sys
from pathlib import Path

from PIL import Image, ImageDraw

SIZE = 96
SS = 4  # supersampling
S = SIZE * SS

RED = (225, 29, 72)
ORANGE = (249, 115, 22)
GREEN = (16, 185, 129)
BLUE = (59, 130, 246)
SLATE = (71, 85, 105)
WHITE = (255, 255, 255)


def canvas(bg):
    img = Image.new("RGB", (S, S), bg)
    return img, ImageDraw.Draw(img)


def finish(img):
    return img.resize((SIZE, SIZE), Image.LANCZOS)


def shade(c, f):
    return tuple(max(0, min(255, int(v * f))) for v in c)


def triangle(d, color, scale=1.0, cy=0.53):
    r = S * 0.30 * scale
    cx, cyp = S / 2, S * cy
    pts = [(cx, cyp - r), (cx + r * 1.08, cyp + r * 0.78), (cx - r * 1.08, cyp + r * 0.78)]
    d.polygon(pts, fill=color)
    d.line(pts + [pts[0]], fill=color, width=int(S * 0.05), joint="curve")


def exclamation(d, color, top=0.40, bottom=0.61, dot=0.70):
    w = S * 0.055
    d.rounded_rectangle([S / 2 - w / 2, S * top, S / 2 + w / 2, S * bottom], radius=w / 2, fill=color)
    r = S * 0.036
    d.ellipse([S / 2 - r, S * dot - r, S / 2 + r, S * dot + r], fill=color)


def check(d, color):
    w = int(S * 0.085)
    d.line([(S * 0.28, S * 0.52), (S * 0.43, S * 0.67), (S * 0.73, S * 0.35)], fill=color, width=w, joint="curve")
    for x, y in [(S * 0.28, S * 0.52), (S * 0.73, S * 0.35)]:
        d.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=color)


def cross(d, color):
    w = int(S * 0.085)
    a, b = S * 0.33, S * 0.67
    d.line([(a, a), (b, b)], fill=color, width=w)
    d.line([(a, b), (b, a)], fill=color, width=w)
    for x, y in [(a, a), (b, b), (a, b), (b, a)]:
        d.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=color)


def bell(d, color):
    d.pieslice([S * 0.30, S * 0.26, S * 0.70, S * 0.66], 180, 360, fill=color)
    d.rectangle([S * 0.30, S * 0.46, S * 0.70, S * 0.64], fill=color)
    d.rounded_rectangle([S * 0.24, S * 0.62, S * 0.76, S * 0.69], radius=S * 0.03, fill=color)
    d.ellipse([S * 0.44, S * 0.68, S * 0.56, S * 0.78], fill=color)
    d.ellipse([S * 0.465, S * 0.20, S * 0.535, S * 0.28], fill=color)


def static_icons(out):
    img, d = canvas(ORANGE)
    triangle(d, WHITE)
    exclamation(d, ORANGE)
    finish(img).save(out / "fail.png", optimize=True)

    img, d = canvas(SLATE)
    cross(d, WHITE)
    finish(img).save(out / "error.png", optimize=True)

    img, d = canvas(GREEN)
    check(d, WHITE)
    finish(img).save(out / "pass.png", optimize=True)

    img, d = canvas(BLUE)
    bell(d, WHITE)
    finish(img).save(out / "test.png", optimize=True)

    img, d = canvas(RED)
    triangle(d, WHITE)
    exclamation(d, RED)
    finish(img).save(out / "critical.png", optimize=True)


def critical_gif(out):
    """Pulsing alarm: the background breathes and a ring expands."""
    frames = []
    n = 12
    for i in range(n):
        t = i / n
        pulse = 0.5 + 0.5 * math.sin(2 * math.pi * t)
        img, d = canvas(shade(RED, 0.78 + 0.30 * pulse))
        # expanding ring
        r = S * (0.30 + 0.22 * t)
        alpha = 1 - t
        ring = shade(WHITE, 1)
        width = max(1, int(S * 0.035 * alpha + 1))
        ring_col = tuple(int(c * alpha + bg * (1 - alpha)) for c, bg in zip(ring, shade(RED, 0.78 + 0.30 * pulse)))
        d.ellipse([S / 2 - r, S / 2 - r, S / 2 + r, S / 2 + r], outline=ring_col, width=width)
        triangle(d, WHITE, scale=0.92 + 0.08 * pulse)
        exclamation(d, shade(RED, 0.78 + 0.30 * pulse))
        frames.append(finish(img).convert("P", palette=Image.ADAPTIVE, colors=64))
    frames[0].save(out / "critical.gif", save_all=True, append_images=frames[1:], duration=90, loop=0, optimize=True)


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "internal/ui/static/img/notify")
    out.mkdir(parents=True, exist_ok=True)
    static_icons(out)
    critical_gif(out)


if __name__ == "__main__":
    main()
