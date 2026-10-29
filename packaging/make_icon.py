"""Erzeugt das App-Symbol (magicbox/assets/magicbox.ico + .png) – einmalig bzw. bei Designänderungen ausführen."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

OUT = Path(__file__).resolve().parent.parent / "magicbox" / "assets"
S = 1024  # in hoher Auflösung zeichnen, dann verkleinern


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def draw() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # Hintergrund: abgerundetes Quadrat mit violettem Verlauf
    grad = Image.new("RGBA", (S, S))
    gd = ImageDraw.Draw(grad)
    top, bottom = (139, 92, 246), (76, 29, 149)
    for y in range(S):
        gd.line([(0, y), (S, y)], fill=lerp(top, bottom, y / S) + (255,))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([40, 40, S - 40, S - 40], radius=220, fill=255)
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)
    # Paket (isometrische Box)
    cx, cy, w, h = S // 2, 600, 300, 170
    top_face = [(cx, cy - 230), (cx + w, cy - 145), (cx, cy - 60), (cx - w, cy - 145)]
    left_face = [(cx - w, cy - 145), (cx, cy - 60), (cx, cy + 250), (cx - w, cy + 165)]
    right_face = [(cx, cy - 60), (cx + w, cy - 145), (cx + w, cy + 165), (cx, cy + 250)]
    d.polygon(left_face, fill=(237, 233, 254))
    d.polygon(right_face, fill=(196, 181, 253))
    d.polygon(top_face, fill=(255, 255, 255))
    # Klebeband: quer über den Deckel (Mitte hintere linke Kante → Mitte vordere rechte Kante) und die Seite hinab
    m1 = (cx - w / 2, cy - 187.5)
    m2 = (cx + w / 2, cy - 102.5)
    off = (0.13 * w, -0.13 * 85)
    a1, a2 = (m1[0] - off[0], m1[1] - off[1]), (m1[0] + off[0], m1[1] + off[1])
    b1, b2 = (m2[0] - off[0], m2[1] - off[1]), (m2[0] + off[0], m2[1] + off[1])
    d.polygon([a1, a2, b2, b1], fill=(253, 224, 71))
    d.polygon([b1, b2, (b2[0], b2[1] + 150), (b1[0], b1[1] + 150)], fill=(234, 179, 8))
    # Funkelstern oben rechts
    sx, sy, r = 760, 250, 120
    star = [(sx, sy - r), (sx + 28, sy - 28), (sx + r, sy), (sx + 28, sy + 28),
            (sx, sy + r), (sx - 28, sy + 28), (sx - r, sy), (sx - 28, sy - 28)]
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(glow).polygon(star, fill=(253, 224, 71, 200))
    img = Image.alpha_composite(img, glow.filter(ImageFilter.GaussianBlur(18)))
    d = ImageDraw.Draw(img)
    d.polygon(star, fill=(254, 249, 195))
    small = [(sx - 170, sy + 120 - 40), (sx - 160, sy + 120 - 10), (sx - 130, sy + 120), (sx - 160, sy + 130),
             (sx - 170, sy + 160), (sx - 180, sy + 130), (sx - 210, sy + 120), (sx - 180, sy + 110)]
    d.polygon(small, fill=(254, 249, 195))
    return img


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    img = draw()
    img.resize((256, 256), Image.LANCZOS).save(OUT / "magicbox.png")
    img.resize((256, 256), Image.LANCZOS).save(
        OUT / "magicbox.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("geschrieben:", OUT)


if __name__ == "__main__":
    main()
