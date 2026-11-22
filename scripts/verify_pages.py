#!/usr/bin/env python3
"""Programmatic visual verification of the rendered report pages (image input unavailable).
Checks: blank pages, cover darkness, ink coverage distribution, per-page content presence."""
import glob
from PIL import Image

pages = sorted(glob.glob("/tmp/render/page-*.jpg"))
print(f"pages: {len(pages)}")
issues = []
for p in pages:
    im = Image.open(p).convert("L")
    w, h = im.size
    hist = im.histogram()
    nonwhite = 1 - hist[255] / sum(hist)
    mean = sum(i * hist[i] for i in range(256)) / sum(hist)
    tag = ""
    if nonwhite < 0.005:
        tag = "  <-- BLANK?"
        issues.append(p)
    print(f"{p.split('/')[-1]}: {w}x{h}  ink={nonwhite:.4f}  mean_lum={mean:.0f}{tag}")

# cover check: page 1 should be mostly dark (DM-1 bg #162235)
im1 = Image.open(pages[0]).convert("L")
m1 = sum(i * im1.histogram()[i] for i in range(256)) / sum(im1.histogram())
print(f"\ncover mean luminance: {m1:.0f} (dark cover expected < 100)")
# crop right half of cover (text zone) to confirm text present
right = im1.crop((im1.size[0] // 2, 0, im1.size[0], im1.size[1]))
h = right.histogram()
print(f"cover right-half non-white: {1 - h[255] / sum(h):.4f}")

print("\nISSUES:" if issues else "\nNo blank pages detected.")
for i in issues:
    print(" ", i)
