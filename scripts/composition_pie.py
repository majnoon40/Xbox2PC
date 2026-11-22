#!/usr/bin/env python3
"""Pie chart of torrent payload composition by file type (for the docx report)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.font_manager as fm
fm.fontManager.addfont('/usr/share/fonts/truetype/chinese/NotoSansSC-Regular.ttf')
fm.fontManager.addfont('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
import matplotlib.pyplot as plt
plt.rcParams['font.sans-serif'] = ['Noto Sans SC', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

# Data computed from the parsed torrent metadata (parse_torrent.py output):
# .rpf 22 files 150.23 GiB | .ttpf 57 files 57.91 GiB | .xvd 1 file 0.32 GiB
# .dll 16 files ~0.011 GiB | .png 5 | .bin 2 | .xml 2 | .config 1 | .pri 1 | .alignmentchunk 1
labels = [
    ".rpf game archives (22 files)",
    ".ttpf asset databases (57 files)",
    ".xvd system volume (1 file)",
    "DLLs, XML, PNG, misc (28 files)",
]
sizes_gib = [150.23, 57.91, 0.325, 0.049]
counts = [22, 57, 1, 28]
total = sum(sizes_gib)
print(f"total GiB check: {total:.2f} (expected ~208.51)")

# Morandi low-saturation palette per skill chart rules
colors = ["6B9DAD", "C49B72", "7BA68A", "B87472"]
colors = ["#" + c for c in colors]

fig, ax = plt.subplots(figsize=(8, 8), constrained_layout=True)
wedges, texts, autotexts = ax.pie(
    sizes_gib,
    labels=labels,
    colors=colors,
    autopct=lambda p: f"{p:.1f}%",
    startangle=90,
    counterclock=False,
    wedgeprops={"linewidth": 1.5, "edgecolor": "white"},
    textprops={"fontsize": 11},
    pctdistance=0.72,
)
for t in autotexts:
    t.set_fontsize(10)
    t.set_color("white")
    t.set_fontweight("bold")
ax.set_title("Torrent payload composition by volume (208.51 GiB total)", fontsize=13, pad=14)

out = "/home/z/my-project/work/torrent-meta/composition_pie.png"
fig.savefig(out, dpi=200)
print("saved:", out)

from PIL import Image
im = Image.open(out).convert("L")
h = im.histogram()
print("verify:", im.size, "non-white ratio", round(1 - h[255] / sum(h), 4))
