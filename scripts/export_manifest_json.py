#!/usr/bin/env python3
"""Export exact torrent manifest (paths + byte sizes) as JSON for the docx generator."""
import json
import libtorrent as lt

data = open("/home/z/my-project/work/torrent-meta/meta_mirror.torrent", "rb").read()
ti = lt.torrent_info(data)
fs = ti.files()

entries = []
for i in range(fs.num_files()):
    f = fs.at(i)
    entries.append({"idx": i, "bytes": f.size, "path": f.path})

out = {
    "name": ti.name(),
    "total_bytes": ti.total_size(),
    "num_files": ti.num_files(),
    "piece_length": ti.piece_length(),
    "num_pieces": ti.num_pieces(),
    "creation_date": ti.creation_date(),
    "creator": ti.creator(),
    "comment": ti.comment(),
    "info_hash_v1": str(ti.info_hashes().v1),
    "files": entries,
}
with open("/home/z/my-project/work/torrent-meta/manifest.json", "w") as fp:
    json.dump(out, fp, indent=1)
print("files:", out["num_files"], "total:", out["total_bytes"], "hash:", out["info_hash_v1"])
