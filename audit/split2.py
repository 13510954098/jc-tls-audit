#!/usr/bin/env python3
"""切分审计结果（只发布端点结果，不发布节点清单）。"""
import sys, os, json, datetime

tls_path, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
lines = [l for l in open(tls_path) if l.strip()]
parts = 8
size = (len(lines) + parts - 1) // parts
for i in range(parts):
    with open(os.path.join(outdir, f"endpoints_part-{i:02d}.jsonl"), "w") as f:
        f.writelines(lines[i * size:(i + 1) * size])
ok = sum(1 for l in lines if '"status": "ok"' in l)
json.dump({
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "endpoints": len(lines),
    "cert_ok": ok,
    "parts": parts,
}, open(os.path.join(outdir, "meta.json"), "w"), ensure_ascii=False, indent=2)
print("split done", len(lines), ok)
