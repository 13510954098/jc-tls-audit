#!/usr/bin/env python3
import sys, json, collections
import yaml

src, out_ep, out_nodes = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = yaml.safe_load(open(src, encoding="utf-8"))
proxies = cfg.get("proxies") or []

endpoints = collections.OrderedDict()
nodes = []

for x in proxies:
    t = (x.get("type") or "").lower()
    tls = bool(x.get("tls"))
    reality = bool(x.get("reality-opts"))
    if t in ("trojan", "hysteria", "hysteria2", "anytls"):
        tls = True
    if reality:
        tls = True
    sni = x.get("servername") or x.get("sni") or ""
    ep = ""
    if tls:
        quic = t in ("hysteria", "hysteria2")
        ep = {"server": str(x.get("server")), "port": int(x.get("port")),
              "sni": sni or str(x.get("server")), "quic": quic, "reality": reality, "nodes": 0}
        key = ("Q" if quic else "T") + ("R|" if reality else "N|") + f"{ep['server']}|{ep['port']}|{ep['sni']}"
        if key not in endpoints:
            endpoints[key] = ep
        endpoints[key]["nodes"] += 1
        ep = key
    nodes.append({"name": x.get("name", ""), "type": t, "server": str(x.get("server")),
                  "port": int(x.get("port")), "tls": tls, "reality": reality, "sni": sni,
                  "skip": bool(x.get("skip-cert-verify")), "ep": ep,
                  "cipher": x.get("cipher") or x.get("encryption") or "",
                  "network": x.get("network") or "", "flow": x.get("flow") or "",
                  "auth": bool(x.get("username") or x.get("password") or x.get("uuid") or x.get("auth")),
                  "udp": bool(x.get("udp"))})

json.dump(list(endpoints.values()), open(out_ep, "w"), ensure_ascii=False)
json.dump(nodes, open(out_nodes, "w"), ensure_ascii=False)
print(f"nodes={len(nodes)} endpoints={len(endpoints)}")
