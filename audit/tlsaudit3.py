#!/usr/bin/env python3
import sys, json, ssl, socket, hashlib, datetime, subprocess, re, ipaddress, concurrent.futures as cf
from cryptography import x509
from cryptography.hazmat.backends import default_backend

TIMEOUT = 9


def eid(ep):
    raw = "|".join([str(ep["server"]), str(ep["port"]), str(ep["sni"]),
                     "1" if ep.get("quic") else "0", "1" if ep.get("reality") else "0"])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def handshake(server, port, sni, verify):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = bool(verify)
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    with socket.create_connection((server, port), timeout=TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        with ctx.wrap_socket(s, server_hostname=sni) as ss:
            return {"der": ss.getpeercert(True), "version": ss.version(),
                    "cipher": (ss.cipher() or ("", "", 0))[0],
                    "alpn": ss.selected_alpn_protocol() or ""}


def openssl_verify(server, port, sni):
    is_ip = False
    try:
        ipaddress.ip_address(sni)
        is_ip = True
    except Exception:
        pass
    cmd = ["openssl", "s_client", "-connect", f"{server}:{port}", "-servername", sni, "-showcerts"]
    cmd += ["-verify_ip", sni] if is_ip else ["-verify_hostname", sni]
    try:
        p = subprocess.run(cmd, input=b"\n", capture_output=True, timeout=14)
    except Exception as e:
        return "", 0, f"TIMEOUT/{type(e).__name__}"
    text = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "ignore")
    chain = text.count("BEGIN CERTIFICATE")
    m = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", text)
    if m:
        code, msg = m.group(1), m.group(2)
        return ("OK" if code == "0" else f"FAIL: {code} ({msg})"), chain, ""
    if "no peer certificate" in text:
        return "FAIL: no peer certificate", chain, ""
    return "ERR: no verify result", chain, text[-80:].replace("\n", " ")


def audit(ep):
    rec = {"id": eid(ep), "reality": bool(ep.get("reality")), "quic": bool(ep.get("quic"))}
    if ep.get("quic"):
        rec.update(status="skip", note="QUIC/UDP 端点")
        return rec
    rec.update(status="fail", error="", fingerprint="", subject="", issuer="",
               sans="", not_before="", not_after="", days_left=None,
               self_signed=None, verify="", tls_version="", cipher="", alpn="",
               key_size=None, chain_len=0)
    try:
        h = handshake(ep["server"], ep["port"], ep["sni"], False)
        der = h["der"]
        cert = x509.load_der_x509_certificate(der, default_backend())
        rec.update(status="ok",
                   fingerprint=hashlib.sha256(der).hexdigest().upper(),
                   subject=cert.subject.rfc4514_string()[:120],
                   issuer=cert.issuer.rfc4514_string()[:120],
                   serial=format(cert.serial_number, "X")[:40],
                   sigalg=cert.signature_algorithm_oid._name,
                   key_type=type(cert.public_key()).__name__,
                   key_size=getattr(cert.public_key(), "key_size", None),
                   tls_version=h["version"], cipher=h["cipher"], alpn=h["alpn"],
                   self_signed=(cert.subject == cert.issuer))
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = san_ext.get_values_for_type(x509.DNSName) + [str(i) for i in san_ext.get_values_for_type(x509.IPAddress)]
            rec["sans"] = ";".join(names)[:200]
        except Exception:
            rec["sans"] = ""
        nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
        na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        rec["not_before"] = nb.strftime("%Y-%m-%d")
        rec["not_after"] = na.strftime("%Y-%m-%d")
        rec["days_left"] = (na - datetime.datetime.now(datetime.timezone.utc)).days
    except Exception as e:
        rec["error"] = f"{type(e).__name__}: {e}"[:120]

    v, chain, err = openssl_verify(ep["server"], ep["port"], ep["sni"])
    rec["verify"] = v if v else "ERR"
    rec["chain_len"] = chain
    if err:
        rec["verify_detail"] = err[:100]
    return rec


def main():
    eps = json.load(open(sys.argv[1]))
    results = []
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for r in ex.map(audit, eps):
            results.append(r)
    with open(sys.argv[2], "w") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    ok = sum(1 for r in results if r["status"] == "ok")
    print(f"endpoints={len(results)} cert_ok={ok}")


if __name__ == "__main__":
    main()
