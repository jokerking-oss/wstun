# -*- coding: utf-8 -*-
"""IP 纯净度检测（check-ip.bat 调用）—— 经本地隧道 10808 打多个权威检测站。

预期：全部显示 YOUR-RESIDENTIAL-HOST / AS26407 Carolina Digital（住宅、hosting=false）。
只要出现 AS13335(Cloudflare) 或 hosting/proxy=true，就说明有流量漏成了机房 IP。

用法：python purity_check.py
退出码：0 = 全部干净；2 = 发现泄漏；1 = 隧道不通
"""
import json
import re
import socket
import ssl
import struct
import sys

PROXY = ("127.0.0.1", 10808)
EXPECT_IP = "YOUR-RESIDENTIAL-HOST"


def socks_connect(host, port, timeout=15):
    s = socket.create_connection(PROXY, timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if len(r) < 2 or r[1] != 0:
        raise OSError("SOCKS 握手失败")
    hb = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
    r = s.recv(4)
    if len(r) < 4 or r[1] != 0:
        raise OSError("SOCKS 连接被拒 rep=%s" % (r[1] if len(r) > 1 else "?"))
    atyp = r[3]
    if atyp == 1:
        s.recv(4)
    elif atyp == 3:
        s.recv(s.recv(1)[0])
    elif atyp == 4:
        s.recv(16)
    s.recv(2)
    return s


def dechunk(body):
    """HTTP/1.1 分块传输解码。

    不做这一步的话，像 api.ip.sb 这种用 chunked 返回 JSON 的站会把
    '9d\\r\\n{...}' 原样交出来，json.loads 直接报 Extra data。
    """
    out = b""
    try:
        while True:
            i = body.find(b"\r\n")
            if i < 0:
                break
            size_line = body[:i].split(b";")[0].strip()
            if not size_line:
                break
            n = int(size_line, 16)
            if n == 0:
                break
            out += body[i + 2:i + 2 + n]
            body = body[i + 2 + n + 2:]
    except Exception:
        return out or body
    return out or body


def http_get(host, path, port=443, use_tls=True, timeout=20, limit=262144):
    raw = socks_connect(host, port, timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=host)
    raw.settimeout(timeout)
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\n"
           "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/124.0 Safari/537.36\r\n"
           "Accept: */*\r\nConnection: close\r\n\r\n" % (path, host))
    raw.sendall(req.encode())
    buf = b""
    while len(buf) < limit:
        try:
            c = raw.recv(8192)
        except socket.timeout:
            break
        if not c:
            break
        buf += c
    raw.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in head.lower():
        body = dechunk(body)
    return head.split(b"\r\n")[0].decode("latin1", "replace"), body


def j(body):
    return json.loads(body.decode("utf-8", "replace"))


def src_ipsb():
    _, b = http_get("api.ip.sb", "/geoip")
    d = j(b)
    return d.get("ip"), "AS%s" % d.get("asn", "?"), d.get("asn_organization") or "?"


def src_ipapi():
    _, b = http_get("ip-api.com", "/json/?fields=query,as,asname,isp,hosting,proxy",
                    port=80, use_tls=False)
    d = j(b)
    flags = []
    if d.get("hosting"):
        flags.append("hosting=true")
    if d.get("proxy"):
        flags.append("proxy=true")
    return d.get("query"), d.get("as") or "?", (d.get("asname") or d.get("isp") or "?") \
        + (" [" + ",".join(flags) + "]" if flags else "")


def src_ipify():
    _, b = http_get("api.ipify.org", "/?format=json")
    return j(b).get("ip"), "", ""


def src_ipinfo():
    _, b = http_get("ipinfo.io", "/json")
    d = j(b)
    return d.get("ip"), "", "%s / %s %s" % (d.get("org", "?"), d.get("city", "?"),
                                            d.get("country", "?"))


def src_cf_trace():
    _, b = http_get("1.1.1.1", "/cdn-cgi/trace")
    t = b.decode("utf-8", "replace")
    g = lambda k: (re.search(r"^%s=(.*)$" % k, t, re.M) or [None, "?"])[1]
    return g("ip"), "", "warp=%s  colo=%s" % (g("warp"), g("colo"))


def src_ipme():
    _, b = http_get("ip.me", "/")
    m = re.search(rb"\b(\d{1,3}(?:\.\d{1,3}){3})\b", b)
    return (m.group(1).decode() if m else None), "", ""


def src_ipapico():
    _, b = http_get("ipapi.co", "/json/")
    d = j(b)
    return d.get("ip"), d.get("asn") or "", str(d.get("org") or "?")


SOURCES = [
    ("api.ip.sb", src_ipsb),
    ("ip-api.com", src_ipapi),
    ("api.ipify.org", src_ipify),
    ("ipinfo.io", src_ipinfo),
    ("1.1.1.1/cdn-cgi/trace", src_cf_trace),
    ("ip.me", src_ipme),
    ("ipapi.co", src_ipapico),
]


def main():
    # 先确认隧道在
    try:
        s = socket.create_connection(PROXY, timeout=3)
        s.close()
    except Exception:
        print("  [x] 隧道没在运行（127.0.0.1:10808 连不上）。")
        print("      请先双击「① 开启住宅上网.bat」。")
        return 1

    print()
    print("%-24s %-17s %-12s %s" % ("检测站", "看到的出口 IP", "ASN", "运营商 / 标记"))
    print("-" * 92)

    ips = []
    leaked = False
    okn = 0
    for name, fn in SOURCES:
        try:
            ip, asn, org = fn()
        except Exception as e:
            print("%-24s %s" % (name, "这个站没返回（%s）—— 通常是它自己限流，看其它站即可"
                                % str(e)[:36]))
            continue
        okn += 1
        if ip:
            ips.append(ip)
        bad = ("13335" in str(asn)) or ("cloudflare" in str(org).lower()) \
            or ("hosting=true" in str(org)) or ("proxy=true" in str(org))
        if bad:
            leaked = True
        if ip and ip != EXPECT_IP:
            leaked = True
        print("%-24s %-17s %-12s %s" % (name, ip or "?", asn or "-", str(org)[:40]))

    print("-" * 92)
    if not ips:
        print("  [x] 一个站都没返回结果 —— 隧道可能在，但出不去。")
        return 1

    uniq = sorted(set(ips))
    print("  共 %d 个站返回，出口 IP：%s" % (okn, "、".join(uniq)))
    print()
    if leaked or uniq != [EXPECT_IP]:
        print("  判定：[x] 有问题 —— 出口不是纯住宅（见上表标注）。")
        print("        先把所有浏览器窗口关掉，再重跑「① 开启住宅上网.bat」。")
        return 2
    print("  判定：[ok] 全部 %d 个站都看到 %s，住宅 IP，无机房泄漏。" % (okn, EXPECT_IP))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("  [x] 出错：%s" % e)
        sys.exit(1)
