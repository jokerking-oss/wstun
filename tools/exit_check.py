# -*- coding: utf-8 -*-
"""经本地隧道(127.0.0.1:10808)快速查看当前出口 IP / ASN —— 几秒钟出结果。

用法：python exit_check.py
退出码：0 = 出口是住宅 IP（好）；2 = 出口是机房/代理 IP（漏了）；1 = 连不上隧道
"""
import socket
import ssl
import struct
import sys
import json

PROXY = ("127.0.0.1", 10808)


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


def http_get(host, path, port=443, use_tls=True, timeout=20):
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
    while len(buf) < 131072:
        try:
            c = raw.recv(8192)
        except socket.timeout:
            break
        if not c:
            break
        buf += c
    raw.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode("latin1", "replace"), body


def main():
    print("正在经隧道 127.0.0.1:10808 查询出口 ...")
    data = None

    # 源 1：api.ip.sb（HTTPS）
    try:
        st, body = http_get("api.ip.sb", "/geoip")
        d = json.loads(body.decode("utf-8", "replace"))
        data = {
            "ip": d.get("ip"),
            "asn": "AS%s" % d.get("asn") if d.get("asn") else "?",
            "org": d.get("asn_organization") or d.get("organization") or "?",
            "country": d.get("country") or "?",
            "city": d.get("city") or "?",
            "hosting": None,
            "proxy": None,
        }
    except Exception as e:
        print("  [源1 api.ip.sb 失败] %s" % str(e)[:70])

    # 源 2：ip-api.com（明文 80）
    if not data or not data.get("ip"):
        try:
            st, body = http_get("ip-api.com", "/json/?fields=query,as,asname,isp,"
                                "country,city,hosting,proxy,mobile", port=80, use_tls=False)
            d = json.loads(body.decode("utf-8", "replace"))
            data = {
                "ip": d.get("query"),
                "asn": d.get("as") or "?",
                "org": d.get("asname") or d.get("isp") or "?",
                "country": d.get("country") or "?",
                "city": d.get("city") or "?",
                "hosting": d.get("hosting"),
                "proxy": d.get("proxy"),
                "mobile": d.get("mobile"),
            }
        except Exception as e:
            print("  [源2 ip-api.com 失败] %s" % str(e)[:70])

    if not data or not data.get("ip"):
        print()
        print("  [x] 查不到出口 IP —— 隧道可能没在运行，或边缘连不上。")
        print("      请先双击「① 开启住宅上网.bat」。")
        return 1

    print()
    print("=" * 62)
    print("  出口 IP  : %s" % data["ip"])
    print("  ASN      : %s" % data["asn"])
    print("  运营商   : %s" % str(data["org"])[:60])
    print("  位置     : %s / %s" % (data["country"], data["city"]))
    bad = (data.get("hosting") is True) or (data.get("proxy") is True)
    plain = "AS13335" in str(data["asn"]) or "Cloudflare" in str(data["org"])
    print("-" * 62)
    if bad or plain:
        print("  判定     : [x] 机房/代理 IP —— 漏了！")
        if plain:
            print("             这是 Cloudflare 的出口，说明流量没走住宅代理。")
        print("             请关掉所有浏览器窗口后重新双击「① 开启住宅上网.bat」，")
        print("             再双击「② 恢复原样.bat」→「①」重启一遍。")
        return 2
    print("  判定     : [ok] 住宅 IP，纯净（hosting=false / proxy=false）")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("[x] 出错：%s" % e)
        sys.exit(1)
