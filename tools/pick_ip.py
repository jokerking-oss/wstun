# -*- coding: utf-8 -*-
"""Cloudflare 边缘入口 IP 优选（只读探测：不改系统代理、不动隧道、不断网）

为什么要做：隧道段的瓶颈是「中国 → Cloudflare 边缘」这一段（实测 2.5-2.9 MB/s），
而 Cloudflare 是 Anycast —— 同一个域名会解析到不同出口 IP，不同 IP 在国内走的
国际路由差别巨大（有的走优质线路，有的走拥堵的普通线路）。

做法：拿一批 Cloudflare 官方段的候选 IP，并发测 TCP 握手延迟；对最快的一批再做
完整 TLS 握手 + 证书校验（SNI 用真实域名），确认它确实服务我们的 Pages 项目。
最后把最快的写进 client/goodip.json —— 客户端连的是 IP，TLS 的 SNI 仍是域名，
所以证书与路由都不受影响。

用法：
  python pick_ip.py              只测不改（默认，安全）
  python pick_ip.py --apply      额外写入 client/goodip.json（自动备份原文件）
"""
import argparse
import ipaddress
import json
import os
import random
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

sys.stdout.reconfigure(encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
TUNNEL = os.path.dirname(HERE)
CLIENT = os.path.join(TUNNEL, "client")
CFG_PATH = os.path.join(CLIENT, "wstun.json")
if not os.path.exists(CFG_PATH):
    # 开源仓库里真实的 wstun.json 被 .gitignore 排除，只有模板
    CFG_PATH = os.path.join(CLIENT, "wstun.example.json")
GOODIP_PATH = os.path.join(CLIENT, "goodip.json")

# Cloudflare 官方公布的 IPv4 段（cloudflare.com/ips-v4）
CF_SEGS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]


def sample_ips(seg, rng):
    """按段大小分层采样：大段多取、小段少取。"""
    net = ipaddress.ip_network(seg)
    n = net.num_addresses
    if n <= 1024:
        cnt = 8
    elif n <= 16384:
        cnt = 18
    elif n <= 65536:
        cnt = 28
    else:
        cnt = 40
    cnt = max(1, min(cnt, n - 2))
    out = set()
    lo, hi = 1, max(1, n - 2)
    guard = 0
    while len(out) < cnt and guard < cnt * 30:
        out.add(str(net.network_address + rng.randint(lo, hi)))
        guard += 1
    return out


def tcp_ms(ip, port, timeout):
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    dt = (time.perf_counter() - t0) * 1000.0
    try:
        s.close()
    except Exception:
        pass
    return dt


def tls_ms(ip, host, port, timeout):
    """完整 TLS 握手 + 证书校验。返回 (毫秒 or None, 错误说明)"""
    t0 = time.perf_counter()
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception as e:
        return None, type(e).__name__
    try:
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(raw, server_hostname=host)
    except ssl.SSLCertVerificationError:
        return None, "证书不匹配"
    except ssl.SSLError as e:
        return None, "TLS:%s" % (getattr(e, "reason", None) or type(e).__name__)
    except Exception as e:
        return None, type(e).__name__
    dt = (time.perf_counter() - t0) * 1000.0
    try:
        ss.close()
    except Exception:
        pass
    return dt, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="把最快 IP 写入 client/goodip.json")
    ap.add_argument("--top", type=int, default=14, help="进入 TLS 复验的候选数")
    ap.add_argument("--workers", type=int, default=32, help="并发数")
    ap.add_argument("--timeout", type=float, default=2.0, help="TCP 探测超时（秒）")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    if not os.path.exists(CFG_PATH):
        print("[x] 找不到 %s" % CFG_PATH)
        return 2
    try:
        cfg = json.load(open(CFG_PATH, encoding="utf-8"))
    except Exception as e:
        print("[x] 读取 wstun.json 失败: %s" % e)
        return 2
    u = urlparse(cfg.get("endpoint") or "")
    host = u.hostname
    if not host:
        print("[x] wstun.json 的 endpoint 无法解析出域名")
        return 2
    port = u.port or 443

    print("=" * 62)
    print("Cloudflare 边缘入口优选（只读探测）")
    print("=" * 62)
    print("目标域名 : %s" % host)
    print("端口     : %d" % port)

    dns_ips = []
    try:
        for it in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
            ip = it[4][0]
            if ":" not in ip and ip not in dns_ips:
                dns_ips.append(ip)
    except Exception as e:
        print("[!] DNS 解析失败: %s" % e)

    cur = None
    if os.path.exists(GOODIP_PATH):
        try:
            cur = json.load(open(GOODIP_PATH, encoding="utf-8")).get(host)
        except Exception:
            pass
    print("DNS 解析 : %s" % (", ".join(dns_ips) or "(无)"))
    print("当前记录 : %s" % (cur or "(无)"))
    print()

    cands = set(dns_ips)
    if cur:
        cands.add(cur)
    for seg in CF_SEGS:
        cands |= sample_ips(seg, rng)
    cands = sorted(cands)
    print("候选 %d 个，开始 TCP 探测（并发 %d，单个超时 %.1fs）..."
          % (len(cands), args.workers, args.timeout))

    t0 = time.time()
    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(tcp_ms, ip, port, args.timeout): ip for ip in cands}
        done = 0
        for f in as_completed(futs):
            done += 1
            ip = futs[f]
            try:
                ms = f.result()
            except Exception:
                ms = None
            if ms is not None:
                rows.append((ms, ip))
            if done % 80 == 0:
                print("   ... %d/%d  可达 %d" % (done, len(cands), len(rows)))
    rows.sort()
    print("TCP 可达 %d / %d，用时 %.1fs" % (len(rows), len(cands), time.time() - t0))
    if not rows:
        print("[x] 没有任何候选可达——网络不通或全部被拦。")
        return 1

    print()
    print("TCP 握手延迟最快 10 个：")
    for ms, ip in rows[:10]:
        tag = (" [DNS]" if ip in dns_ips else "") + (" [当前]" if ip == cur else "")
        print("   %8.0f ms   %-16s%s" % (ms, ip, tag))

    head = [ip for _, ip in rows[:args.top]]
    print()
    print("对最快 %d 个做完整 TLS 复验（SNI=%s，校验证书）..." % (len(head), host))
    verified = []
    with ThreadPoolExecutor(max_workers=min(16, len(head))) as ex:
        futs = {ex.submit(tls_ms, ip, host, port, 5.0): ip for ip in head}
        for f in as_completed(futs):
            ip = futs[f]
            try:
                ms, err = f.result()
            except Exception as e:
                ms, err = None, str(e)
            if ms is not None:
                verified.append((ms, ip))
            elif err:
                print("   %-16s 复验失败: %s" % (ip, err))
    verified.sort()

    print()
    if not verified:
        print("[x] 没有一个通过 TLS 复验（证书不匹配或握手失败）。")
        return 1
    print("=" * 62)
    print("TLS 握手延迟排名（越低越好）")
    print("=" * 62)
    for i, (ms, ip) in enumerate(verified, 1):
        tag = (" [DNS 原生]" if ip in dns_ips else "") + (" [当前在用]" if ip == cur else "")
        print("  %2d. %8.0f ms   %-16s%s" % (i, ms, ip, tag))

    best_ms, best_ip = verified[0]
    print()
    print("最优 : %s  (%.0f ms)" % (best_ip, best_ms))
    old = [m for m, i in verified if i == cur]
    if cur and old:
        print("当前 : %s  (%.0f ms)  ->  提升 %.0f ms" % (cur, old[0], old[0] - best_ms))
    elif cur:
        print("当前 : %s 未进复验前列（更慢或不可达）" % cur)
    print()

    if args.apply:
        if os.path.exists(GOODIP_PATH):
            try:
                bak = GOODIP_PATH + ".bak"
                with open(GOODIP_PATH, "rb") as f:
                    data = f.read()
                with open(bak, "wb") as f:
                    f.write(data)
                print("已备份原文件 -> %s" % os.path.basename(bak))
            except Exception as e:
                print("[!] 备份失败: %s" % e)
        try:
            d = {}
            if os.path.exists(GOODIP_PATH):
                d = json.load(open(GOODIP_PATH, encoding="utf-8"))
            d[host] = best_ip
            with open(GOODIP_PATH, "w", encoding="utf-8") as f:
                json.dump(d, f)
            print("已写入 %s : %s -> %s" % (os.path.basename(GOODIP_PATH), host, best_ip))
            print()
            print("注意：已在运行的隧道进程不会重读该文件，需重启隧道才生效。")
        except Exception as e:
            print("[x] 写入失败: %s" % e)
            return 1
    else:
        print("（未写入任何文件。确认没问题后再加 --apply。）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
