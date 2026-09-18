# -*- coding: utf-8 -*-
"""优选 IP 的真实吞吐对比（只读：不改系统代理、不动隧道、不断网）

延迟低不等于带宽高 —— 必须实测。
做法：对每个候选边缘 IP，用同一 SNI（speed.cloudflare.com）直连该 IP，
拉一段固定大小的数据，测真实吞吐。Cloudflare 是 Anycast，连到哪个 IP
就走哪条路由，与 SNI 无关，所以这能反映「中国 → 该边缘 IP」的真实带宽。

用法：
  python pick_speed.py                     测当前 IP + 默认候选
  python pick_speed.py --ips 1.2.3.4,...   指定候选
"""
import argparse
import json
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout.reconfigure(encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
TUNNEL = os.path.dirname(HERE)
CLIENT = os.path.join(TUNNEL, "client")
GOODIP_PATH = os.path.join(CLIENT, "goodip.json")
CFG_PATH = os.path.join(CLIENT, "wstun.json")
if not os.path.exists(CFG_PATH):
    # 开源仓库里真实的 wstun.json 被 .gitignore 排除，只有模板
    CFG_PATH = os.path.join(CLIENT, "wstun.example.json")

# 用 Cloudflare 自家的测速端点拉数据。连的是指定 IP，所以路由由 IP 决定。
MEASURE_HOST = "speed.cloudflare.com"
MEASURE_PATH = "/__down?bytes=%d"


def pull(ip, nbytes, read_timeout=25.0, tls_timeout=6.0):
    """返回 dict: ok / status / bytes / secs / mbps / t_tls / err"""
    r = {"ip": ip, "ok": False, "status": None, "bytes": 0,
         "secs": 0.0, "mbps": 0.0, "t_tls": 0.0, "err": ""}
    t0 = time.perf_counter()
    try:
        raw = socket.create_connection((ip, 443), timeout=tls_timeout)
    except Exception as e:
        r["err"] = "TCP:" + type(e).__name__
        return r
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE       # 只测带宽，不校验证书
        ss = ctx.wrap_socket(raw, server_hostname=MEASURE_HOST)
    except Exception as e:
        r["err"] = "TLS:" + (getattr(e, "reason", None) or type(e).__name__)
        try:
            raw.close()
        except Exception:
            pass
        return r
    r["t_tls"] = time.perf_counter() - t0
    try:
        ss.settimeout(read_timeout)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\n"
               "User-Agent: curl/8.4.0\r\nAccept: */*\r\n"
               "Connection: close\r\n\r\n" % (MEASURE_PATH % nbytes, MEASURE_HOST))
        ss.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = ss.recv(65536)
            if not d:
                break
            buf += d
            if len(buf) > 65536:
                break
        head, _, rest = buf.partition(b"\r\n\r\n")
        line = head.split(b"\r\n")[0].decode("latin1", "replace")
        parts = line.split()
        if len(parts) >= 2:
            try:
                r["status"] = int(parts[1])
            except Exception:
                pass
        if r["status"] != 200:
            r["err"] = "HTTP %s" % r["status"]
            ss.close()
            return r
        total = len(rest)
        t1 = time.perf_counter()
        while True:
            try:
                d = ss.recv(262144)
            except socket.timeout:
                r["err"] = "读取超时"
                break
            if not d:
                break
            total += len(d)
        dt = max(1e-6, time.perf_counter() - t1)
        r["bytes"] = total
        r["secs"] = dt
        r["mbps"] = (total / 1048576.0) / dt
        r["ok"] = total > 0
    except Exception as e:
        r["err"] = "%s" % type(e).__name__
    finally:
        try:
            ss.close()
        except Exception:
            pass
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ips", default="", help="逗号分隔的候选 IP")
    ap.add_argument("--bytes", type=int, default=8 * 1024 * 1024, help="每个 IP 拉多少字节")
    ap.add_argument("--rounds", type=int, default=1, help="每个 IP 重复几轮，取最好")
    ap.add_argument("--workers", type=int, default=4, help="并发数；1 = 串行（最准，排除互相抢带宽）")
    args = ap.parse_args()

    cands = []
    cur = None
    if os.path.exists(GOODIP_PATH):
        try:
            d = json.load(open(GOODIP_PATH, encoding="utf-8"))
            if os.path.exists(CFG_PATH):
                from urllib.parse import urlparse
                h = urlparse(json.load(open(CFG_PATH, encoding="utf-8")).get("endpoint") or "").hostname
                cur = d.get(h)
        except Exception:
            pass
    if cur:
        cands.append(cur)
    if args.ips:
        cands += [x.strip() for x in args.ips.split(",") if x.strip()]
    else:
        cands += ["104.17.176.26", "104.17.111.61", "104.17.215.27",
                  "104.19.33.174", "104.17.104.45", "162.159.158.159",
                  "162.159.141.155", "104.27.59.39"]
    # 去重保序
    seen = set()
    cands = [x for x in cands if not (x in seen or seen.add(x))]

    print("=" * 64)
    print("边缘 IP 真实吞吐对比（只读；直连该 IP，不经隧道）")
    print("=" * 64)
    print("测速源   : %s%s" % (MEASURE_HOST, MEASURE_PATH % args.bytes))
    print("每 IP    : %.1f MB，重复 %d 轮" % (args.bytes / 1048576.0, args.rounds))
    print("当前记录 : %s" % (cur or "(无)"))
    print("候选     : %d 个" % len(cands))
    print()

    results = {}
    for rd in range(1, args.rounds + 1):
        if args.rounds > 1:
            print("--- 第 %d 轮 ---" % rd)
        # 并发跑，缩短总时长；--workers 1 则串行（最准）
        with ThreadPoolExecutor(max_workers=max(1, min(args.workers, len(cands)))) as ex:
            futs = {ex.submit(pull, ip, args.bytes): ip for ip in cands}
            for f in as_completed(futs):
                ip = futs[f]
                try:
                    r = f.result()
                except Exception as e:
                    r = {"ip": ip, "ok": False, "err": type(e).__name__,
                         "mbps": 0.0, "bytes": 0, "secs": 0.0, "t_tls": 0.0}
                if r["ok"]:
                    print("  %-16s  %7.2f MB/s   (%.1f MB / %.2fs, TLS %.0fms)%s"
                          % (ip, r["mbps"], r["bytes"] / 1048576.0, r["secs"],
                             r["t_tls"] * 1000,
                             "  [当前]" if ip == cur else ""))
                    old = results.get(ip)
                    if not old or r["mbps"] > old["mbps"]:
                        results[ip] = r
                else:
                    print("  %-16s  失败: %s%s" % (ip, r["err"], "  [当前]" if ip == cur else ""))

    print()
    print("=" * 64)
    print("吞吐排名（MB/s，越高越好）")
    print("=" * 64)
    rank = sorted(results.values(), key=lambda x: -x["mbps"])
    for i, r in enumerate(rank, 1):
        tag = "  [当前在用]" if r["ip"] == cur else ""
        print("  %2d.  %7.2f MB/s   %-16s  TLS %4.0fms%s"
              % (i, r["mbps"], r["ip"], r["t_tls"] * 1000, tag))

    if rank:
        best = rank[0]
        print()
        print("最快 : %s   %.2f MB/s" % (best["ip"], best["mbps"]))
        if cur and cur in results:
            c = results[cur]["mbps"]
            print("当前 : %s   %.2f MB/s   ->  %+.2f MB/s (%.0f%%)"
                  % (cur, c, best["mbps"] - c,
                     (best["mbps"] / c - 1) * 100 if c else 0))
        elif cur:
            print("当前 : %s   本轮未测出（不可达或失败）" % cur)
        print()
        print("最优 IP = %s" % best["ip"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
