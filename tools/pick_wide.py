# -*- coding: utf-8 -*-
"""多轮广域采样：复用 pick_ip.py 的探测函数，多个随机种子跑，汇总去重，
给出跨轮次最稳的 TLS 延迟排名。只读，不改任何文件。

用法：
  python _pick_wide.py --rounds 4 --workers 48 --timeout 1.6 --top 20
"""
import argparse
import importlib.util
import os
import random
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

# 动态导入同目录的 pick_ip.py
spec = importlib.util.spec_from_file_location("_pick_ip", os.path.join(HERE, "pick_ip.py"))
pk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--workers", type=int, default=48)
    ap.add_argument("--timeout", type=float, default=1.6)
    ap.add_argument("--top", type=int, default=20)
    args = ap.parse_args()

    cfg = pk.json.load(open(CFG_PATH, encoding="utf-8"))
    u = urlparse(cfg.get("endpoint") or "")
    host, port = u.hostname, (u.port or 443)

    dns_ips = []
    for it in pk.socket.getaddrinfo(host, port, proto=pk.socket.IPPROTO_TCP):
        ip = it[4][0]
        if ":" not in ip and ip not in dns_ips:
            dns_ips.append(ip)
    cur = None
    if os.path.exists(GOODIP_PATH):
        try:
            cur = pk.json.load(open(GOODIP_PATH, encoding="utf-8")).get(host)
        except Exception:
            pass

    print("=" * 66)
    print("多轮广域优选  host=%s port=%d" % (host, port))
    print("DNS=%s   当前记录=%s" % (", ".join(dns_ips), cur or "(无)"))
    print("=" * 66)

    tls_best = {}          # ip -> (ms, 命中轮次)
    tcp_hits = {}          # ip -> 最快 tcp ms
    all_seen = set()

    for r in range(args.rounds):
        rng = random.Random(1000 + r)
        cands = set(dns_ips)
        if cur:
            cands.add(cur)
        for seg in pk.CF_SEGS:
            cands |= pk.sample_ips(seg, rng)
        cands = sorted(cands)
        all_seen |= set(cands)

        t0 = time.time()
        rows = []
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(pk.tcp_ms, ip, port, args.timeout): ip for ip in cands}
            for f in as_completed(futs):
                ip = futs[f]
                try:
                    ms = f.result()
                except Exception:
                    ms = None
                if ms is not None:
                    rows.append((ms, ip))
                    if ip not in tcp_hits or ms < tcp_hits[ip]:
                        tcp_hits[ip] = ms
        rows.sort()
        head = [ip for _, ip in rows[:args.top]]
        ver = []
        with ThreadPoolExecutor(max_workers=min(16, len(head))) as ex:
            futs = {ex.submit(pk.tls_ms, ip, host, port, 5.0): ip for ip in head}
            for f in as_completed(futs):
                ip = futs[f]
                try:
                    ms, err = f.result()
                except Exception:
                    ms = None
                if ms is not None:
                    ver.append((ms, ip))
        ver.sort()
        for ms, ip in ver:
            if ip not in tls_best or ms < tls_best[ip][0]:
                tls_best[ip] = (ms, r + 1)
        print("[轮 %d] 候选 %d  TCP 可达 %d  TLS 通过 %d  用时 %.1fs  最快: %s"
              % (r + 1, len(cands), len(rows), len(ver),
                 time.time() - t0,
                 ("%s %.0fms" % (ver[0][1], ver[0][0])) if ver else "-"))

    print()
    print("=" * 66)
    print("跨轮次汇总（累计测试过 %d 个不同 IP）" % len(all_seen))
    print("=" * 66)
    rank = sorted(tls_best.items(), key=lambda kv: kv[1][0])
    for i, (ip, (ms, rd)) in enumerate(rank[:25], 1):
        tag = (" [DNS原生]" if ip in dns_ips else "") + (" [当前在用]" if ip == cur else "")
        print("  %2d. %7.0f ms   %-16s (首见第%d轮)%s" % (i, ms, ip, rd, tag))

    print()
    print("候选清单（逗号分隔，供测速用）：")
    print(",".join(ip for ip, _ in rank[:12]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
