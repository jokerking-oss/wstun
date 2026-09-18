# -*- coding: utf-8 -*-
"""决胜复测：对少数候选做多轮「串行 + 轮间冷却」测量，按均值与最差表现选最稳的。

为什么要冷却：短时间内连续大量下载会被 speed.cloudflare.com 限流，
表现为某些样本突然掉到 1.x MB/s，污染排名。

只读，不改任何文件。
用法：python _tiebreak.py --ips a,b,c --rounds 3 --gap 8 --bytes 8388608
"""
import argparse
import importlib.util
import os
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))

spec = importlib.util.spec_from_file_location("_pick_speed",
                                              os.path.join(HERE, "pick_speed.py"))
ps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ps)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ips", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--gap", type=float, default=8.0, help="轮间冷却秒数")
    ap.add_argument("--bytes", type=int, default=8 * 1024 * 1024)
    args = ap.parse_args()

    ips = [x.strip() for x in args.ips.split(",") if x.strip()]
    samples = {ip: [] for ip in ips}
    tls = {ip: [] for ip in ips}

    print("=" * 70)
    print("决胜复测（串行，每轮之间冷却 %.0fs）" % args.gap)
    print("=" * 70)
    for rd in range(1, args.rounds + 1):
        print("--- 第 %d 轮 ---" % rd)
        for ip in ips:
            r = ps.pull(ip, args.bytes)
            if r["ok"]:
                samples[ip].append(r["mbps"])
                tls[ip].append(r["t_tls"] * 1000)
                print("  %-16s %6.2f MB/s   (%.2fs, TLS %.0fms)"
                      % (ip, r["mbps"], r["secs"], r["t_tls"] * 1000))
            else:
                print("  %-16s 失败: %s" % (ip, r["err"]))
        if rd < args.rounds:
            time.sleep(args.gap)

    print()
    print("=" * 70)
    print("汇总（按『最差表现』降序 —— 最稳的排前面）")
    print("=" * 70)
    rows = []
    for ip in ips:
        s = samples[ip]
        if not s:
            rows.append((ip, None, None, None, None, 0))
            continue
        rows.append((ip, sum(s) / len(s), min(s), max(s),
                     sum(tls[ip]) / len(tls[ip]) if tls[ip] else 0, len(s)))
    rows.sort(key=lambda r: (r[2] is None, -(r[2] or 0), -(r[1] or 0)))
    print("  %-16s %8s %8s %8s %8s %5s" % ("IP", "均值", "最差", "最好", "TLS均", "样本"))
    for ip, mean, lo, hi, t, n in rows:
        if mean is None:
            print("  %-16s %8s" % (ip, "全部失败"))
            continue
        print("  %-16s %7.2f %8.2f %8.2f %7.0fms %5d" % (ip, mean, lo, hi, t, n))

    good = [r for r in rows if r[1] is not None]
    if good:
        best = good[0]
        print()
        print(">>> 推荐（最稳）: %s   均值 %.2f  最差 %.2f MB/s"
              % (best[0], best[1], best[2]))
        bymean = sorted(good, key=lambda r: -r[1])
        print(">>> 按均值最快  : %s   均值 %.2f  最差 %.2f MB/s"
              % (bymean[0][0], bymean[0][1], bymean[0][2]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
