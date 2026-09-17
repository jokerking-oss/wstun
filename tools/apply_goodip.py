# -*- coding: utf-8 -*-
"""把优选出的边缘 IP 写入 client/goodip.json

⚠️ 关键顺序问题（踩过的坑 #18）：
正在运行的客户端进程在内存里持有 _GOODIP，**每次建连都会把 goodip.json 重写一遍**。
所以进程运行时改这个文件，会在几秒内被静默覆盖回去 —— 必须
「先停守护 → 再停客户端 → 写文件 → 起客户端 → 起守护」。

用法：
  python tools/apply_goodip.py --status              # 看当前状态
  python tools/apply_goodip.py 104.17.104.45         # 进程在跑时：只提示正确做法，不写
  python tools/apply_goodip.py 104.17.104.45 --restart   # 自动完成（会断网约 5–15 秒）
  python tools/apply_goodip.py 104.17.104.45 --force     # 明知会被覆盖仍写（仅调试）
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from urllib.parse import urlparse

sys.stdout.reconfigure(encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLIENT = os.path.join(ROOT, "client")
GOODIP = os.path.join(CLIENT, "goodip.json")
CFG = os.path.join(CLIENT, "wstun.example.json")
if not os.path.exists(CFG):
    CFG = os.path.join(CLIENT, "wstun.json")
GUARD = os.path.join(ROOT, "guard.py")
WSTUN = os.path.join(CLIENT, "wstun.py")
PORT = 10808


def interpreter(windowed=False):
    """优先用当前解释器；需要无窗口时找同目录的 pythonw。"""
    exe = sys.executable or "python"
    if not windowed:
        return exe
    name = "pythonw.exe" if os.name == "nt" else "pythonw"
    cand = os.path.join(os.path.dirname(exe), name)
    if os.path.exists(cand):
        return cand
    found = shutil.which(name) or shutil.which("pythonw") or shutil.which("python3")
    return found or exe


def port_listening():
    if os.name == "nt":
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                             capture_output=True).stdout.decode("latin1", "replace")
        pids = set()
        for ln in out.splitlines():
            p = ln.split()
            if len(p) >= 5 and p[0].upper() == "TCP" and p[3].upper() == "LISTENING" \
                    and p[1].endswith(":" + str(PORT)):
                pids.add(p[4])
        return pids
    # POSIX: 用 ss / lsof 兜底（只判断"有没有人监听"，不求精确 pid）
    for cmd in (["ss", "-lptn", "sport = :%d" % PORT], ["lsof", "-ti", "tcp:%d" % PORT]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                return {"?"}
        except FileNotFoundError:
            continue
    return set()


def host_of_cfg():
    try:
        return urlparse(json.load(open(CFG, encoding="utf-8")).get("endpoint") or "").hostname
    except Exception:
        return None


def show_status():
    host = host_of_cfg()
    try:
        d = json.load(open(GOODIP, encoding="utf-8"))
    except Exception:
        d = {}
    pids = port_listening()
    print("目标域名   : %s" % (host or "(配置里读不到 endpoint)"))
    print("goodip.json: %s" % json.dumps(d, ensure_ascii=False))
    if os.path.exists(GOODIP + ".bak"):
        try:
            print("备份 .bak  : %s" % json.dumps(json.load(open(GOODIP + ".bak", encoding="utf-8")),
                                                 ensure_ascii=False))
        except Exception:
            pass
    print("客户端     : %s" % ("运行中 pid=%s" % ",".join(sorted(pids)) if pids else "未运行"))
    gp = os.path.join(ROOT, "_runtime", "guard.pid")
    print("守护       : %s" % ("pid=%s" % open(gp, encoding="utf-8").read().strip()
                               if os.path.exists(gp) else "未运行"))
    print()
    print("⚠️ 客户端运行时改 goodip.json 会被它几秒内覆盖回去。")
    print("   要生效必须：停守护 → 停客户端 → 写文件 → 起客户端 → 起守护。")


def stop_guard():
    if not os.path.exists(GUARD):
        return
    r = subprocess.run([interpreter(), GUARD, "--stop"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    print("  停守护: exit=%s %s" % (r.returncode, (r.stdout or "").strip()[:120]))
    time.sleep(0.8)


def stop_tunnel():
    pids = port_listening()
    if not pids:
        print("  停客户端: 本来就没在跑")
        return
    for p in sorted(pids):
        print("  停客户端: pid=%s" % p)
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", p], capture_output=True)
        else:
            subprocess.run(["kill", "-f", p], capture_output=True)
    for _ in range(15):
        if not port_listening():
            return
        time.sleep(0.4)
    print("  [!] 端口 %d 仍未释放" % PORT)


def start_tunnel(wait=45):
    print("  起客户端: %s" % os.path.basename(interpreter(windowed=True)))
    flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0
    subprocess.Popen([interpreter(windowed=True), "-u", WSTUN],
                     creationflags=flags,
                     stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     close_fds=True)
    t0 = time.time()
    while time.time() - t0 < wait:
        if port_listening():
            print("  起客户端: 就绪，用时 %.1f 秒" % (time.time() - t0))
            return True
        time.sleep(0.5)
    print("  [x] 客户端 %d 秒内没起来" % wait)
    return False


def start_guard():
    if not os.path.exists(GUARD):
        return
    flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0
    subprocess.Popen([interpreter(windowed=True), GUARD, "--start"],
                     creationflags=flags,
                     stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     close_fds=True)
    time.sleep(1.5)
    print("  起守护: 已发起")


def write_ip(host, ip):
    old = {}
    if os.path.exists(GOODIP):
        try:
            old = json.load(open(GOODIP, encoding="utf-8"))
        except Exception:
            old = {}
        with open(GOODIP, "rb") as f:
            data = f.read()
        with open(GOODIP + ".bak", "wb") as f:
            f.write(data)
        print("  已备份原文件 -> goodip.json.bak")
    print("  原记录: %s" % json.dumps(old, ensure_ascii=False))
    old[host] = ip
    with open(GOODIP, "w", encoding="utf-8") as f:
        json.dump(old, f)
    print("  新记录: %s" % json.dumps(old, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip", nargs="?", help="要写入的边缘 IP")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--restart", action="store_true",
                    help="自动 停守护→停客户端→写→起客户端→起守护")
    ap.add_argument("--force", action="store_true", help="进程在跑时也强行写（会被覆盖，仅调试）")
    args = ap.parse_args()

    if args.status or not args.ip:
        show_status()
        return 0

    host = host_of_cfg()
    if not host:
        print("[x] 读不到 endpoint，无法确定要写哪个域名")
        return 2
    running = bool(port_listening())
    print("目标域名 : %s" % host)
    print("要写入   : %s" % args.ip)
    print("客户端   : %s" % ("运行中" if running else "未运行"))
    print()

    if running and not (args.restart or args.force):
        print("=" * 68)
        print("客户端正在运行 —— 现在写文件会被它几秒内覆盖回去。")
        print("运行中的进程在内存里持有旧 IP，每次建连都会重写这个文件。")
        print()
        print("请二选一：")
        print("  A) 自动完成（会断网约 5–15 秒）：")
        print("       python tools/apply_goodip.py %s --restart" % args.ip)
        print("  B) 手动：停守护 → 停客户端 → 跑本命令 → 起客户端 → 起守护")
        print("=" * 68)
        return 3

    if args.restart:
        print("[1/5] 停守护（否则它会在我们停完客户端后立刻把它拉起来，读到旧文件）")
        stop_guard()
        print("[2/5] 停客户端")
        stop_tunnel()
        print("[3/5] 写 goodip.json")
        write_ip(host, args.ip)
        print("[4/5] 起客户端")
        ok = start_tunnel()
        print("[5/5] 起守护")
        start_guard()
        time.sleep(3)
        pids = port_listening()
        print()
        print("=" * 68)
        print("客户端: %s" % ("运行中 pid=%s" % ",".join(sorted(pids)) if pids else "未运行"))
        try:
            cur = json.load(open(GOODIP, encoding="utf-8"))
            print("文件  : %s" % json.dumps(cur, ensure_ascii=False))
            print("生效  : %s" % ("是" if cur.get(host) == args.ip else "否（文件已被覆盖）"))
        except Exception as e:
            print("读文件失败: %s" % e)
        print("=" * 68)
        return 0 if ok else 1

    write_ip(host, args.ip)
    return 0


if __name__ == "__main__":
    sys.exit(main())
