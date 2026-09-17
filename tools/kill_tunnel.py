# -*- coding: utf-8 -*-
"""关掉占用 10808 端口的隧道进程（「② 恢复原样.bat」用）。"""
import os
import socket
import subprocess
import sys
import time

PORT = 10808


def listeners():
    out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                         capture_output=True).stdout.decode("latin1", "replace")
    pids = set()
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" \
                and parts[3].upper() == "LISTENING" and parts[1].endswith(":" + str(PORT)):
            pids.add(parts[4])
    return pids


def main():
    pids = listeners()
    if not pids:
        print("       隧道本来就没在运行。")
        return 0
    for p in sorted(pids):
        r = subprocess.run(["taskkill", "/F", "/PID", p], capture_output=True)
        if r.returncode == 0:
            print("       已停止隧道进程 pid=%s" % p)
        else:
            err = r.stdout.decode("gbk", "replace").strip() or r.stderr.decode("gbk", "replace").strip()
            print("       停止 pid=%s 失败：%s" % (p, err[:100]))
    time.sleep(1.0)
    s = socket.socket()
    s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", PORT))
        print("       [warn] 端口 %d 仍被占用，可能需要几秒才释放。" % PORT)
    except Exception:
        print("       端口 %d 已释放。" % PORT)
    finally:
        s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
