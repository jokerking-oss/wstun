# -*- coding: utf-8 -*-
"""优选 IP 落地：停守护 -> 停隧道 -> 写 goodip.json -> 起隧道 -> 验证 -> 起守护
并做「隧道内真实吞吐」的前后对比。

为什么要写成一个自主脚本（而不是一步步手动执行）：
  系统代理指着 127.0.0.1:10808，隧道一停，所有走系统代理的程序（包括调用本
  脚本的 AI 助手自身）都会立刻断链。所以整条流程必须脱离调用者独立跑完，
  结果只写进文件，事后读取。

保护调用者不断链的做法：
  在停隧道之前，**临时把系统代理设为「关闭」**（直连）。因为助手的后端是国内
  域名，直连可达，所以这段窗口期内它不会失联；隧道起来后立刻恢复代理指向 10808。
  全程用 try/finally 保证最终一定恢复。

用法：
  # 推荐：用 spawn_detached.py 以 WMI 方式启动（脱离调用方进程树，断链也能跑完）
  python tools/spawn_detached.py tools/apply_wide.py --ip <边缘IP> --grace 5

  python tools/apply_wide.py --ip <边缘IP>       # 直接前台跑（调试用）
  （<边缘IP> 由 pick_ip.py / pick_speed.py / tiebreak.py 选出来）
"""
import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TUNNEL = os.path.dirname(HERE)
CLIENT = os.path.join(TUNNEL, "client")
RUNTIME = os.path.join(TUNNEL, "_runtime")
GOODIP = os.path.join(CLIENT, "goodip.json")
CFG = os.path.join(CLIENT, "wstun.json")
GUARD = os.path.join(TUNNEL, "guard.py")
PROXY_TOOL = os.path.join(HERE, "proxy.py")
WSTUN = os.path.join(CLIENT, "wstun.py")
LOG = os.path.join(RUNTIME, "apply.log")
REPORT = os.path.join(RUNTIME, "apply_report.json")
PORT = 10808

# 开源版不内置默认 IP —— 每个网络环境的最优边缘 IP 都不同，
# 请先用 pick_ip.py / pick_speed.py / tiebreak.py 选好，再用 --ip 传进来。
DEFAULT_IP = ""

_lines = []


def log(msg):
    """写日志。

    注意：本脚本可能由 WMI 创建进程启动（脱离调用方进程树），那种情况下
    没有 stdout，所以日志必须自己落盘，不能依赖重定向。
    """
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    _lines.append(line)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    try:
        print(line, flush=True)
    except Exception:
        pass


def _py(path_name):
    # 开源版：优先用运行本脚本的解释器（同一环境里必有 pythonw）
    here = os.path.dirname(sys.executable)
    for c in [os.path.join(here, path_name),
              sys.executable]:
        if os.path.exists(c):
            return c
    return sys.executable


PY = _py("python.exe")
PYW = _py("pythonw.exe")


# ---------------------------------------------------------------- 进程工具
def py_procs():
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*' } | "
          "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=90)
        out = r.stdout.decode("utf-8", "replace").strip()
        if not out:
            return []
        d = json.loads(out)
        if isinstance(d, dict):
            d = [d]
        return d
    except Exception:
        return []


def roles():
    t, g = [], []
    for p in py_procs():
        cl = p.get("CommandLine") or ""
        pid = int(p.get("ProcessId") or 0)
        if "wstun.py" in cl:
            t.append(pid)
        elif "guard.py" in cl:
            g.append(pid)
    return t, g


def kill_pids(pids, tag):
    for p in sorted(pids):
        try:
            r = subprocess.run(["taskkill", "/F", "/PID", str(p)],
                               capture_output=True, timeout=15)
            log("  已终止 %s pid=%s (rc=%d)" % (tag, p, r.returncode))
        except Exception as e:
            log("  终止 %s pid=%s 失败: %s" % (tag, p, e))


def listeners(port=PORT):
    out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                         capture_output=True).stdout.decode("latin1", "replace")
    pids = set()
    for ln in out.splitlines():
        a = ln.split()
        if len(a) >= 5 and a[0].upper() == "TCP" and a[3].upper() == "LISTENING" \
                and a[1].endswith(":" + str(port)):
            pids.add(a[4])
    return pids


def port_alive(port=PORT, timeout=2.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def proxy_cmd(arg):
    r = subprocess.run([PY, PROXY_TOOL, arg], capture_output=True, timeout=40)
    out = (r.stdout or b"").decode("utf-8", "replace").strip()
    return r.returncode, out


def read_proxy():
    import winreg
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                       r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
    d = {}
    for n in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
        try:
            d[n] = winreg.QueryValueEx(k, n)[0]
        except FileNotFoundError:
            d[n] = None
    winreg.CloseKey(k)
    return d


# ---------------------------------------------------------------- 测速
def tunnel_pull(nbytes=8 * 1024 * 1024, timeout=45.0):
    """经隧道（127.0.0.1:10808 CONNECT）拉数据，测真实吞吐。"""
    r = {"ok": False, "mbps": 0.0, "secs": 0.0, "bytes": 0, "err": "",
         "t_connect": 0.0}
    s = None
    try:
        t0 = time.perf_counter()
        s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
        req = ("CONNECT speed.cloudflare.com:443 HTTP/1.1\r\n"
               "Host: speed.cloudflare.com:443\r\n\r\n").encode()
        s.sendall(req)
        # 逐字节读到 header 结束，避免多读到 TLS 数据
        buf = b""
        while not buf.endswith(b"\r\n\r\n"):
            c = s.recv(1)
            if not c:
                break
            buf += c
            if len(buf) > 8192:
                break
        line = buf.split(b"\r\n")[0].decode("latin1", "replace")
        if " 200" not in line:
            r["err"] = "CONNECT 失败: %s" % line
            return r
        r["t_connect"] = time.perf_counter() - t0

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname="speed.cloudflare.com")
        ss.settimeout(timeout)
        ss.sendall(("GET /__down?bytes=%d HTTP/1.1\r\nHost: speed.cloudflare.com\r\n"
                    "User-Agent: curl/8.4.0\r\nAccept: */*\r\n"
                    "Connection: close\r\n\r\n" % nbytes).encode())
        head = b""
        while b"\r\n\r\n" not in head:
            d = ss.recv(65536)
            if not d:
                break
            head += d
            if len(head) > 65536:
                break
        status = head.split(b"\r\n")[0].decode("latin1", "replace")
        if " 200" not in status:
            r["err"] = "HTTP: %s" % status
            return r
        _, _, rest = head.partition(b"\r\n\r\n")
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
        r.update(ok=total > 0, bytes=total, secs=dt, mbps=(total / 1048576.0) / dt)
        try:
            ss.close()
        except Exception:
            pass
    except Exception as e:
        r["err"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return r


def log_tail(n=4):
    p = os.path.join(CLIENT, "wstun.log")
    try:
        ls = open(p, encoding="utf-8", errors="replace").read().splitlines()
        return ls[-n:]
    except Exception:
        return []


# ---------------------------------------------------------------- 主流程
def work(ip, grace):
    os.makedirs(RUNTIME, exist_ok=True)
    rep = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "target_ip": ip,
           "steps": [], "before": None, "after": None, "ok": False, "notes": []}
    log("=" * 66)
    log("优选 IP 落地：%s" % ip)
    log("=" * 66)
    log("缓冲 %.0f 秒（让调用方先把本轮收尾）..." % grace)
    time.sleep(grace)

    host = None
    try:
        cfg = json.load(open(CFG, encoding="utf-8"))
        from urllib.parse import urlparse
        host = urlparse(cfg.get("endpoint") or "").hostname
    except Exception as e:
        log("[x] 读配置失败: %s" % e)
    log("目标域名: %s" % host)

    t_all, g_all = roles()
    log("起始进程: 隧道 %s / 守护 %s" % (t_all or "无", g_all or "无"))
    rep["steps"].append({"step": "init", "tunnels": t_all, "guards": g_all})

    backup = read_proxy()
    log("起始系统代理: %s" % json.dumps(backup, ensure_ascii=False))
    rep["proxy_before"] = backup

    # ---- 0) 变更前：经隧道测一次吞吐
    log("")
    log("[0] 变更前：经隧道实测吞吐（8MB）...")
    b = tunnel_pull()
    rep["before"] = b
    if b["ok"]:
        log("    变更前 = %.2f MB/s  (%.2fs, 隧道建连 %.2fs)"
            % (b["mbps"], b["secs"], b["t_connect"]))
    else:
        log("    变更前测速失败: %s" % b["err"])
    path_before = [l for l in log_tail(8) if "->" in l]
    rep["path_before"] = path_before[-1:] if path_before else []

    try:
        # ---- 1) 停守护（必须先停，否则它会立刻把隧道拉回来）
        log("")
        log("[1] 停止守护 ...")
        r = subprocess.run([PY, GUARD, "--stop"], capture_output=True, timeout=60)
        log("    guard --stop: %s" % (r.stdout or b"").decode("utf-8", "replace").strip())
        time.sleep(1.0)
        _, g = roles()
        if g:
            log("    仍有守护残留 %s，强制清理" % g)
            kill_pids(g, "守护")
        time.sleep(0.5)
        _, g = roles()
        log("    剩余守护: %s" % (g or "无"))
        rep["steps"].append({"step": "stop_guard", "left": g})

        # ---- 2) 临时直连（保住调用方的连接）
        log("")
        log("[2] 临时关闭系统代理（直连），避免调用方在窗口期内失联 ...")
        rc, out = proxy_cmd("off")
        log("    rc=%d %s" % (rc, out.replace("\n", " | ")[:200]))
        rep["steps"].append({"step": "proxy_off", "rc": rc})

        # ---- 3) 停所有隧道
        log("")
        log("[3] 停止全部隧道进程 ...")
        t, _ = roles()
        kill_pids(t, "隧道")
        for _ in range(20):
            if not port_alive(PORT, timeout=1.0):
                break
            time.sleep(0.4)
        log("    10808 监听: %s" % ("仍占用!" if port_alive(PORT) else "已释放"))
        rep["steps"].append({"step": "stop_tunnel", "port_free": not port_alive(PORT)})

        # ---- 4) 写 goodip.json
        log("")
        log("[4] 写入优选 IP 到 goodip.json ...")
        if os.path.exists(GOODIP):
            old = open(GOODIP, encoding="utf-8").read()
            bak = GOODIP + ".bak"
            open(bak, "w", encoding="utf-8").write(old)
            log("    原内容 %s -> 已备份 %s" % (old.strip(), os.path.basename(bak)))
        d = {}
        if os.path.exists(GOODIP):
            try:
                d = json.load(open(GOODIP, encoding="utf-8"))
            except Exception:
                d = {}
        d[host] = ip
        with open(GOODIP, "w", encoding="utf-8") as f:
            json.dump(d, f)
        back = json.load(open(GOODIP, encoding="utf-8"))
        log("    回读校验: %s" % json.dumps(back, ensure_ascii=False))
        if back.get(host) != ip:
            log("[x] 写入校验失败！")
            rep["notes"].append("写入校验失败")
        rep["steps"].append({"step": "write_goodip", "value": back})

        # ---- 5) 起隧道
        log("")
        log("[5] 启动隧道（后台无窗口）...")
        DETACHED = 0x00000008 | 0x00000200
        subprocess.Popen([PYW, "-u", WSTUN], cwd=CLIENT, creationflags=DETACHED,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True)
        ok_up = False
        for i in range(90):
            if port_alive(PORT, timeout=1.5):
                ok_up = True
                log("    10808 已监听（等待 %.1fs）" % (i * 0.5))
                break
            time.sleep(0.5)
        if not ok_up:
            log("[x] 隧道 45 秒内没起来")
        rep["steps"].append({"step": "start_tunnel", "listening": ok_up})

        # ---- 6) 恢复系统代理
        log("")
        log("[6] 恢复系统代理指向隧道 127.0.0.1:10808 ...")
        rc, out = proxy_cmd("on")
        log("    rc=%d %s" % (rc, out.replace("\n", " | ")[:200]))
        rep["steps"].append({"step": "proxy_on", "rc": rc, "now": read_proxy()})

        if not ok_up:
            log("[!] 隧道没起来，先做 failover（还原到原代理设置），保证能上网")
            rc, out = proxy_cmd("restore-safe")
            log("    restore-safe rc=%d %s" % (rc, out.replace("\n", " | ")[:160]))
            rep["notes"].append("隧道未起来，已 failover")
            return rep

        # ---- 7) 等客户端写回（这一步专门抓「被覆盖」问题）
        log("")
        log("[7] 观察 12 秒，确认优选 IP 没被客户端覆盖回去 ...")
        kept = True
        for i in range(6):
            time.sleep(2.0)
            try:
                cur = json.load(open(GOODIP, encoding="utf-8")).get(host)
            except Exception:
                cur = None
            log("    +%2ds  goodip = %s" % ((i + 1) * 2, cur))
            if cur != ip:
                kept = False
                break
        rep["steps"].append({"step": "clobber_check", "kept": kept})

        # ---- 8) 变更后：经隧道测吞吐
        log("")
        log("[8] 变更后：经隧道实测吞吐（8MB）...")
        a = tunnel_pull()
        rep["after"] = a
        if a["ok"]:
            log("    变更后 = %.2f MB/s  (%.2fs, 隧道建连 %.2fs)"
                % (a["mbps"], a["secs"], a["t_connect"]))
        else:
            log("    变更后测速失败: %s" % a["err"])
        path_after = [l for l in log_tail(8) if "->" in l]
        rep["path_after"] = path_after[-1:] if path_after else []

        # ---- 9) 起守护
        log("")
        log("[9] 启动守护 ...")
        r = subprocess.run([PY, GUARD, "--start"], capture_output=True, timeout=90)
        log("    %s" % (r.stdout or b"").decode("utf-8", "replace").strip())

        # ---- 10) 终检
        log("")
        log("[10] 终检 ...")
        time.sleep(2.0)
        t, g = roles()
        fin = {
            "tunnels": t, "guards": g,
            "port_alive": port_alive(PORT),
            "goodip": json.load(open(GOODIP, encoding="utf-8")) if os.path.exists(GOODIP) else None,
            "proxy": read_proxy(),
        }
        rep["final"] = fin
        log("    隧道进程 %s / 守护进程 %s" % (t or "无", g or "无"))
        log("    10808 监听: %s" % fin["port_alive"])
        log("    goodip     : %s" % json.dumps(fin["goodip"], ensure_ascii=False))
        log("    系统代理   : %s" % json.dumps(fin["proxy"], ensure_ascii=False))

        same = fin["proxy"].get("ProxyServer") == "127.0.0.1:10808" and fin["proxy"].get("ProxyEnable") == 1
        rep["ok"] = bool(ok_up and same and fin["goodip"]
                         and fin["goodip"].get(host) == ip)
        log("")
        if rep["ok"]:
            log(">>> 落地成功：优选 IP 生效，隧道与守护各一个，系统代理已指回隧道。")
        else:
            log(">>> [注意] 有项目未达预期，请看上面的明细。")

    except Exception as e:
        import traceback
        log("[x] 异常: %s" % e)
        log(traceback.format_exc()[:1500])
        rep["notes"].append("异常: %s" % e)
    finally:
        # 兜底：除非隧道确实活着，否则不要留下"代理指着死端口"的状态
        try:
            if not port_alive(PORT, timeout=2.0):
                log("[!] 兜底：隧道不在，还原系统代理设置。")
                proxy_cmd("restore-safe")
        except Exception:
            pass
        rep["ended"] = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(REPORT, "w", encoding="utf-8") as f:
                json.dump(rep, f, ensure_ascii=False, indent=2)
            with open(os.path.join(RUNTIME, "apply_report.txt"), "w",
                      encoding="utf-8") as f:
                f.write("\n".join(_lines) + "\n")
            log("报告已写入 %s" % REPORT)
        except Exception as e:
            log("写报告失败: %s" % e)
    return rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True, help="先用 pick_speed/tiebreak 选好的边缘 IP")
    ap.add_argument("--grace", type=float, default=4.0)
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    os.makedirs(RUNTIME, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n" + "=" * 66 + "\n启动 %s  pid=%d\n"
                % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid()))
    rep = work(args.ip, args.grace)
    return 0 if rep.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
