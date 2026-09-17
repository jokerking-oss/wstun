# -*- coding: utf-8 -*-
"""wstun 兜底守护（guard）—— 补掉「隧道死了 = 全系统上不了网」这个软肋。

背景
----
系统代理指向 127.0.0.1:10808。隧道进程一旦消失（崩溃 / 被误关 / 边缘断连），
整个系统就没有出口了。这个守护进程负责把这件事变成"自动恢复"。

它做三件事
----------
1. **保活**：每 check_interval 秒探测 10808。不在了就自动把隧道拉起来（最多等
   restart_wait 秒确认），并重新广播系统代理（防止被别的软件抢走）。
2. **断尾求生（failover）**：如果连续 failover_after 次都拉不起来，说明短期内
   隧道真的不可用 —— 这时**自动把系统代理还原成你原来的设置**（备份里的
   SakuraCat 7897，或纯直连），先保证你不断网；然后每
   retry_interval_after_failover 秒继续在后台尝试恢复隧道。
3. **恢复即切回**：隧道一旦重新可用，如果"意图"是开启，就自动把系统代理切回
   住宅隧道，并弹窗告诉你。

不会和别人打架
--------------
用 `_runtime/proxy_intent.txt` 记录"用户的意图"：
  - 双击 go.bat / on.bat / system-proxy-on.bat  -> 写成 on
  - 双击 off.bat / system-proxy-off.bat          -> 写成 off
守护**只在意图为 on 时**才动系统代理。你手工关掉代理之后，它不会偷偷给你打开。

用法
----
    pythonw guard.py            # 后台守护（窗口无所谓，它只写日志）
    python  guard.py --status   # 看它现在在干什么
    python  guard.py --stop     # 停止守护（off.bat 会调它）
    python  guard.py --once     # 只检查一轮，打印结果就退出（排障用）
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.join(HERE, "client")
TOOLS = os.path.join(HERE, "tools")
RUNTIME = os.path.join(HERE, "_runtime")
CFG = os.path.join(CLIENT, "wstun.json")
LOGFILE = os.path.join(RUNTIME, "guard.log")
PIDFILE = os.path.join(RUNTIME, "guard.pid")
INTENT = os.path.join(RUNTIME, "proxy_intent.txt")
STATE = os.path.join(RUNTIME, "guard_state.json")

MUTEX_PORT = 10899          # 单实例锁：能独占绑定这个端口就说明没有第二个守护
LOG_MAX = 1 * 1024 * 1024   # 日志超过 1MB 就轮转


def _find_py():
    """定位可用的 python 解释器：优先当前解释器，其次 PATH，最后常见安装位置。"""
    cands = [sys.executable]
    w = shutil.which("python")
    if w:
        cands.append(w)
    for c in cands:
        if c and os.path.exists(c):
            return c
    return sys.executable


def _find_pyw():
    """定位无窗口解释器（pythonw），拿不到就退回 python（会带控制台窗口）。"""
    cands = []
    w = shutil.which("pythonw")
    if w:
        cands.append(w)
    cands.append(sys.executable.replace("python.exe", "pythonw.exe"))
    for c in cands:
        if c and os.path.exists(c):
            return c
    return _find_py()


PY = _find_py()
PYW = _find_pyw()


def log(msg):
    line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        os.makedirs(RUNTIME, exist_ok=True)
        if os.path.exists(LOGFILE) and os.path.getsize(LOGFILE) > LOG_MAX:
            try:
                os.replace(LOGFILE, LOGFILE + ".bak")
            except Exception:
                pass
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------- 基础探测
def cfg():
    defaults = {
        "enabled": True,
        "check_interval": 20,
        "deep_check_interval": 600,
        "restart_wait": 45,
        "failover_after": 3,
        "retry_interval_after_failover": 300,
    }
    try:
        with open(CFG, "r", encoding="utf-8") as f:
            c = json.load(f)
        g = c.get("guard") or {}
        defaults.update(g)
        defaults["_port"] = int(c.get("listen_port", 10808))
        defaults["_host"] = c.get("listen_host", "127.0.0.1")
    except Exception as e:
        log("读配置失败（用默认值继续）: %s" % e)
        defaults["_port"] = 10808
        defaults["_host"] = "127.0.0.1"
    return defaults


def port_alive(host="127.0.0.1", port=10808, timeout=2.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def listeners_on(port):
    """返回正在监听该端口的 pid 集合（tasklist 不可靠，用 netstat）。"""
    pids = set()
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                             capture_output=True, timeout=10).stdout
        txt = out.decode("latin1", "replace")
        for ln in txt.splitlines():
            parts = ln.split()
            if len(parts) >= 5 and parts[0].upper() == "TCP" \
                    and parts[3].upper() == "LISTENING" \
                    and parts[1].endswith(":" + str(port)):
                pids.add(parts[4])
    except Exception:
        pass
    return pids


def deep_check(host, port):
    """真·连通性检查：经隧道做一次 SOCKS5 CONNECT 到 gstatic 的 204 端点。

    端口在监听 ≠ 隧道能出网（边缘挂了/住宅代理挂了都会这样）。所以隔一段时间
    做一次真实探测。目标选 gstatic/generate_204：响应 204、无正文，代价极小。
    """
    target = ("www.gstatic.com", 443)
    try:
        s = socket.create_connection((host, port), timeout=12)
        s.settimeout(12)
        s.sendall(b"\x05\x01\x00")
        if len(s.recv(2)) < 2:
            raise OSError("socks handshake")
        hb = target[0].encode()
        import struct
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
                  + struct.pack(">H", target[1]))
        r = s.recv(4)
        ok = len(r) == 4 and r[1] == 0
        if ok:                                  # 吃掉 BND.ADDR/PORT 再关
            atyp = r[3]
            if atyp == 1:
                s.recv(4)
            elif atyp == 3:
                s.recv(s.recv(1)[0])
            elif atyp == 4:
                s.recv(16)
            s.recv(2)
        s.close()
        return ok
    except Exception:
        return False


# ---------------------------------------------------------------- 动作
def start_tunnel(port=10808, host="127.0.0.1"):
    """以无窗口方式拉起客户端。

    开跑前再核对一次端口：10808 是 SO_REUSEADDR 监听的，两个客户端能同时绑上，
    那会导致"一半请求走旧进程"，所以宁可多等一下也不重复启动。
    """
    if port_alive(host, port):
        return True
    DETACHED = 0x00000008 | 0x00000200      # DETACHED_PROCESS | NEW_PROCESS_GROUP
    try:
        subprocess.Popen([PYW, "-u", os.path.join(CLIENT, "wstun.py")],
                         cwd=CLIENT, creationflags=DETACHED,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         close_fds=True)
        return True
    except Exception as e:
        log("拉起隧道失败: %s" % e)
        return False


def kill_tunnel(port):
    pids = listeners_on(port)
    for p in sorted(pids):
        try:
            subprocess.run(["taskkill", "/F", "/PID", p],
                           capture_output=True, timeout=10)
            log("已终止隧道进程 pid=%s" % p)
        except Exception as e:
            log("终止 pid=%s 失败: %s" % (p, e))
    return not pids


def proxy_cmd(arg):
    """调 tools/proxy.py 改系统代理。返回 (ok, 输出)。"""
    try:
        r = subprocess.run([PY, os.path.join(TOOLS, "proxy.py"), arg],
                           capture_output=True, timeout=30)
        out = (r.stdout or b"").decode("utf-8", "replace").strip()
        return r.returncode == 0, out
    except Exception as e:
        return False, str(e)


def intent():
    try:
        with open(INTENT, "r", encoding="utf-8") as f:
            v = f.read().strip().lower()
        return v if v in ("on", "off") else "on"
    except Exception:
        return "on"


def set_intent(v):
    try:
        os.makedirs(RUNTIME, exist_ok=True)
        with open(INTENT, "w", encoding="utf-8") as f:
            f.write(v)
    except Exception:
        pass


def notify(title, text, seconds=25):
    """弹一个会自动消失的提示框（WScript.Shell.Popup 自带超时）。

    注意：这里是把文本拼进 VBScript 字符串字面量，所以要先转义双引号、
    并把换行拼成 " & vbCrLf & "，否则生成的脚本语法就坏了。
    """
    vbs = os.path.join(RUNTIME, "_notify.vbs")

    def lit(s):
        parts = [p.replace('"', "'") for p in s.replace("\r", "").split("\n")]
        return '" & vbCrLf & "'.join(parts)

    try:
        os.makedirs(RUNTIME, exist_ok=True)
        with open(vbs, "w", encoding="gbk", newline="\r\n") as f:
            f.write('Set sh = CreateObject("WScript.Shell")\r\n')
            f.write('sh.Popup "%s", %d, "%s", 64\r\n' % (lit(text), seconds, lit(title)))
        subprocess.Popen(["wscript.exe", vbs],
                         creationflags=0x00000008,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        log("已弹窗提示: %s" % title)
    except Exception as e:
        log("弹窗失败（不影响功能）: %s" % e)


def save_state(d):
    d["_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(RUNTIME, exist_ok=True)
        with open(STATE, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------- 单实例锁
def acquire_mutex():
    """能独占绑定 MUTEX_PORT 就拿到锁。刻意不设 SO_REUSEADDR：
    Windows 下设了它两个进程就能绑同一个端口，锁就失效了。"""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", MUTEX_PORT))
        s.listen(1)
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None


# ---------------------------------------------------------------- 主循环
def run():
    mutex = acquire_mutex()
    if mutex is None:
        log("已经有一个守护在跑了，本进程退出。")
        print("守护已在运行，无需重复启动。")
        return 0

    try:
        os.makedirs(RUNTIME, exist_ok=True)
        with open(PIDFILE, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass

    c = cfg()
    host, port = c["_host"], c["_port"]
    log("=" * 60)
    log("兜底守护启动 pid=%d  探测间隔=%ss  连续失败 %s 次则断尾求生"
        % (os.getpid(), c["check_interval"], c["failover_after"]))

    fail_streak = 0          # 连续「拉不起来」次数
    deep_fails = 0           # 连续「端口在但出不了网」次数
    failed_over = False      # 是否已经切回原设置
    last_deep = 0.0
    stopped_marker = os.path.join(RUNTIME, "guard.stop")

    while True:
        try:
            if os.path.exists(stopped_marker):
                log("收到停止标记，退出。")
                break

            want = intent()

            if port_alive(host, port):
                fail_streak = 0

                # --- 深度探测：端口在监听不代表能出网 ---
                if time.time() - last_deep > c["deep_check_interval"]:
                    last_deep = time.time()
                    ok = deep_check(host, port)
                    if ok:
                        deep_fails = 0
                    else:
                        deep_fails += 1
                        log("深度探测失败（第 %d 次）——端口在，但经它出不了网。"
                            % deep_fails)
                        if deep_fails >= 2:
                            log("连续两次深度探测失败，重启隧道客户端。")
                            kill_tunnel(port)
                            time.sleep(2)
                            if start_tunnel(port, host):
                                for _ in range(c["restart_wait"]):
                                    time.sleep(1)
                                    if port_alive(host, port):
                                        break
                            deep_fails = 0
                            last_deep = time.time()

                # --- 隧道可用：如果之前断尾求生过，现在切回住宅 ---
                if failed_over:
                    if want == "on":
                        ok, out = proxy_cmd("on")
                        if ok:
                            failed_over = False
                            log("隧道已恢复，系统代理已切回住宅线路。")
                            save_state({"status": "healthy", "failed_over": False})
                            notify("wstun 隧道已恢复",
                                   "住宅线路已经自动切回来了，可以继续上网。")
                        else:
                            log("隧道已恢复，但切回系统代理失败：%s" % out[:200])
                    else:
                        failed_over = False
                        log("隧道已恢复；当前意图是 off，系统代理保持原样。")
                        save_state({"status": "healthy", "failed_over": False})

            else:
                # --- 端口不见了：拉起 ---
                log("检测到隧道不在（10808 无监听），自动拉起 ...")
                started = start_tunnel(port, host)
                ok = False
                if started:
                    for _ in range(c["restart_wait"]):
                        time.sleep(1)
                        if port_alive(host, port):
                            ok = True
                            break
                if ok:
                    fail_streak = 0
                    log("隧道已自动拉起，恢复正常。")
                    save_state({"status": "healthy", "failed_over": failed_over,
                                "note": "隧道曾中断，已自动拉起"})
                else:
                    fail_streak += 1
                    log("拉起失败（连续第 %d 次）" % fail_streak)
                    if fail_streak >= c["failover_after"] and not failed_over:
                        if want == "on":
                            log("隧道连续 %d 次起不来 —— 断尾求生：把系统代理还原，"
                                "先保证能上网。" % fail_streak)
                            ok2, out = proxy_cmd("restore-safe")
                            failed_over = True
                            log("还原系统代理: %s" % out[:300].replace("\n", " | "))
                            save_state({"status": "failed_over", "failed_over": True})
                            notify("wstun 隧道暂时起不来",
                                   "已经自动把你的网络切回原来的设置，先正常上网。\n"
                                   "守护会在后台继续尝试恢复，通了会自动切回住宅线路。",
                                   30)
                        else:
                            log("隧道起不来，但当前意图是 off —— 不动系统代理。")
                            save_state({"status": "tunnel_down", "failed_over": False})

            # --- 下一次探测的间隔 ---
            if fail_streak >= c["failover_after"]:
                interval = c["retry_interval_after_failover"]
            else:
                interval = c["check_interval"]
            # 分片 sleep，保证 --stop / 标记文件能及时生效
            end = time.time() + interval
            while time.time() < end:
                time.sleep(min(2, max(0.2, end - time.time())))
                if os.path.exists(stopped_marker):
                    break
        except Exception as e:
            log("守护循环异常（忽略并继续）: %r" % e)
            time.sleep(10)

    try:
        if os.path.exists(stopped_marker):
            os.remove(stopped_marker)
    except Exception:
        pass
    try:
        if os.path.exists(PIDFILE):
            os.remove(PIDFILE)
    except Exception:
        pass
    try:
        mutex.close()
    except Exception:
        pass
    log("守护已退出。")
    return 0


def do_stop():
    """停止正在跑的守护，并把停止标记清掉（下次要能正常启动）。"""
    pid = None
    try:
        with open(PIDFILE, "r", encoding="utf-8") as f:
            pid = f.read().strip()
    except Exception:
        pass
    killed = False
    if pid and pid.isdigit():
        r = subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
        killed = r.returncode == 0
    if not killed:
        # PID 文件不可靠时，用「谁占着锁端口」来兜底
        pids = listeners_on(MUTEX_PORT)
        for p in sorted(pids):
            subprocess.run(["taskkill", "/F", "/PID", p], capture_output=True)
            killed = True
    marker = os.path.join(RUNTIME, "guard.stop")
    try:
        os.makedirs(RUNTIME, exist_ok=True)
        with open(marker, "w", encoding="utf-8") as f:
            f.write("stop")
    except Exception:
        pass
    time.sleep(1.5)
    try:
        if os.path.exists(marker):
            os.remove(marker)
    except Exception:
        pass
    print("守护已停止。" if killed else "守护本来就没在运行。")
    return 0


def do_status():
    running = acquire_mutex() is None
    print("守护状态 : %s" % ("运行中" if running else "未运行"))
    print("锁端口   : %d" % MUTEX_PORT)
    print("用户意图 : %s  (on=走住宅隧道 / off=不要动系统代理)" % intent())
    for label, path in (("进程文件", PIDFILE), ("状态文件", STATE)):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    print("%s : %s" % (label, f.read().strip().replace("\n", " ")))
            except Exception:
                pass
    if os.path.exists(LOGFILE):
        print("--- 日志尾部 ---")
        try:
            with open(LOGFILE, "r", encoding="utf-8", errors="replace") as f:
                for ln in f.read().splitlines()[-12:]:
                    print("  " + ln)
        except Exception:
            pass
    return 0


def do_start():
    """从 bat 调用：后台（无窗口）拉起守护。已经在跑就什么都不做。"""
    if acquire_mutex() is None:
        print("守护已经在运行。")
        return 0
    DETACHED = 0x00000008 | 0x00000200
    try:
        subprocess.Popen([PYW, "-u", os.path.abspath(__file__)],
                         cwd=HERE, creationflags=DETACHED,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         close_fds=True)
    except Exception as e:
        print("拉起守护失败：%s" % e)
        return 1
    time.sleep(1.2)
    if acquire_mutex() is None:
        print("守护已启动（后台运行，日志：_runtime\\guard.log）")
        return 0
    print("守护启动命令已发出，但没确认到进程。请看 _runtime\\guard.log。")
    return 1


def do_once():
    c = cfg()
    host, port = c["_host"], c["_port"]
    alive = port_alive(host, port)
    print("端口 %s:%d 监听 : %s" % (host, port, "是" if alive else "否"))
    print("用户意图        : %s" % intent())
    if alive:
        print("深度探测(出网)  : %s" % ("通" if deep_check(host, port) else "不通"))
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    arg = (sys.argv[1] if len(sys.argv) > 1 else "").lower()
    if arg in ("--stop", "-stop", "stop"):
        sys.exit(do_stop())
    if arg in ("--status", "-status", "status"):
        sys.exit(do_status())
    if arg in ("--once", "-once", "once"):
        sys.exit(do_once())
    if arg in ("--start", "-start", "start"):
        sys.exit(do_start())
    if arg in ("--intent-on", "-intent-on"):
        set_intent("on")
        print("意图已记为 on（守护会管理系统代理）")
        sys.exit(0)
    if arg in ("--intent-off", "-intent-off"):
        set_intent("off")
        print("意图已记为 off（守护不再动系统代理）")
        sys.exit(0)
    sys.exit(run())
