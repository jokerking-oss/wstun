# -*- coding: utf-8 -*-
"""Windows 系统代理（WinINET）设置工具 —— wstun 专用

用法：
    python proxy.py on      # 把系统代理指向 127.0.0.1:10808（走隧道）
    python proxy.py off     # 关闭系统代理（恢复直连）
    python proxy.py show    # 只看当前设置
    python proxy.py backup  # 备份当前设置到 proxy-backup.json
    python proxy.py restore # 从备份恢复

为什么不用 PowerShell：本机上 PowerShell 写注册表会被安全策略拦下，而
Python 的 winreg 稳定可用。设置完会用 wininet 广播变更，让已运行的浏览器
/桌面应用立刻重新读取代理，不必重启。
"""
import ctypes
import json
import os
import sys
import time
import winreg

KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
HERE = os.path.dirname(os.path.abspath(__file__))
BACKUP = os.path.join(HERE, "proxy-backup.json")

SERVER = "127.0.0.1:10808"

# 不进隧道的直连名单：本机/内网 + 国内 .cn 顶级域 + Claude Code 用的国内中转站。
# 其余全部走隧道 -> 美国住宅；隧道客户端内部还有一层更细的国内 IP 段判定。
BYPASS = ";".join([
    "localhost", "127.*", "10.*",
    "172.16.*", "172.17.*", "172.18.*", "172.19.*", "172.20.*", "172.21.*",
    "172.22.*", "172.23.*", "172.24.*", "172.25.*", "172.26.*", "172.27.*",
    "172.28.*", "172.29.*", "172.30.*", "172.31.*",
    "192.168.*", "<local>",
    "*.cn", "*.com.cn", "*.net.cn", "*.org.cn", "*.gov.cn", "*.edu.cn",
    "*.example.com", "*.example.org", "*.example.net",
])


def _read():
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY)
    out = {}
    for n in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
        try:
            out[n] = winreg.QueryValueEx(k, n)[0]
        except FileNotFoundError:
            out[n] = None
    winreg.CloseKey(k)
    return out


def _write(enable, server=None, bypass=None):
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
    if server is not None:
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server)
    if bypass is not None:
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, bypass)
    winreg.CloseKey(k)


def _broadcast():
    """通知系统代理已变更，正在运行的程序会立刻重新读取。"""
    try:
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0, 39, 0, 0)      # SETTINGS_CHANGED
        w.InternetSetOptionW(0, 37, 0, 0)      # REFRESH
        return True
    except Exception:
        return False


def show():
    cur = _read()
    print("ProxyEnable   =", cur["ProxyEnable"], "(1=启用, 0=关闭)")
    print("ProxyServer   =", cur["ProxyServer"])
    print("ProxyOverride =", (cur["ProxyOverride"] or "")[:200])


def backup(force=False):
    """备份当前设置。

    注意：restore 用的是 BACKUP 这个文件，它存的是「切换到隧道之前」的原始
    设置，很宝贵。所以默认不会覆盖它——已经存在时就存成带时间戳的新文件。
    """
    cur = _read()
    cur["_backup_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    target = BACKUP
    if os.path.exists(BACKUP) and not force:
        target = os.path.join(HERE, "_proxy-backup-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    with open(target, "w", encoding="utf-8") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)
    print("[ok] 当前设置已备份 ->", target)
    show()


def on():
    _write(True, SERVER, BYPASS)
    _broadcast()
    print("[ok] 系统代理 -> %s（国外走美国住宅，国内走直连）" % SERVER)
    show()


def off():
    _write(False)
    _broadcast()
    print("[ok] 系统代理已关闭（恢复本机直连）")
    show()


def restore():
    if not os.path.exists(BACKUP):
        print("[x] 没有备份文件:", BACKUP)
        return 1
    with open(BACKUP, "r", encoding="utf-8") as f:
        cur = json.load(f)
    _write(bool(cur.get("ProxyEnable")), cur.get("ProxyServer"),
           cur.get("ProxyOverride"))
    _broadcast()
    print("[ok] 已恢复备份设置")
    show()


def _port_listening(server):
    """判断 'host:port' 里的本地端口现在是否真有程序在监听。"""
    import socket as _s
    host, _, port = (server or "").rpartition(":")
    try:
        s = _s.socket()
        s.settimeout(1.2)
        s.connect((host or "127.0.0.1", int(port)))
        s.close()
        return True
    except Exception:
        return False


def restore_safe():
    """智能恢复（「② 恢复原样.bat」用的就是这个）。

    - 备份里那个代理端口还有程序在监听（比如 SakuraCat 的 7897 在跑）
      -> 精确还原成备份设置，回到你原来的日常状态
    - 那个端口已经没人监听了（比如 SakuraCat 已经卸载/退出）
      -> 直接关闭系统代理，走纯直连；绝不把一个「死代理」留在系统里
    """
    if not os.path.exists(BACKUP):
        print("[!] 没找到备份文件，改为直接关闭系统代理。")
        return off()
    with open(BACKUP, "r", encoding="utf-8") as f:
        cur = json.load(f)
    srv = cur.get("ProxyServer")
    if cur.get("ProxyEnable") and srv and _port_listening(srv):
        _write(True, srv, cur.get("ProxyOverride"))
        _broadcast()
        print("[ok] 已还原成你原来的设置：%s（那个程序正在运行）" % srv)
        show()
        return 0
    _write(False)
    _broadcast()
    if srv:
        print("[ok] 原来的代理 %s 没在运行，已改为「关闭系统代理」→ 纯直连。" % srv)
    else:
        print("[ok] 已关闭系统代理 → 纯直连。")
    show()
    return 0


if __name__ == "__main__":
    cmd = (sys.argv[1] if len(sys.argv) > 1 else "show").lower()
    fn = {"on": on, "off": off, "show": show, "backup": backup, "restore": restore,
          "restore-safe": restore_safe}.get(cmd)
    if not fn:
        print(__doc__)
        sys.exit(1)
    sys.exit(fn() or 0)
