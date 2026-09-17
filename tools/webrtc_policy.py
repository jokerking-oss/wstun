# -*- coding: utf-8 -*-
"""Edge WebRTC 防泄露策略开关

背景
----
系统代理只管 TCP。WebRTC 用 UDP，会绕过代理直接从本机出去，把真实公网 IP
（中国移动）交给网页 —— AI 站点看到的就是「美国 IP + 中国 IP 双出口」这种
典型代理特征。桌面端 AI 客户端基本不触发 WebRTC，主要是网页版受影响。

Edge 官方策略（注意：Edge 的策略名与 Chrome 的 WebRtcIPHandlingPolicy 不同）
  GP 名称  : Restrict exposure of local IP address by WebRTC
  注册表值 : WebRtcLocalhostIpHandling
  路径     : SOFTWARE\\Policies\\Microsoft\\Edge   (HKLM 或 HKCU)
  类型     : REG_SZ
  取值     :
    disable_non_proxied_udp  -> 禁止非代理 UDP，WebRTC 不再暴露本机真实 IP  ← 用这个
    default                  -> 恢复默认（暴露）
  文档: https://learn.microsoft.com/zh-cn/deployEdge/microsoft-edge-policies/webrtclocalhostiphandling

权限说明（重要）
----------------
`...\\Software\\Policies` 这个键在 Windows 上被加固：Owner 是 SYSTEM，
普通用户只有 ReadKey。所以**必须管理员权限**才能写。
本脚本优先写 HKLM（机器级）；若当前已提权则一次成功。
未提权时会明确报错并返回退出码 3，由外层 bat 负责提权。

副作用
------
Edge 内的 WebRTC（网页版视频通话 / 网页会议 / 部分 P2P）会失去直连 UDP，
退化为经代理的 TCP 或直接失败。桌面版应用（腾讯会议/Zoom 客户端）不受影响。
普通网页浏览、AI 对话完全不受影响。
策略不热加载，**必须完全退出 Edge 再打开**才生效。

用法
----
  python webrtc_policy.py on        # 开启（需管理员）
  python webrtc_policy.py off       # 设为 default（需管理员）
  python webrtc_policy.py restore   # 还原到脚本首次运行前的原始状态
  python webrtc_policy.py status    # 只看状态（不需要管理员）
"""
import os
import sys
import json
import winreg

VALUE_NAME = "WebRtcLocalhostIpHandling"
ON_VALUE = "disable_non_proxied_udp"
OFF_VALUE = "default"

# (标签, HKEY, 子键路径) —— 顺序即优先级
TARGETS = [
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge"),
    ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Edge"),
]

HERE = os.path.dirname(os.path.abspath(__file__))
TUNNEL = os.path.dirname(HERE)
RUNTIME = os.path.join(TUNNEL, "_runtime")
BACKUP = os.path.join(RUNTIME, "webrtc-policy-backup.json")

EXIT_NEED_ADMIN = 3


# --------------------------------------------------------------------------- #
# 基础读写
# --------------------------------------------------------------------------- #
def _read(hive, path):
    """返回 (键存在, 值存在, 值)。"""
    key_exists = value_exists = False
    value = None
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            key_exists = True
            try:
                value, _t = winreg.QueryValueEx(k, VALUE_NAME)
                value_exists = True
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass
    except PermissionError:
        # 读都读不了（极少见），当作不存在处理
        pass
    return key_exists, value_exists, value


def _write(hive, path, value):
    """写值。无权限会抛 PermissionError。"""
    with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, value)


def _delete_value(hive, path):
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, VALUE_NAME)
        return True
    except (FileNotFoundError, PermissionError):
        return False


def _delete_key_if_empty(hive, path):
    """值都清空后，把空键也删掉，做到彻底还原。"""
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            if winreg.QueryInfoKey(k)[1] > 0:
                return False
    except (FileNotFoundError, PermissionError):
        return False
    try:
        winreg.DeleteKey(hive, path)
        return True
    except OSError:
        return False


def read_all():
    return {label: _read(hive, path) for label, hive, path in TARGETS}


def is_elevated():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def broadcast():
    """广播设置变更（礼貌性动作；策略实际要重启浏览器才读）。"""
    try:
        import ctypes
        res = ctypes.c_long()
        ctypes.windll.user32.SendMessageTimeoutW(
            0xFFFF, 0x001A, 0, ctypes.c_wchar_p("Software\\Policies\\Microsoft\\Edge"),
            0x0002, 1000, ctypes.byref(res))
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# 备份
# --------------------------------------------------------------------------- #
def backup_once():
    """首次改动前记录原始状态，之后不覆盖。"""
    if os.path.exists(BACKUP):
        try:
            with open(BACKUP, "r", encoding="utf-8") as f:
                if "targets" in json.load(f):
                    return
        except Exception:
            pass
    snapshot = {}
    for label, hive, path in TARGETS:
        ke, ve, v = _read(hive, path)
        snapshot[label] = {"键存在": ke, "值存在": ve, "原始值": v}
    os.makedirs(RUNTIME, exist_ok=True)
    with open(BACKUP, "w", encoding="utf-8") as f:
        json.dump({
            "说明": "本策略生效前的原始状态。restore 会严格按这个还原。",
            "策略": VALUE_NAME,
            "targets": snapshot,
        }, f, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------- #
# 命令
# --------------------------------------------------------------------------- #
def _apply(value, label_verb):
    """把值写到第一个可写的目标位置。返回 (是否成功, 位置标签, 错误)。"""
    errors = []
    for label, hive, path in TARGETS:
        try:
            _write(hive, path, value)
            return True, label, None
        except PermissionError:
            errors.append("%s: 拒绝访问" % label)
        except OSError as e:
            errors.append("%s: %s" % (label, e))
    return False, None, "; ".join(errors)


def cmd_on():
    backup_once()
    ok, where, err = _apply(ON_VALUE, "开启")
    if not ok:
        print("[x] 写入失败：%s" % err)
        print()
        print("    原因：`...\\Software\\Policies` 这个键在 Windows 上被加固，")
        print("          普通用户只有读权限，必须用管理员身份写。")
        print("    做法：双击桌面的「④ 修复WebRTC泄露.bat」，在弹出的窗口点\"是\"。")
        return EXIT_NEED_ADMIN
    broadcast()
    kx, vx, v = _read(dict((lb, (h, p)) for lb, h, p in TARGETS)[where][0],
                      dict((lb, (h, p)) for lb, h, p in TARGETS)[where][1])
    print("[ok] 已开启 WebRTC 防泄露（写入位置：%s）" % where)
    print("     %s = %s" % (VALUE_NAME, v))
    print("     完整路径：%s\\%s" % (where, dict((lb, p) for lb, _h, p in TARGETS)[where]))
    print()
    print("     >>> 必须完全退出 Edge（所有窗口都关掉）再打开才生效。")
    print("     >>> 验证：浏览器打开 https://browserleaks.com/webrtc 看有没有中国 IP。")
    return 0


def cmd_off():
    backup_once()
    ok, where, err = _apply(OFF_VALUE, "关闭")
    if not ok:
        print("[x] 写入失败：%s" % err)
        print("    需要管理员权限，请双击桌面「④ 修复WebRTC泄露.bat」。")
        return EXIT_NEED_ADMIN
    broadcast()
    print("[ok] 已设为 default（WebRTC 会再次暴露本机 IP），位置：%s" % where)
    return 0


def cmd_restore():
    if not os.path.exists(BACKUP):
        print("[!] 没有备份文件，无法还原：%s" % BACKUP)
        return 1
    with open(BACKUP, "r", encoding="utf-8") as f:
        b = json.load(f)
    snap = b.get("targets") or {}
    touched = False
    for label, hive, path in TARGETS:
        want = snap.get(label)
        if want is None:
            continue
        if want.get("值存在"):
            try:
                _write(hive, path, want.get("原始值") or OFF_VALUE)
                print("[ok] %s 还原成原始值：%s" % (label, want.get("原始值")))
                touched = True
            except PermissionError:
                print("[x] %s 还原失败：需要管理员权限" % label)
                return EXIT_NEED_ADMIN
        else:
            try:
                removed = _delete_value(hive, path)
                killed = _delete_key_if_empty(hive, path)
                if removed or killed:
                    print("[ok] %s 已清除策略（原始状态本来就没有它）" % label)
                    touched = True
                else:
                    print("[i] %s 本来就没有策略值" % label)
            except PermissionError:
                print("[x] %s 清除失败：需要管理员权限" % label)
                return EXIT_NEED_ADMIN
    broadcast()
    if not touched:
        print("[i] 无需改动，当前已是原始状态。")
    print()
    print("     >>> 完全退出 Edge 后重新打开生效。")
    return 0


def cmd_status():
    print("=== Edge WebRTC 防泄露 状态 ===")
    print("  当前进程已提权: %s" % is_elevated())
    print()
    got = read_all()
    best = None
    for label, hive, path in TARGETS:
        ke, ve, v = got[label]
        mark = "—"
        if ve and v == ON_VALUE:
            mark = "✅ 防泄露已开启"
            best = label
        elif ve:
            mark = "⚠️ 有值但非防泄露档：%s" % v
        else:
            mark = "❌ 未设置"
        print("  [%s] %s" % (label, mark))
        print("       键=%s  值=%s" % (ke, ve))
        print("       路径=%s\\%s" % (label, path))
    print()
    if best:
        print("  判定：✅ 已生效于 %s" % best)
    else:
        print("  判定：❌ 未开启 —— WebRTC 会把你的真实 IP(中国移动)交给网页")
    print()
    print("  备份文件: %s (%s)" % (BACKUP, "存在" if os.path.exists(BACKUP) else "无"))
    try:
        import subprocess
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq msedge.exe", "/NH"],
                             capture_output=True).stdout.decode("gbk", "replace")
        n = out.lower().count("msedge.exe")
        print("  Edge 进程数: %d %s" % (n, "（>0 表示策略还没被浏览器读到，需完全退出 Edge）" if n else ""))
    except Exception:
        pass
    return 0 if best else 1


def main():
    arg = (sys.argv[1] if len(sys.argv) > 1 else "status").lower().lstrip("-")
    fn = {"on": cmd_on, "off": cmd_off,
          "restore": cmd_restore, "status": cmd_status}.get(arg)
    if fn is None:
        print(__doc__)
        return 2
    return fn()


if __name__ == "__main__":
    sys.exit(main())
