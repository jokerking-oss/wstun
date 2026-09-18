# -*- coding: utf-8 -*-
"""通用「脱离进程树启动」器：用 WMI 启动脚本，命令行由 Python 自己拼，避开 shell 转义。

用法：
  python _spawn_detached.py <目标脚本路径> [参数...]
  python _spawn_detached.py --raw "<完整命令行>"     # 直接给命令行

原理：Win32_Process.Create 由 WMI 服务创建进程，父进程是 WmiPrvSE.exe，
不在调用方的 Job Object 里，因此调用方结束（甚至断链）后仍能继续跑。
"""
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

PY = os.environ.get("WSTUN_PYTHON") or sys.executable
if not os.path.exists(PY):
    PY = sys.executable


def spawn(cmdline):
    ps = ("$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
          "-Arguments @{ CommandLine = '%s' }; "
          "Write-Output ($r.ProcessId.ToString() + '|' + $r.ReturnValue.ToString())"
          % cmdline.replace("'", "''"))
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=120)
    out = r.stdout.decode("utf-8", "replace").strip()
    err = r.stderr.decode("utf-8", "replace").strip()
    if err:
        print("  powershell stderr: %s" % err[:300])
    return out


def main():
    args = sys.argv[1:]
    if not args:
        print("用法: _spawn_detached.py <脚本> [参数...]")
        return 2
    if args[0] == "--raw":
        cmdline = args[1]
    else:
        parts = [PY, "-X", "utf8"] + args
        cmdline = subprocess.list2cmdline(parts)
    print("命令行: %s" % cmdline)
    out = spawn(cmdline)
    print("返回  : %s" % out)
    if "|" in out:
        pid, _, ret = out.partition("|")
        ok = ret.strip() == "0"
        print("PID   : %s" % pid.strip())
        print("结果  : %s" % ("启动成功" if ok else "ReturnValue=%s" % ret.strip()))
        return 0 if ok else 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
