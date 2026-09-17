#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wstun 边缘端 —— 通用容器版（Koyeb / Render / Fly.io / 任意 VPS）

协议：
  客户端 WSS 连接 -> 第一条消息 "host:port" -> 之后是裸 TCP 字节流

环境变量（全部有默认值，可直接部署）：
  AUTH_TOKEN     客户端口令
  UPSTREAM_HOST  上游代理 IP，留空 = 边缘直连目标
  UPSTREAM_PORT  上游代理端口
  UPSTREAM_USER / UPSTREAM_PASS
  MODE           up=强制走上游代理 / direct=强制直连 / auto=优先上游，失败直连（默认）
  PORT           监听端口，默认 8080
"""
import os
import asyncio
import base64

import websockets
from websockets.asyncio.server import serve

# —— 默认值：直接部署即可用，设了环境变量则以环境变量为准 ——
DEF = {
    "AUTH": "CHANGE-ME-use-a-long-random-token",
    "UP_HOST": "YOUR-RESIDENTIAL-HOST",
    "UP_PORT": "8080",
    "UP_USER": "YOUR-USERNAME",
    "UP_PASS": "YOUR-PASSWORD",
}

AUTH = os.environ.get("AUTH_TOKEN") or DEF["AUTH"]
UP_HOST = os.environ.get("UPSTREAM_HOST") or DEF["UP_HOST"]
UP_PORT = int(os.environ.get("UPSTREAM_PORT") or DEF["UP_PORT"])
UP_USER = os.environ.get("UPSTREAM_USER") or DEF["UP_USER"]
UP_PASS = os.environ.get("UPSTREAM_PASS") or DEF["UP_PASS"]
MODE = (os.environ.get("MODE") or "auto").strip().lower()
PORT = int(os.environ.get("PORT", "8080"))

USE_UP = bool(UP_HOST) and UP_PORT > 0 and MODE in ("auto", "up")
AUTH_HDR = ""
if USE_UP and UP_USER:
    _a = base64.b64encode(("%s:%s" % (UP_USER, UP_PASS)).encode()).decode()
    AUTH_HDR = "Proxy-Authorization: Basic %s\r\n" % _a


def target_of(ws):
    """从 WebSocket 握手里取出 URL，用于校验口令"""
    path = ""
    for attr in ("request", "response"):
        obj = getattr(ws, attr, None)
        if obj is not None:
            path = getattr(obj, "path", "") or ""
            if path:
                break
    if not path:
        try:
            path = ws.path  # 部分版本
        except Exception:
            path = ""
    return path or "/"


async def drain(reader, limit=65536):
    """读掉上游对 CONNECT 的响应头，返回剩余字节"""
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < limit:
        chunk = await reader.read(4096)
        if not chunk:
            raise ConnectionError("upstream closed during CONNECT")
        buf += chunk
    if b"\r\n\r\n" not in buf:
        raise ConnectionError("CONNECT response too long")
    head, rest = buf.split(b"\r\n\r\n", 1)
    if not head.startswith(b"HTTP/1.1 2") and not head.startswith(b"HTTP/1.0 2"):
        raise ConnectionError("upstream refused: " + head[:60].decode("latin1"))
    return rest


async def pipe_ws_to_tcp(ws, writer):
    try:
        async for msg in ws:
            if isinstance(msg, str):
                msg = msg.encode()
            writer.write(msg)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def pipe_tcp_to_ws(reader, ws):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            await ws.send(data)
    except Exception:
        pass
    try:
        await ws.close()
    except Exception:
        pass


async def handler(ws):
    try:
        if AUTH:
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(target_of(ws)).query)
            got = (q.get("a") or [""])[0]
            if got != AUTH:
                await ws.close(code=4003, reason="forbidden")
                return

        first = await asyncio.wait_for(ws.recv(), timeout=25)
        if isinstance(first, str):
            first = first.encode()
        host, _, p = first.decode().strip().rpartition(":")
        port = int(p)
    except Exception as e:
        try:
            await ws.close(code=4000, reason=str(e)[:80])
        except Exception:
            pass
        return

    reader = writer = None
    rest = b""
    if USE_UP:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(UP_HOST, UP_PORT), timeout=20)
            writer.write(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%s\r\n"
                          % (host, port, host, port, AUTH_HDR)).encode())
            await writer.drain()
            rest = await asyncio.wait_for(drain(reader), timeout=25)
            print("UP   %s:%d" % (host, port), flush=True)
        except Exception as e:
            print("UP_FAIL %s:%d %s" % (host, port, str(e)[:70]), flush=True)
            try:
                writer.close()
            except Exception:
                pass
            reader = writer = None
            if MODE == "up":
                try:
                    await ws.close(code=4001, reason=str(e)[:80])
                except Exception:
                    pass
                return

    if writer is None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=20)
            print("DIRECT %s:%d" % (host, port), flush=True)
        except Exception as e:
            print("DIRECT_FAIL %s:%d %s" % (host, port, str(e)[:70]), flush=True)
            try:
                await ws.close(code=4001, reason=str(e)[:80])
            except Exception:
                pass
            return

    if rest:
        await ws.send(rest)

    t1 = asyncio.create_task(pipe_ws_to_tcp(ws, writer))
    t2 = asyncio.create_task(pipe_tcp_to_ws(reader, ws))
    await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    t1.cancel()
    t2.cancel()


async def main():
    async with serve(handler, "0.0.0.0", PORT,
                     ping_interval=20, ping_timeout=60, max_size=None) as srv:
        print("wstun edge on 0.0.0.0:%d mode=%s upstream=%s"
              % (PORT, MODE, ("%s:%d" % (UP_HOST, UP_PORT)) if USE_UP else "direct"),
              flush=True)
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
