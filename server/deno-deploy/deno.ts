/**
 * wstun 边缘端 —— Deno Deploy 版
 *
 * 部署：打开 https://dash.deno.com → New Project → Playground(粘贴本文件) → Deploy
 *      得到 https://<名字>.deno.dev  （实测该域名在中国大陆未被封锁）
 *
 * 环境变量（Deno Deploy 项目 Settings → Environment Variables）：
 *   AUTH_TOKEN     客户端口令
 *   UPSTREAM_HOST  上游代理 IP，例 YOUR-RESIDENTIAL-HOST（留空 = 边缘直连目标）
 *   UPSTREAM_PORT  例 8080
 *   UPSTREAM_USER / UPSTREAM_PASS
 */
// —— 默认值：粘贴即可用，无需配环境变量；若设了环境变量则以环境变量为准 ——
const DEF = {
  AUTH: "CHANGE-ME-use-a-long-random-token",
  UP_HOST: "YOUR-RESIDENTIAL-HOST",
  UP_PORT: "8080",
  UP_USER: "YOUR-USERNAME",
  UP_PASS: "YOUR-PASSWORD",
};

const AUTH = Deno.env.get("AUTH_TOKEN") || DEF.AUTH;
const UP_HOST = Deno.env.get("UPSTREAM_HOST") || DEF.UP_HOST;
const UP_PORT = parseInt(Deno.env.get("UPSTREAM_PORT") || DEF.UP_PORT, 10);
const UP_USER = Deno.env.get("UPSTREAM_USER") || DEF.UP_USER;
const UP_PASS = Deno.env.get("UPSTREAM_PASS") || DEF.UP_PASS;
const USE_UP = UP_HOST.length > 0 && UP_PORT > 0;

const enc = new TextEncoder();
const dec = new TextDecoder();

function findHeaderEnd(buf: Uint8Array): number {
  for (let i = 0; i + 3 < buf.length; i++) {
    if (buf[i] === 13 && buf[i + 1] === 10 && buf[i + 2] === 13 && buf[i + 3] === 10) return i + 4;
  }
  return -1;
}

/** 读掉上游对 CONNECT 的响应头，返回头之后的残留字节 */
async function drainConnect(conn: Deno.Conn): Promise<Uint8Array> {
  let acc = new Uint8Array(0);
  const chunk = new Uint8Array(4096);
  for (let i = 0; i < 64; i++) {
    const n = await conn.read(chunk);
    if (n === null) throw new Error("upstream closed during CONNECT");
    const piece = chunk.subarray(0, n);
    const merged = new Uint8Array(acc.length + piece.length);
    merged.set(acc, 0);
    merged.set(piece, acc.length);
    acc = merged;
    const idx = findHeaderEnd(acc);
    if (idx >= 0) {
      const head = dec.decode(acc.subarray(0, idx));
      if (!/^HTTP\/1\.[01] 2/.test(head)) {
        throw new Error("upstream refused: " + head.split("\r\n")[0]);
      }
      return acc.subarray(idx);
    }
  }
  throw new Error("CONNECT response too long");
}

Deno.serve((req: Request): Response => {
  const url = new URL(req.url);

  if (AUTH) {
    const got = url.searchParams.get("a") || req.headers.get("x-auth") || "";
    if (got !== AUTH) return new Response("forbidden", { status: 403 });
  }

  if ((req.headers.get("upgrade") || "").toLowerCase() !== "websocket") {
    return new Response("wstun edge node is up\n", { status: 200 });
  }

  const { socket, response } = Deno.upgradeWebSocket(req);
  socket.binaryType = "arraybuffer";

  let conn: Deno.Conn | null = null;
  let started = false;
  let closed = false;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    try { conn?.close(); } catch (_) { /* ignore */ }
    try { socket.close(); } catch (_) { /* ignore */ }
  };

  socket.onmessage = async (ev: MessageEvent) => {
    try {
      const raw: Uint8Array = typeof ev.data === "string"
        ? enc.encode(ev.data)
        : new Uint8Array(ev.data as ArrayBuffer);

      if (!started) {
        started = true;
        const target = dec.decode(raw).trim();
        const i = target.lastIndexOf(":");
        if (i < 0) throw new Error("bad target " + target);
        const host = target.slice(0, i);
        const port = parseInt(target.slice(i + 1), 10);
        if (!host || !port) throw new Error("bad target " + target);

        let first: Uint8Array = new Uint8Array(0);
        if (USE_UP) {
          try {
            const c = await Deno.connect({ hostname: UP_HOST, port: UP_PORT });
            const auth = btoa(UP_USER + ":" + UP_PASS);
            await c.write(enc.encode(
              `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n` +
              `Proxy-Authorization: Basic ${auth}\r\n\r\n`
            ));
            first = await drainConnect(c);
            conn = c;                       // 上游可用，走住宅代理出口
          } catch (_) {
            conn = null;                    // 上游不可用，自动降级为边缘直连
          }
        }
        if (!conn) conn = await Deno.connect({ hostname: host, port });
        if (first.length) socket.send(first);

        // TCP -> WS
        const cc = conn!;
        (async () => {
          const buf = new Uint8Array(65536);
          try {
            for (;;) {
              const n = await cc.read(buf);
              if (n === null) break;
              if (n > 0) socket.send(buf.subarray(0, n));
            }
          } catch (_) { /* ignore */ }
          cleanup();
        })();
        return;
      }

      await conn!.write(raw);
    } catch (e) {
      try { socket.close(); } catch (_) { /* ignore */ }
    }
  };

  socket.onclose = cleanup;
  socket.onerror = cleanup;

  return response;
});
