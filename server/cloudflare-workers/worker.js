/**
 * wstun 边缘端 —— Cloudflare Workers / Cloudflare Pages Functions 版
 *
 * 作用：把 WebSocket 里的字节流还原成原始 TCP，并可选择经上游 HTTP 代理（住宅代理）出去。
 *      明文 SNI 只存在于「边缘节点 -> 住宅代理」这一跳，不经过中国大陆链路。
 *
 * 环境变量（在 Cloudflare 面板 Secrets 里设置）：
 *   AUTH_TOKEN     必填，客户端口令
 *   UPSTREAM_HOST  上游代理 IP，例 YOUR-RESIDENTIAL-HOST（留空 = 边缘节点直连目标）
 *   UPSTREAM_PORT  上游代理端口，例 8080
 *   UPSTREAM_USER  上游代理账号
 *   UPSTREAM_PASS  上游代理密码
 */
import { connect } from "cloudflare:sockets";

const enc = new TextEncoder();
const dec = new TextDecoder();

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** 读掉上游代理对 CONNECT 的响应头，返回头后面的残留数据 */
async function drainConnectResponse(reader) {
  let buf = new Uint8Array(0);
  for (let i = 0; i < 50; i++) {
    const { value, done } = await reader.read();
    if (done) throw new Error("upstream closed during CONNECT");
    buf = concat(buf, value);
    const s = dec.decode(buf);
    const idx = s.indexOf("\r\n\r\n");
    if (idx >= 0) {
      const head = s.slice(0, idx + 4);
      const rest = buf.slice(idx + 4); // 头是 ASCII，字节数与字符数一致
      if (!/^HTTP\/1\.[01] 2/.test(head)) {
        throw new Error("upstream refused: " + head.split("\r\n")[0]);
      }
      return rest;
    }
  }
  throw new Error("CONNECT response too long");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (env.AUTH_TOKEN) {
      const got = url.searchParams.get("a") || request.headers.get("x-auth") || "";
      if (got !== env.AUTH_TOKEN) {
        return new Response("forbidden", { status: 403 });
      }
    }

    if ((request.headers.get("upgrade") || "").toLowerCase() !== "websocket") {
      return new Response("wstun edge node is up\n", { status: 200 });
    }

    const upHost = env.UPSTREAM_HOST || "";
    const upPort = parseInt(env.UPSTREAM_PORT || "0", 10);
    const upUser = env.UPSTREAM_USER || "";
    const upPass = env.UPSTREAM_PASS || "";
    const useUp = upHost.length > 0 && upPort > 0;

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    let socket = null;
    let writer = null;
    let started = false;

    server.addEventListener("message", async (event) => {
      try {
        const raw = typeof event.data === "string"
          ? enc.encode(event.data)
          : new Uint8Array(event.data);

        if (!started) {
          started = true;
          const target = dec.decode(raw).trim();
          const idx = target.lastIndexOf(":");
          if (idx < 0) throw new Error("bad target " + target);
          const host = target.slice(0, idx);
          const port = parseInt(target.slice(idx + 1), 10);
          if (!host || !port) throw new Error("bad target " + target);

          let first = new Uint8Array(0);
          if (useUp) {
            try {
              const s = connect({ hostname: upHost, port: upPort });
              const w = s.writable.getWriter();
              const auth = btoa(upUser + ":" + upPass);
              await w.write(enc.encode(
                "CONNECT " + host + ":" + port + " HTTP/1.1\r\n" +
                "Host: " + host + ":" + port + "\r\n" +
                "Proxy-Authorization: Basic " + auth + "\r\n\r\n"
              ));
              first = await drainConnectResponse(s.readable.getReader());
              socket = s;
              writer = w;
            } catch (e) {
              socket = null;   // 上游不可用 -> 降级为边缘直连
            }
          }
          if (!socket) {
            socket = connect({ hostname: host, port: port });
            writer = socket.writable.getWriter();
          }

          const reader = socket.readable.getReader();
          if (first.length) server.send(first);

          (async () => {
            try {
              for (;;) {
                const { value, done } = await reader.read();
                if (done) break;
                if (value && value.length) server.send(value);
              }
            } catch (e) { /* 连接关闭 */ }
            try { server.close(1000, "closed"); } catch (e) {}
          })();
          return;
        }

        await writer.write(raw);
      } catch (e) {
        try { server.close(1011, String(e && e.message || e).slice(0, 100)); } catch (_) {}
      }
    });

    const cleanup = async () => {
      try { if (writer) await writer.close(); } catch (e) {}
      try { if (socket) socket.close(); } catch (e) {}
    };
    server.addEventListener("close", cleanup);
    server.addEventListener("error", cleanup);

    return new Response(null, { status: 101, webSocket: client });
  },
};
