/**
 * wstun 边缘端 —— Cloudflare Pages 高级模式（_worker.js）
 *
 * 两个踩过的坑（实测结论，勿改回去）：
 *  1) Pages 的 functions/ 文件路由层：返回 101 但 message 事件根本不派发。
 *     => 必须用高级模式 _worker.js。
 *  2) Cloudflare 的 WS 层会【丢弃客户端发来的二进制帧】（opcode 0x82），
 *     文本帧（0x81）则完全正常，实测 32KB 无压力。
 *     => 客户端一律用文本帧，载荷用 base64 编码（保证合法 UTF-8）。
 *     边缘->客户端方向二进制是通的，但这里统一用 base64 文本，简单可靠。
 *
 * 协议：WSS 连接 -> 第一条 base64 文本 "host:port" -> 之后每条 base64 文本都是裸 TCP 字节
 * 上游：?m=up 走美国住宅代理；?m=direct 让边缘自己出网
 */
import { connect } from "cloudflare:sockets";

// ---------------------------------------------------------------------------
// 配置：优先从环境变量读取（强烈推荐），下面的默认值仅用于本地调试。
//
// Cloudflare 上设置位置：
//   Pages   -> 项目 -> Settings -> Environment variables（Production 和 Preview 都要加）
//   Workers -> 项目 -> Settings -> Variables and Secrets
//
//   AUTH_TOKEN     客户端口令，必须与 client/wstun.json 的 token 一致
//   UPSTREAM_HOST  上游住宅代理 IP（留空 = 边缘节点自己出网，即机房 IP）
//   UPSTREAM_PORT  上游住宅代理端口
//   UPSTREAM_USER  上游代理账号
//   UPSTREAM_PASS  上游代理密码（建议用 Secret，别用明文变量）
// ---------------------------------------------------------------------------
const DEF = {
  AUTH: "CHANGE-ME-use-a-long-random-token",
  UP_HOST: "",
  UP_PORT: 8080,
  UP_USER: "",
  UP_PASS: "",
};

let AUTH = DEF.AUTH;
let UP_HOST = DEF.UP_HOST;
let UP_PORT = DEF.UP_PORT;
let UP_USER = DEF.UP_USER;
let UP_PASS = DEF.UP_PASS;

// env 在同一 isolate 内是稳定的，这里赋值幂等；未配置时保留上面的默认值。
function bindEnv(env) {
  if (!env) return;
  AUTH = env.AUTH_TOKEN || AUTH;
  if (env.UPSTREAM_HOST !== undefined) UP_HOST = env.UPSTREAM_HOST || "";
  if (env.UPSTREAM_PORT) {
    const p = parseInt(env.UPSTREAM_PORT, 10);
    if (p > 0) UP_PORT = p;
  }
  if (env.UPSTREAM_USER !== undefined) UP_USER = env.UPSTREAM_USER || "";
  if (env.UPSTREAM_PASS !== undefined) UP_PASS = env.UPSTREAM_PASS || "";
}
// 下行切片：走二进制帧，没有 base64 膨胀，可以给得很大。
// 关键原因：Worker 的 isolate 是单线程的，并发连接共享同一份 CPU，
// 帧越小事件循环次数越多，多条流互相挤占就越明显。
const DOWN_CHUNK = 65536;
// 上行切片：必须 base64，实测 CF 的文本帧 32KB 无压力，
// 取 16384（编码后约 21.8KB）在安全范围内。
const CHUNK = 16384;

const enc = new TextEncoder();
const dec = new TextDecoder();

const LOG = [];
function L(s) {
  try {
    LOG.push(new Date().toISOString().slice(11, 23) + " " + s);
    if (LOG.length > 300) LOG.splice(0, LOG.length - 300);
  } catch (e) { /* ignore */ }
}

/* ---------------- base64 ---------------- */
// 上行（客户端->边缘）必须走文本帧，所以还要 base64。
// 用 TextDecoder 做 latin1 解码比 String.fromCharCode.apply 快得多，
// 在 Worker 的 CPU 预算里这块很值钱。
let _latin = null;
try { _latin = new TextDecoder("latin1"); } catch (e) {
  try { _latin = new TextDecoder("windows-1252"); } catch (e2) { _latin = null; }
}
function b64enc(bytes) {
  if (_latin) {
    try { return btoa(_latin.decode(bytes)); } catch (e) { /* 落到下面的回退 */ }
  }
  let s = "";
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  }
  return btoa(s);
}
function b64dec(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64str(s) { return btoa(s); }

function findHeaderEnd(b) {
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i + 4;
  }
  return -1;
}

async function drainConnect(reader) {
  const chunks = [];
  let total = 0;
  for (let i = 0; i < 64; i++) {
    const r = await reader.read();
    if (r.done) throw new Error("upstream closed during CONNECT");
    chunks.push(r.value);
    total += r.value.length;
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { merged.set(c, off); off += c.length; }
    const idx = findHeaderEnd(merged);
    if (idx >= 0) {
      const head = dec.decode(merged.subarray(0, idx));
      if (!/^HTTP\/1\.[01] 2/.test(head)) throw new Error("upstream refused: " + head.split("\r\n")[0]);
      return { rest: merged.subarray(idx) };
    }
  }
  throw new Error("CONNECT response too long");
}

export default {
  async fetch(req, env, ctx) {
    bindEnv(env);
    const url = new URL(req.url);
    const cf = req.cf || {};

    if ((url.searchParams.get("a") || req.headers.get("x-auth") || "") !== AUTH) {
      return new Response("forbidden", { status: 403 });
    }

    const j = (o) => new Response(JSON.stringify(o, null, 2) + "\n",
      { status: 200, headers: { "content-type": "application/json; charset=utf-8" } });

    if (url.searchParams.get("log")) {
      if (url.searchParams.get("log") === "clear") { LOG.length = 0; return new Response("cleared\n"); }
      return j({ colo: cf.colo, n: LOG.length, log: LOG.slice(-100) });
    }

    if (url.searchParams.get("speed")) {
      const n = parseInt(url.searchParams.get("speed"), 10) || 3000000;
      const t0 = Date.now();
      let bytes = 0, status = 0;
      try {
        const r = await fetch("https://speed.cloudflare.com/__down?bytes=" + n);
        status = r.status;
        const b = await r.arrayBuffer();
        bytes = b.byteLength;
      } catch (e) { return j({ error: String(e && e.message || e) }); }
      const dt = (Date.now() - t0) / 1000;
      return j({ colo: cf.colo, via: "cloudflare fetch", bytes, seconds: +dt.toFixed(2),
                 KBps: Math.round(bytes / dt / 1024) });
    }

    // 测边缘 socket 直连目标（不走住宅代理）能不能通
    if (url.searchParams.get("dial")) {
      const t = url.searchParams.get("dial");
      const i = t.lastIndexOf(":");
      const host = t.slice(0, i), port = parseInt(t.slice(i + 1), 10);
      const out = { host, port, colo: cf.colo };
      try {
        const t0 = Date.now();
        const s = connect({ hostname: host, port });
        await s.opened;
        out.opened_ms = Date.now() - t0;
        const w = s.writable.getWriter();
        await w.write(enc.encode("GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: curl/8\r\n\r\n"));
        const rd = s.readable.getReader();
        let got = "";
        const t1 = Date.now();
        while (Date.now() - t1 < 8000 && got.length < 200) {
          const r = await rd.read();
          if (r.done) break;
          got += dec.decode(r.value);
        }
        out.first = got.split("\r\n")[0] || "(empty)";
        try { s.close(); } catch (e) { /* ignore */ }
      } catch (e) {
        out.error = String((e && e.message) || e).slice(0, 100);
      }
      return j(out);
    }

    if (url.searchParams.get("diag")) {
      const hosts = ["www.google.com", "chatgpt.com", "example.com", "www.youtube.com"];
      const out = [];
      for (const h of hosts) {
        try {
          const s = connect({ hostname: UP_HOST, port: UP_PORT });
          await s.opened;
          const w = s.writable.getWriter();
          await w.write(enc.encode("CONNECT " + h + ":80 HTTP/1.1\r\nHost: " + h + ":80\r\n" +
            "Proxy-Authorization: Basic " + b64str(UP_USER + ":" + UP_PASS) + "\r\n\r\n"));
          const r0 = s.readable.getReader();
          await drainConnect(r0);
          r0.releaseLock();
          await w.write(enc.encode("GET / HTTP/1.1\r\nHost: " + h +
            "\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"));
          const rd = s.readable.getReader();
          let got = "";
          const t0 = Date.now();
          while (Date.now() - t0 < 8000 && got.length < 120) {
            const r = await rd.read();
            if (r.done) break;
            got += dec.decode(r.value);
          }
          out.push({ host: h, upstream: got.split("\r\n")[0] || "(empty)" });
          try { s.close(); } catch (e) { /* ignore */ }
        } catch (e) {
          out.push({ host: h, upstream: "ERR " + (((e && e.message) ? e.message : String(e))).slice(0, 60) });
        }
      }
      return j({ colo: cf.colo, out });
    }

    // 测生产路径下住宅代理真实带宽：worker(US) -> 住宅代理 -> 目标:80 大文件。
    // ?upspeed=N 开 N 条并行住宅连接测聚合，验证并行是否叠加（Worker 的 connect 是裸 TCP，
    // 无法对目标做 TLS，所以用明文 HTTP/1.1 大文件测吞吐，足以反映代理出口带宽）。
    if (url.searchParams.get("upspeed")) {
      const n = Math.min(parseInt(url.searchParams.get("upspeed"), 10) || 1, 8);
      const dur = 4;
      const TH = "ipv4.download.thinkbroadband.com", TP = 80, PATH = "/20MB.zip";
      const merge = (a, b) => { const c = new Uint8Array(a.length + b.length); c.set(a); c.set(b, a.length); return c; };
      const oneConn = async () => {
        const s = connect({ hostname: UP_HOST, port: UP_PORT });
        await s.opened;
        const w = s.writable.getWriter();
        await w.write(enc.encode("CONNECT " + TH + ":" + TP + " HTTP/1.1\r\nHost: " + TH + ":" + TP + "\r\n" +
          "Proxy-Authorization: Basic " + b64str(UP_USER + ":" + UP_PASS) + "\r\n\r\n"));
        const r0 = s.readable.getReader();
        let buf = new Uint8Array(0), headEnd = -1;
        for (let i = 0; i < 40; i++) {
          const r = await r0.read();
          if (r.done) break;
          buf = merge(buf, r.value);
          const idx = findHeaderEnd(buf);
          if (idx >= 0) { headEnd = idx; break; }
        }
        r0.releaseLock();
        if (headEnd < 0) { try { s.close(); } catch (e) {} return 0; }
        await w.write(enc.encode("GET " + PATH + " HTTP/1.1\r\nHost: " + TH +
          "\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"));
        const t0 = Date.now();
        let total = 0;
        const rd = s.readable.getReader();
        try {
          while (Date.now() - t0 < dur * 1000) {
            const r = await rd.read();
            if (r.done) break;
            total += r.value.length;
          }
        } catch (e) { /* ignore */ }
        try { s.close(); } catch (e) {}
        return total;
      };
      const results = await Promise.all(Array.from({ length: n }, () => oneConn()));
      const total = results.reduce((a, b) => a + b, 0);
      return j({ colo: cf.colo, conns: n, bytes: total, seconds: dur,
        agg_KBps: Math.round(total / dur / 1024),
        per_KBps: Math.round(total / n / dur / 1024),
        note: "worker(US)->residential proxy->" + TH + ":80" });
    }

    // 通用下载测速：?get=URL&mode=direct|up&sec=N
    // direct: 走 CF 出口 fetch(URL)（支持任意 https）；up: 走住宅代理 CONNECT+HTTP/1.1 GET（仅 http:80 明文，Worker 不能对 :443 做 TLS）
    if (url.searchParams.get("get")) {
      const target = url.searchParams.get("get");
      const mode = (url.searchParams.get("mode") || "direct").toLowerCase();
      const sec = Math.min(parseInt(url.searchParams.get("sec"), 10) || 5, 20);
      let u;
      try { u = new URL(target); } catch (e) { return j({ error: "bad url" }); }
      if (mode === "direct") {
        const t0 = Date.now(); let bytes = 0; let status = 0;
        let bodyBuf = new Uint8Array(0);
        const merge = (a, b) => { const c = new Uint8Array(a.length + b.length); c.set(a); c.set(b, a.length); return c; };
        try {
          const r = await fetch(u.toString(), { headers: { "User-Agent": "curl/8" } });
          status = r.status;
          if (!r.body) return j({ via: "direct", status, error: "no body" });
          const rd = r.body.getReader();
          while (Date.now() - t0 < sec * 1000) {
            const c = await rd.read(); if (c.done) break; bytes += c.value.length;
            bodyBuf = merge(bodyBuf, c.value);
          }
        } catch (e) { return j({ via: "direct", error: String((e && e.message) || e) }); }
        const dt = (Date.now() - t0) / 1000;
        let preview = "";
        try { preview = dec.decode(bodyBuf.slice(0, 400)); } catch (e) {}
        return j({ via: "direct", colo: cf.colo, url: u.toString(), status, seconds: +dt.toFixed(2), KBps: Math.round(bytes / dt / 1024), bytes, preview });
      } else {
        if (u.protocol !== "http:") return j({ via: "up", error: "residential path supports http:80 only (Worker cannot TLS to :443)" });
        const TH = u.hostname, TP = u.port ? parseInt(u.port, 10) : 80, PATH = u.pathname + (u.search || "");
        const merge = (a, b) => { const c = new Uint8Array(a.length + b.length); c.set(a); c.set(b, a.length); return c; };
        let t0 = Date.now(), bytes = 0;
        let bufAll = new Uint8Array(0);
        try {
          const s = connect({ hostname: UP_HOST, port: UP_PORT }); await s.opened;
          const w = s.writable.getWriter();
          await w.write(enc.encode("CONNECT " + TH + ":" + TP + " HTTP/1.1\r\nHost: " + TH + ":" + TP + "\r\n" +
            "Proxy-Authorization: Basic " + b64str(UP_USER + ":" + UP_PASS) + "\r\n\r\n"));
          const r0 = s.readable.getReader(); let buf = new Uint8Array(0), he = -1;
          for (let i = 0; i < 40; i++) { const r = await r0.read(); if (r.done) break; buf = merge(buf, r.value); const idx = findHeaderEnd(buf); if (idx >= 0) { he = idx; break; } }
          r0.releaseLock();
          if (he < 0) { try { s.close(); } catch (e) {} return j({ via: "up", error: "proxy connect failed" }); }
          await w.write(enc.encode("GET " + PATH + " HTTP/1.1\r\nHost: " + TH + "\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"));
          const rd = s.readable.getReader();
          while (Date.now() - t0 < sec * 1000) {
            const r = await rd.read();
            if (r.done) break;
            bytes += r.value.length;
            const nb = new Uint8Array(bufAll.length + r.value.length);
            nb.set(bufAll); nb.set(r.value, bufAll.length);
            bufAll = nb;
          }
          try { s.close(); } catch (e) {}
        } catch (e) { return j({ via: "up", error: String((e && e.message) || e) }); }
        const dt = (Date.now() - t0) / 1000;
        let preview = "";
        try { preview = dec.decode(bufAll.slice(0, 400)); } catch (e) {}
        return j({ via: "up", colo: cf.colo, url: u.toString(), seconds: +dt.toFixed(2), KBps: Math.round(bytes / dt / 1024), bytes, preview });
      }
    }

    // 取响应体原文（用于排查/找端点）：?raw=URL （走 CF 出口 fetch）
    if (url.searchParams.get("raw")) {
      const target = url.searchParams.get("raw");
      try {
        const u = new URL(target);
        const r = await fetch(u.toString(), { headers: { "User-Agent": "curl/8" } });
        const b = await r.text();
        return new Response(JSON.stringify({ status: r.status, len: b.length, head: b.slice(0, 40000) }),
          { headers: { "content-type": "application/json; charset=utf-8" } });
      } catch (e) { return j({ error: String((e && e.message) || e) }); }
    }

    if ((req.headers.get("upgrade") || "").toLowerCase() !== "websocket") {
      return j({ ok: true, mode: "advanced-worker", framing: "base64-text", colo: cf.colo, country: cf.country });
    }

    const mode = url.searchParams.get("m") || "up";
    const echo = url.searchParams.get("echo") === "1";
    L("WS conn mode=" + mode + " colo=" + cf.colo + (echo ? " echo" : ""));

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    let socket = null, writer = null, started = false, ready = false, closed = false;
    let sentFrames = 0, sentBytes = 0, recvFrames = 0, recvBytes = 0;
    // 上游还没连好时先排队。客户端往往在建连消息之后立刻就把 TLS ClientHello
    // 发过来了，此时 writer 还是 null —— 早期版本会把这些数据静默丢弃，
    // 表现就是「HTTP 通、HTTPS 握手必失败」。
    const pending = [];
    let chain = Promise.resolve();

    const cleanup = () => {
      if (closed) return;
      closed = true;
      L("cleanup up=" + sentFrames + "F/" + sentBytes + "B down=" + recvFrames + "F/" + recvBytes + "B");
      try { if (socket) socket.close(); } catch (e) { /* ignore */ }
      try { server.close(); } catch (e) { /* ignore */ }
    };

    // 下行（边缘->客户端）直接发二进制帧：
    // 1) 省掉边缘的 base64 编码和客户端的解码，两边 CPU 都省；
    // 2) 境内这段少传 33% 的字节。
    // Cloudflare 只丢「客户端发来的」二进制帧，下行二进制实测正常。
    const push = (buf) => {
      for (let i = 0; i < buf.length; i += CHUNK) {
        const part = buf.subarray(i, Math.min(i + CHUNK, buf.length));
        server.send(part);
        sentFrames++; sentBytes += part.length;
      }
    };

    const fail = (tag, e) => {
      const msg = "EDGE_ERR " + tag + ": " + (((e && e.message) ? e.message : String(e)) || "").slice(0, 120);
      L("FAIL " + msg);
      try { server.send(b64enc(enc.encode(msg))); } catch (e) { /* ignore */ }
      cleanup();
    };

    async function handleMsg(s) {
      let raw;
      try { raw = b64dec(s); } catch (e) { return; }
      recvFrames++; recvBytes += raw.length;
      if (echo) { server.send(b64enc(raw)); return; }

      if (!started) {
        started = true;
        const target = dec.decode(raw).trim();
        L("target=" + target);
        const i = target.lastIndexOf(":");
        if (i < 0) throw new Error("bad target " + target);
        const host = target.slice(0, i);
        const port = parseInt(target.slice(i + 1), 10);
        if (!host || !port) throw new Error("bad target");

        socket = connect({
          hostname: mode === "direct" ? host : UP_HOST,
          port: mode === "direct" ? port : UP_PORT,
        });
        await socket.opened;
        writer = socket.writable.getWriter();
        if (mode !== "direct") {
          await writer.write(enc.encode("CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " +
            host + ":" + port + "\r\nProxy-Authorization: Basic " +
            b64str(UP_USER + ":" + UP_PASS) + "\r\n\r\n"));
          const r0 = socket.readable.getReader();
          const r = await drainConnect(r0);
          r0.releaseLock();
          if (r.rest.length) push(r.rest);
        }
        L("dial ok " + host + ":" + port + " pending=" + pending.length);
        ready = true;
        // 补发排队期间攒下的数据
        if (pending.length) {
          for (const p of pending) await writer.write(p);
          pending.length = 0;
        }
        const reader = socket.readable.getReader();
        (async () => {
          try {
            for (;;) {
              const rr = await reader.read();
              if (rr.done) break;
              if (rr.value && rr.value.length) push(rr.value);
            }
          } catch (e) { L("read err " + ((e && e.message) ? e.message : e)); }
          cleanup();
        })();
        return;
      }

      if (ready && writer) {
        await writer.write(raw);
      } else if (!closed) {
        pending.push(raw);
        if (pending.length > 256) pending.shift();   // 兜底，别无限涨
      }
    }

    server.addEventListener("message", (ev) => {
      const s = ev.data;
      if (typeof s !== "string" || s.length === 0) return;
      // 串行处理，保证字节顺序与客户端发出的一致
      chain = chain.then(() => handleMsg(s)).catch((e) => fail("relay", e));
      ctx.waitUntil(chain);
    });

    server.addEventListener("close", () => cleanup());
    server.addEventListener("error", (e) => { L("err " + ((e && e.message) || "")); cleanup(); });

    return new Response(null, { status: 101, webSocket: client });
  }
};
