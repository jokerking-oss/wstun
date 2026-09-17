#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wstun 本地端  ——  Windows 一键翻墙客户端

原理：
  本机 127.0.0.1:10808 开一个 SOCKS5 / HTTP 双协议代理
  每一条连接被封进一条 WSS（TLS 里的 WebSocket）送到境外边缘节点
  边缘节点再把字节还原成 TCP，经美国住宅代理出去
  => 中国大陆这一段链路上没有任何明文 SNI，只有一条普通的 HTTPS 连接

依赖：仅 Python 标准库，无需 pip 安装任何东西。
"""
import os, sys, json, socket, ssl, struct, base64, threading, time, random, select, bisect

HERE = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(HERE, "wstun.json")
LOG_PATH = os.path.join(HERE, "wstun.log")
IP_PATH = os.path.join(HERE, "goodip.json")
DF_PATH = os.path.join(HERE, "direct_fail.json")
CNIP_PATH = os.path.join(HERE, "china_ip.txt")
LOG_LOCK = threading.Lock()
STATS = {"ok": 0, "fail": 0, "fallback": 0, "local": 0}

# 本次连接去本地直连（国内站点），完全不经过隧道和任何代理
LOCAL_DIRECT = "local_direct"

# 域名 -> 上次成功连上的 IP。Cloudflare 一个域名解析出多个 IP，其中一部分
# 在国内是死的（SYN 直接丢包，要等 21s 才超时）。记住能用的那个，别再踩坑。
_GOODIP = {}
_IP_LOCK = threading.Lock()
try:
    if os.path.exists(IP_PATH):
        with open(IP_PATH, "r", encoding="utf-8") as f:
            _GOODIP = json.load(f)
except Exception:
    _GOODIP = {}


def _save_goodip(host, ip):
    with _IP_LOCK:
        _GOODIP[host] = ip
        try:
            with open(IP_PATH, "w", encoding="utf-8") as f:
                json.dump(_GOODIP, f)
        except Exception:
            pass


def connect_fast(host, port, timeout=30, per_ip=4):
    """逐个候选 IP 试连，每个最多 per_ip 秒。

    socket.create_connection 拿到多个 A 记录时会按顺序死等第一个，
    遇上被丢包的 IP 就要白白等 ~21s（Windows 的 SYN 重试节奏）。
    这里改成：已知可用 IP 优先 + 每个 IP 短超时快速切换。
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except Exception:
        infos = []
    addrs = []
    for it in infos:
        ip = it[4][0]
        if ip not in addrs:
            addrs.append(ip)
    good = _GOODIP.get(host)
    if good in addrs:
        addrs.remove(good)
        addrs.insert(0, good)
    if not addrs:
        addrs = [(host, port)]
    last = None
    for ip in addrs:
        try:
            s = socket.create_connection((ip, port) if isinstance(ip, str) else ip,
                                         timeout=min(timeout, per_ip))
            _save_goodip(host, ip if isinstance(ip, str) else ip[0])
            return s
        except Exception as e:
            last = e
    raise last if last else OSError("connect failed")


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    try:
        with LOG_LOCK:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass
    try:
        print(line, flush=True)
    except Exception:
        pass


# ---------------------------------------------------------------- WebSocket
class WSError(Exception):
    pass


class WS:
    """极简 WebSocket 客户端（仅二进制帧，自带掩码/心跳），纯标准库"""

    def __init__(self, url, timeout=25, insecure=False):
        self.url = url
        self.timeout = timeout
        self.insecure = insecure
        self.sock = None
        self._buf = b""
        self._rx = 0          # 收到的字节数（用于判断这条路到底通不通）
        self._tx = 0
        self.mode = None      # "direct" / "up"
        self._t0 = time.time()
        self._edge_err = None  # 边缘回的明确错误（说明这条路不通）

    def _readn(self, n):
        buf = b""
        if self._buf:
            # 握手响应尾部的残留字节（CF 会在 101 之后立刻发帧），必须先消费掉
            take = self._buf[:n]
            self._buf = self._buf[n:]
            if len(take) == n:
                return take
            buf = take
        while len(buf) < n:
            c = self.sock.recv(n - len(buf))
            if not c:
                raise WSError("eof")
            buf += c
        return buf

    @staticmethod
    def _nagle_off(s):
        """关掉 Nagle。默认开启时小包会被攒 40ms 再发，
        对 TLS 握手这种一问一答的交互是纯损失。"""
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

    def connect(self):
        from urllib.parse import urlparse
        u = urlparse(self.url)
        scheme = u.scheme.lower()
        host = u.hostname
        port = u.port or (443 if scheme == "wss" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query

        raw = connect_fast(host, port, timeout=self.timeout)
        if scheme == "wss":
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            self.sock = raw
        self.sock.settimeout(self.timeout)
        self._nagle_off(self.sock)

        key = base64.b64encode(bytes(random.getrandbits(8) for _ in range(16))).decode()
        req = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (path, (host if u.port is None else "%s:%d" % (host, port)), key)
        )
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = self.sock.recv(4096)
            if not d:
                raise WSError("handshake eof")
            buf += d
        if b"101" not in buf.split(b"\r\n")[0]:
            raise WSError("handshake failed: " + buf.split(b"\r\n")[0].decode("latin1"))
        self._buf = buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""

    def send(self, data: bytes, chunk=16384):
        """分片发送，每片一个独立的【文本帧】，载荷 base64 编码。

        两个实测结论，别改回去：
        1) Cloudflare 的 WS 层会直接【丢弃客户端发来的二进制帧】(opcode 0x82)，
           文本帧 (0x81) 完全正常，实测 32KB 无压力。
        2) 因为文本帧必须是合法 UTF-8，裸 TCP 字节用 base64 编码后再发
           （约 33% 开销，换来 100% 的投递率，很值）。
        TCP 是字节流，把一个大包拆成多个小帧在语义上完全等价。
        """
        if not data:
            return
        self._tx += len(data)
        for i in range(0, len(data), chunk):
            self._send_frame(base64.b64encode(data[i:i + chunk]).decode("ascii"))

    def _send_frame(self, text: str):
        payload = text.encode("ascii")
        hdr = bytearray()
        hdr.append(0x81)  # FIN + text
        n = len(payload)
        mask = bytes(random.getrandbits(8) for _ in range(4))
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        hdr += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(hdr) + masked)

    def ping(self):
        try:
            mask = bytes(random.getrandbits(8) for _ in range(4))
            hdr = bytes([0x89, 0x80]) + mask
            self.sock.sendall(hdr)
        except Exception:
            raise WSError("ping failed")

    def recv(self):
        """返回 bytes；b'' 表示对端关闭"""
        while True:
            head = self._readn(2)
            b0, b1 = head[0], head[1]
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            ln = b1 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._readn(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._readn(8))[0]
            if masked:
                m = self._readn(4)
            payload = self._readn(ln) if ln else b""
            if masked:
                payload = bytes(x ^ m[i % 4] for i, x in enumerate(payload))
            if opcode == 0x8:
                return b""
            if opcode == 0x9:
                self.ping()  # 用 pong 位回一个（0x89 是 ping，够用作心跳应答）
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x2:
                # 下行已经是纯二进制（见 wstun.py 的注释：CF 只丢上行二进制帧），
                # 直接交给应用，省掉一次 base64 解码。
                self._rx += len(payload)
                return payload
            # 文本帧：上行方向的载荷 + 边缘的错误提示，走 base64
            try:
                out = base64.b64decode(payload)
            except Exception:
                out = payload
            # 边缘连不上上游时会回 EDGE_ERR 文本（CF 拒绝连某些目标时会这样）。
            # 别把它当数据交给应用——否则浏览器会把它当成 TLS 响应而报握手错误。
            if out.startswith(b"EDGE_ERR"):
                self._edge_err = out[:200].decode("latin1", "replace")
                return b""
            self._rx += len(out)
            return out

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------- 通道
def plain_pipe(a, b):
    """两个裸 socket 双向搬运（兜底直连时用）"""

    def one_way(x, y):
        try:
            while True:
                data = x.recv(65536)
                if not data:
                    break
                y.sendall(data)
        except Exception:
            pass
        finally:
            for s in (x, y):
                try:
                    s.close()
                except Exception:
                    pass

    t = threading.Thread(target=one_way, args=(a, b), daemon=True)
    t.start()
    one_way(b, a)


def ws_to_sock(ws, sock):
    try:
        while True:
            try:
                data = ws.recv()
            except socket.timeout:
                try:
                    ws.ping()
                except Exception:
                    break
                continue
            if not data:
                break
            sock.sendall(data)
    except Exception:
        pass
    finally:
        try: sock.close()
        except Exception: pass
        try: ws.close()
        except Exception: pass


def sock_to_ws(sock, ws):
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            ws.send(data)
    except Exception:
        pass
    finally:
        try: sock.close()
        except Exception: pass
        try: ws.close()
        except Exception: pass


# ---------------------------------------------------------------- 直连兜底
def direct_connect(target_host, target_port, fallback, timeout=15):
    """兜底：直连住宅代理（明文）。被掐的站点仍会失败，但不影响其它站点。"""
    if not fallback:
        return None
    try:
        from urllib.parse import urlparse
        u = urlparse(fallback)
        s = socket.create_connection((u.hostname, u.port), timeout=timeout)
        auth = ""
        if u.username:
            import base64 as _b
            auth = "Proxy-Authorization: Basic %s\r\n" % _b.b64encode(
                ("%s:%s" % (u.username, u.password or "")).encode()).decode()
        s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%s\r\n"
                   % (target_host, target_port, target_host, target_port, auth)).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                raise OSError("closed")
            buf += d
        if not buf.startswith(b"HTTP/1.1 200") and not buf.startswith(b"HTTP/1.0 200"):
            raise OSError("refused:" + buf[:40].decode("latin1"))
        return s
    except Exception:
        return None


# ------------------------------------------------------- 国内直连（不走隧道）
# 目标：国内站点用本机真实线路直连（快、稳），其余一律走美国住宅代理。
# 判据有两层：① 域名是否命中国内域名名单；② 解析出的 IP 是否落在国内 IP 段。
_CN_NETS = []        # [(起始IP整数, 结束IP整数)]，按起始排序
_CN_STARTS = []      # 起始值数组，供 bisect 二分
_CN_LOCK = threading.Lock()


def load_cn_nets(path):
    """载入国内 IPv4 段表（每行一个 CIDR）。返回载入条数。"""
    global _CN_NETS, _CN_STARTS
    nets = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or "/" not in ln or ln.startswith("#"):
                    continue
                ip, _, m = ln.partition("/")
                try:
                    bits = int(m)
                    a = struct.unpack(">I", socket.inet_aton(ip))[0]
                except Exception:
                    continue
                if bits < 0 or bits > 32:
                    continue
                mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
                nets.append((a & mask, (a & mask) | (~mask & 0xFFFFFFFF)))
    except Exception as e:
        log("  [warn] 载入 %s 失败: %s" % (os.path.basename(path), str(e)[:60]))
        return 0
    nets.sort()
    with _CN_LOCK:
        _CN_NETS = nets
        _CN_STARTS = [n[0] for n in nets]
    return len(nets)


def ip_in_cn(ip):
    """判断一个 IPv4 字面量是否属于国内地址段。"""
    if not ip or ip.count(".") != 3:
        return False
    try:
        v = struct.unpack(">I", socket.inet_aton(ip))[0]
    except Exception:
        return False
    if not _CN_STARTS:
        return False
    i = bisect.bisect_right(_CN_STARTS, v) - 1
    if i < 0:
        return False
    s, e = _CN_NETS[i]
    return s <= v <= e


def _is_ip_literal(h):
    if not h:
        return False
    if ":" in h:                       # IPv6 字面量
        return True
    return h.count(".") == 3 and h[0].isdigit()


def _dns_via(host, server, timeout=3):
    """手搓 A 记录查询，用于绕开被代理软件劫持的本地 53 端口。"""
    out = []
    try:
        tid = random.randint(0, 0xFFFF)
        q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        for part in host.rstrip(".").split("."):
            b = part.encode("idna")
            q += bytes([len(b)]) + b
        q += b"\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(4096)
        s.close()
        if len(data) < 12 or struct.unpack(">H", data[:2])[0] != tid:
            return out
        anc = struct.unpack(">H", data[6:8])[0]
        i = 12
        while i < len(data) and data[i] != 0:      # 跳过 QNAME
            i += data[i] + 1
        i += 5                                    # 0 + QTYPE + QCLASS
        for _ in range(anc):
            if i >= len(data):
                break
            if (data[i] & 0xC0) == 0xC0:          # 压缩指针
                i += 2
            else:
                while i < len(data) and data[i] != 0:
                    i += data[i] + 1
                i += 1
            if i + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            if rtype == 1 and rdlen == 4:
                out.append(socket.inet_ntoa(data[i:i + 4]))
            i += rdlen
    except Exception:
        pass
    return out


def local_connect(host, port, timeout=15):
    """真·直连：不经过隧道、也不经过任何代理，用本机线路连出去。"""
    infos = []
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except Exception:
        infos = []
    if not infos:
        for ip in _dns_via(host, "223.5.5.5"):        # 阿里公共 DNS 兜底
            infos.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)))
    last = None
    for af, st, proto, _, sa in infos:
        s = None
        try:
            s = socket.socket(af, st, proto)
            s.settimeout(timeout)
            WS._nagle_off(s)
            s.connect(sa)
            s.settimeout(None)
            return s
        except Exception as e:
            last = e
            try:
                if s:
                    s.close()
            except Exception:
                pass
    log("  国内直连失败 %s:%d (%s)" % (host, port, str(last)[:50]))
    return None


# ---------------------------------------------------------------- 连接池
class Pool:
    """预热连接池。

    每新建一条隧道要付约 1.1 秒的固定成本（TCP + TLS + WS 握手）。
    一个网页几十个资源，逐个付这个代价就是「打开网页很慢」的主因。
    这里提前把 WSS 握手做完，请求来了直接取用，只付剩余的上游 dial 时间。
    """

    def __init__(self, mk, sizes=None, ttl=30, idle_stop=90):
        self.mk = mk                      # mk(mode) -> 已握手的 WS
        self.sizes = sizes or {"direct": 4, "up": 2}
        self.ttl = ttl                    # 池中连接最长存活时间（秒）
        self.idle_stop = idle_stop        # 这么久没请求就停止预热，别空烧额度
        self.q = {m: [] for m in self.sizes}
        self.lock = threading.Lock()
        self.last_use = time.time()

    def _alive(self, ws):
        try:
            if getattr(ws, "sock", None) is None:
                return False
            r, _, _ = select.select([ws.sock], [], [], 0)
            return not r                  # 有数据/EOF 说明这条已经废了
        except Exception:
            return False

    def put(self, mode, ws):
        try:
            ws.close()
        except Exception:
            pass

    def get(self, mode):
        self.last_use = time.time()
        with self.lock:
            lst = self.q.get(mode, [])
            while lst:
                ws, ts = lst.pop()
                if time.time() - ts < self.ttl and self._alive(ws):
                    return ws
                try:
                    ws.close()
                except Exception:
                    pass
        return self.mk(mode)              # 池空或都过期：现场建（退化成老行为）

    def maintain(self):
        while True:
            time.sleep(2)
            try:
                if time.time() - self.last_use > self.idle_stop:
                    with self.lock:      # 长时间没人用：清空，省额度
                        for m in self.q:
                            for ws, _ in self.q[m]:
                                try: ws.close()
                                except Exception: pass
                            self.q[m] = []
                    continue
                for mode, want in self.sizes.items():
                    with self.lock:
                        lst = self.q.setdefault(mode, [])
                        now = time.time()
                        fresh = []
                        for item in lst:
                            if now - item[1] < self.ttl and self._alive(item[0]):
                                fresh.append(item)
                            else:
                                try: item[0].close()
                                except Exception: pass
                        lst[:] = fresh
                        need = want - len(lst)
                    for _ in range(max(0, need)):
                        try:
                            ws = self.mk(mode)
                        except Exception:
                            break
                        with self.lock:
                            self.q[mode].append((ws, time.time()))
            except Exception:
                pass


# ---------------------------------------------------------------- 主服务
class Server:
    def __init__(self, cfg):
        self.cfg = cfg
        self.endpoint = cfg["endpoint"]
        self.token = cfg.get("token", "")
        self.timeout = int(cfg.get("timeout", 25))
        self.insecure = bool(cfg.get("tls_skip_verify", False))
        self.fallback = cfg.get("fallback", "")
        self.host = cfg.get("listen_host", "127.0.0.1")
        self.port = int(cfg.get("listen_port", 10808))
        # 分流：默认走 Cloudflare 自己的出口（快），只有名单里的站点才绕住宅代理
        self.default_mode = cfg.get("default_mode", "direct")
        # 防范性开关：true 时彻底切断 Cloudflare 机房出口（direct）通路，
        # 保证任何请求的出口都是住宅 IP —— 宁可失败，也不静默漏成机房 IP。
        self.strict = bool(cfg.get("strict_residential", False))
        if self.strict:
            self.default_mode = "up"
        self.residential = [d.lower() for d in cfg.get("residential", [])]
        # 国内直连：命中名单/国内 IP 段的目标直接出本机线路，不入隧道。
        cd = cfg.get("cn_direct") or {}
        self.cn_direct = bool(cd.get("enabled", False))
        self.cn_domains = [(d or "").lower().lstrip(".") for d in cd.get("domains", [])]
        self.cn_nets_n = 0
        if self.cn_direct:
            self.cn_nets_n = load_cn_nets(os.path.join(HERE, cd.get("ip_file", "china_ip.txt")))
        self._dns_cache = {}          # host -> (ip 或 None, 记录时间)
        self._dns_lock = threading.Lock()
        poolcfg = cfg.get("pool", {})
        self.pool = Pool(self._mk_ws,
                         sizes={"direct": int(poolcfg.get("direct", 6)),
                                "up": int(poolcfg.get("up", 2))},
                         ttl=int(poolcfg.get("ttl", 30)),
                         idle_stop=int(poolcfg.get("idle_stop", 90)))
        # 走 CF 直连失败的域名（CF 的 socket 连不了自家域名等），6 小时内改走住宅代理
        self._direct_fail = {}
        self._df_lock = threading.Lock()
        try:
            if os.path.exists(DF_PATH):
                with open(DF_PATH, "r", encoding="utf-8") as f:
                    self._direct_fail = json.load(f)
        except Exception:
            self._direct_fail = {}

    def _endpoint(self, mode):
        """在基础 URL 上补上鉴权与上游模式，避免旧配置里写死的 m= 干扰"""
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        u = urlparse(self.endpoint)
        q = dict(parse_qsl(u.query))
        if self.token:
            q["a"] = self.token
        q["m"] = mode
        return urlunparse((u.scheme, u.netloc, u.path, "", urlencode(q), ""))

    def _mk_ws(self, mode):
        # strict：任何绕过住宅代理的企图都被强行掰回 up，楼层封死在代码层
        if self.strict and mode != "up":
            mode = "up"
        ws = WS(self._endpoint(mode), timeout=self.timeout, insecure=self.insecure)
        ws.connect()
        ws.mode = mode
        return ws

    def _resolve_cached(self, host):
        """带缓存的本地解析：只为判断目标是不是国内，结果 10 分钟内复用。"""
        now = time.time()
        with self._dns_lock:
            rec = self._dns_cache.get(host)
        if rec and (now - rec[1]) < (600 if rec[0] else 60):
            return rec[0]
        ip = None
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            for _af, _st, _pr, _cn, sa in infos:
                ip = sa[0]
                break
        except Exception:
            ip = None
        with self._dns_lock:
            if len(self._dns_cache) > 2000:
                self._dns_cache.clear()
            self._dns_cache[host] = (ip, now)
        return ip

    def is_domestic(self, host):
        """判断目标是不是国内（应该走本机直连）。"""
        h = (host or "").lower().rstrip(".")
        if not h:
            return False
        # ① 域名后缀命中
        for d in self.cn_domains:
            if h == d or h.endswith("." + d):
                return True
        # ② IP 字面量（浏览器把域名解析在本地时走这条）
        if _is_ip_literal(h):
            return ip_in_cn(h)
        # ③ 域名未命中名单时，自己解析一次看落点
        ip = self._resolve_cached(h)
        return bool(ip) and ip_in_cn(ip)

    def route(self, host):
        """决定这条连接怎么走：

        LOCAL_DIRECT —— 国内站点，本机真·直连
        "up"         —— 美国住宅代理（默认出口）
        "direct"     —— Cloudflare 边缘出口（strict 模式下不会用到）

        顺序很重要：先让 residential 名单（AI / 流媒体 / IP 检测站）优先锁定
        住宅出口，任何情况下都不会被国内直连规则误抢——这是纯净度的保险。
        """
        h = (host or "").lower().rstrip(".")
        for d in self.residential:
            if h == d or h.endswith("." + d):
                return "up"
        if self.cn_direct and self.is_domestic(h):
            return LOCAL_DIRECT
        if self.strict:
            return "up"          # 防范性：其余目标一律住宅，无例外
        # CF 的 socket 连不了少数目标（比如 Cloudflare 自家域名）。
        # 要连续失败两次才拉黑：单次很可能是偶发，误拉黑会把本来很快的
        # 站点推去挤 1MB/s 的住宅代理。
        with self._df_lock:
            rec = self._direct_fail.get(h)
        if isinstance(rec, dict):
            if rec.get("n", 0) >= 2 and (time.time() - rec.get("t", 0)) < 2 * 3600:
                return "up"
        elif isinstance(rec, (int, float)):        # 旧格式：单时间戳
            if (time.time() - rec) < 2 * 3600:
                return "up"
        return self.default_mode

    def _note_result(self, host, up):
        """连接结束后：如果 direct 这条路几乎没传数据，就拉黑它"""
        if not isinstance(up, WS) or up.mode != "direct":
            return
        # 只有边缘明确报错（CF 拒绝连这个目标）才算 direct 不通。
        # 不要按「数据少、结束快」判断——404/301/302 这类正常小响应会被误伤。
        if not getattr(up, "_edge_err", None):
            return
        h = (host or "").lower()
        with self._df_lock:
            rec = self._direct_fail.get(h)
            n = (rec.get("n", 0) if isinstance(rec, dict) else 1) + 1
            self._direct_fail[h] = {"n": n, "t": time.time()}
            try:
                with open(DF_PATH, "w", encoding="utf-8") as f:
                    json.dump(self._direct_fail, f)
            except Exception:
                pass
        if n < 2:
            log("  direct 对 %s 失败 1 次，先观察（%s）"
                % (host, (up._edge_err or "")[:50]))
            return
        log("  direct 对 %s 连续失败，已记下，之后改走住宅代理" % host)

    def _tunnel(self, host, port, first_bytes=b""):
        """返回通道对象（WS 或裸 socket）。

        优先从预热池取连接（省掉 ~1.1s 的握手），失败则退回住宅代理，
        最后才考虑明文兜底。
        """
        mode = self.route(host)
        log("  %s:%d -> %s" % (host, port, "本地直连" if mode == LOCAL_DIRECT else mode))
        if mode == LOCAL_DIRECT:
            # 国内站点：本机线路直连，不入隧道，也不碰住宅代理
            s = local_connect(host, port, timeout=min(self.timeout, 20))
            if s is None:
                STATS["fail"] += 1
                raise OSError("国内直连失败: %s:%d" % (host, port))
            STATS["local"] += 1
            if first_bytes:
                s.sendall(first_bytes)
            return s
        last = ""
        for attempt in range(3):
            try:
                ws = self.pool.get(mode)
                ws._t0 = time.time()      # 从这一刻才算这条连接真正开始干活
                ws._edge_err = None
                ws.send(("%s:%d" % (host, port)).encode())
                if first_bytes:
                    ws.send(first_bytes)
                return ws
            except Exception as e:
                last = str(e)[:70]
                # CF 直连对部分目标不可用（例如 80 端口），退回住宅代理重试
                if mode != "up":
                    mode = "up"
                time.sleep(0.15)
        # strict：不启用明文兜底。明文 CONNECT 会把目标域名暴露给 GFW，
        # 而且万一兜底指向别的出口，就直接把「纯净度」毁了 —— 宁可报错。
        if self.strict:
            STATS["fail"] += 1
            raise OSError("strict_residential: 住宅路径失败，拒绝任何降级兜底: " + last)
        log("  隧道失败(%s:%d): %s —— 尝试兜底" % (host, port, last))
        s = direct_connect(host, port, self.fallback)
        if s is None:
            STATS["fail"] += 1
            raise OSError("tunnel and fallback both failed: " + last)
        STATS["fallback"] += 1
        if first_bytes:
            s.sendall(first_bytes)
        return s

    # ---------- SOCKS5 ----------
    def handle_socks(self, c):
        c.recv(262)
        c.sendall(b"\x05\x00")
        hdr = c.recv(4)
        if len(hdr) < 4 or hdr[1] != 1:
            c.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        atyp = hdr[3]
        if atyp == 1:
            host = socket.inet_ntoa(c.recv(4))
        elif atyp == 3:
            n = c.recv(1)[0]
            host = c.recv(n).decode("latin1")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, c.recv(16))
        else:
            c.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = struct.unpack(">H", c.recv(2))[0]

        try:
            up = self._tunnel(host, port)
        except Exception:
            c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return
        c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
        STATS["ok"] += 1
        try:
            if isinstance(up, WS):
                threading.Thread(target=sock_to_ws, args=(c, up), daemon=True).start()
                ws_to_sock(up, c)
            else:
                plain_pipe(c, up)
        finally:
            self._note_result(host, up)

    # ---------- HTTP ----------
    def handle_http(self, c, first):
        buf = first
        while b"\r\n\r\n" not in buf:
            d = c.recv(4096)
            if not d:
                return
            buf += d
        head, rest = buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        reqline = lines[0].split()
        if len(reqline) < 2:
            return
        method, uri = reqline[0].decode("latin1"), reqline[1].decode("latin1")

        if method.upper() == "CONNECT":
            hostport = uri
        else:
            if not uri.startswith("http://"):
                c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            rest_of = uri[len("http://"):]
            slash = rest_of.find("/")
            hostport = rest_of[:slash] if slash >= 0 else rest_of
            # 改写成 origin-form
            path = rest_of[slash:] if slash >= 0 else "/"
            lines[0] = ("%s %s %s" % (method, path, "HTTP/1.1")).encode()
            head = b"\r\n".join(lines)
            rest = head + b"\r\n\r\n" + rest

        host, _, p = hostport.rpartition(":")
        port = int(p) if p.isdigit() else (443 if method.upper() == "CONNECT" else 80)

        try:
            up = self._tunnel(host, port, rest if method.upper() != "CONNECT" else b"")
        except Exception:
            c.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        if method.upper() == "CONNECT":
            c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        STATS["ok"] += 1
        try:
            if isinstance(up, WS):
                threading.Thread(target=sock_to_ws, args=(c, up), daemon=True).start()
                ws_to_sock(up, c)
            else:
                plain_pipe(c, up)
        finally:
            self._note_result(host, up)

    def handle(self, c, addr):
        try:
            WS._nagle_off(c)
            c.settimeout(30)
            first = c.recv(1)
            if not first:
                return
            if first == b"\x05":
                self.handle_socks(c)
            else:
                self.handle_http(c, first + c.recv(8192))
        except Exception:
            pass
        finally:
            try: c.close()
            except Exception: pass

    def serve(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(128)
        log("wstun 本地代理已启动  %s:%d" % (self.host, self.port))
        log("边缘节点: %s" % self.endpoint)
        log("默认出口: %s（住宅代理名单 %d 条）" % (self.default_mode, len(self.residential)))
        if self.cn_direct:
            log("国内直连: 开启（域名规则 %d 条 + 国内 IP 段 %d 条）—— 国内站点走本机线路，"
                "其余全部走美国住宅" % (len(self.cn_domains), self.cn_nets_n))
        else:
            log("国内直连: 关闭")
        log("纯净度守护: %s" % ("strict——所有流量强制住宅，禁止任何机房出口降级"
                              if self.strict else "off（未启用 strict_residential）"))
        log("预热池: direct=%d up=%d，空闲 %ds 后停止预热" %
            (self.pool.sizes.get("direct", 0), self.pool.sizes.get("up", 0), self.pool.idle_stop))
        log("请把浏览器/系统代理设为 SOCKS5 127.0.0.1:%d（或 HTTP 同端口）" % self.port)
        threading.Thread(target=self.pool.maintain, daemon=True).start()
        while True:
            try:
                c, addr = s.accept()
                threading.Thread(target=self.handle, args=(c, addr), daemon=True).start()
            except Exception:
                pass


def main():
    if not os.path.exists(CFG_PATH):
        log("缺少配置文件 " + CFG_PATH)
        sys.exit(1)
    with open(CFG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if not cfg.get("endpoint"):
        log("wstun.json 里 endpoint 为空，请先部署边缘节点并填写地址")
        sys.exit(1)
    Server(cfg).serve()


if __name__ == "__main__":
    main()
