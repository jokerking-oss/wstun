# wstun · 住宅 IP 出口隧道

> **把你的出口 IP 变成一个真正的美国家庭宽带用户。**
> 基于 Cloudflare 免费边缘 + 你自己的住宅代理，纯 Python 实现，零第三方依赖。

---

## 这是什么

`wstun` 是一条自建的 **WSS 隧道**：本地起一个 SOCKS5/HTTP 代理，流量经 Cloudflare 的边缘节点加密转发，最终从你自己的**住宅代理**出口出网。

它不是传统 VPN，也不是加密代理链。它解决的是一个非常具体的问题：

**你手里有一枚干净的住宅 IP，但"你 → 它"这一段是明文的，路径上的中间盒读到域名就把连接掐了。**

所以真正要做的事只有一件 —— **把"我要访问哪个域名"这句话，挪到境外再说**。

```
你的程序 → 127.0.0.1:10808 (本地代理)
              │  国内域名 / 国内 IP？ → 本机直连（不进隧道）
              ↓ 其余一律 TLS 封装
        Cloudflare 边缘节点（境外）
              ↓  CONNECT
        你的住宅代理（真实家庭宽带 IP）
              ↓
            目标站点
```

---

## 为什么值得一看

### 1. 出口是真·住宅，不是机房

落在 ASN 家庭宽带段。机房 IP 会被主流服务按 ASN 分类器打上 `datacenter` / `proxy` 标签，那是各类风控与限流的直接依据；住宅出口没有这个问题。

### 2. Fail-closed：宁可报错，绝不静默漏

这是整套设计里最反直觉、也最重要的一条。

配置项 `strict_residential: true` 会**物理切断**一切降级通路 —— 住宅段不可用时**直接抛错**，绝不偷偷把流量回落到边缘节点的机房出口。

因为"慢一点"是小事，"在你不知情的时候漏一次机房 IP"是不可逆的污染。**可用性让位于一致性**，代价是可见的失败。

### 3. 智能分流：六成以上的连接根本不进隧道

内置 `china_ip.txt`（7400+ 条国内 CIDR）+ 域名规则表。命中的目标走本机线路：**不占连接池、不共享隧道窗口、不消耗住宅侧会话数**。

优先级：`residential 强制名单` > `国内直连` > `默认住宅`。

### 4. 性能是榨出来的，不是买来的

每建一条 WSS 通道的固定成本是 **1.13 秒**（TCP 1 RTT + TLS 1 RTT + `101 Switching Protocols` 的 Upgrade 往返）。一个网页几十个跨域资源，就是**逐次重复缴纳这笔过路费**。

四刀下去：

| 手段 | 效果 |
|---|---|
| **连接池预热** —— 空闲窗口期提前完成握手，请求到达直接复用 | 建通道 **1.13s → 0.01s** |
| **好 IP 优先 + 落盘** —— 已验证地址优先，每个候选 4s 硬超时，失败立即切换（Happy-Eyeballs 式） | 消除首个候选丢包导致的 **21 秒纯等待** |
| **`TCP_NODELAY`** —— 关闭 Nagle 与小包攒批 | 每轮省 **~40ms** |
| **国内流量本地卸载** | **66.9%** 的连接不进隧道 |

实测（同一台机器、同一时段）：

| 场景 | 优化前 | 优化后 |
|---|---|---|
| Google 首页 TTFB 端到端 | 3.21 s | **0.81 s** |
| 单流吞吐 | 252 KB/s | **1085 KB/s** |
| 16 资源 / 8 域名并发 | 15/16 成功 | **16/16，共 2.1 s** |
| x.com 首屏 | 打不开 | **3 s** |

### 5. 看门狗：进程死了自己爬起来

`guard.py` 是一个独立的状态机守护进程：

- 定周期采样 `127.0.0.1:10808` 的 listening 状态；
- 失活 → 拉起并进入 **45 秒收敛窗口**；
- **只有"拉起且等满收敛窗口仍不可用"才递增失败计数** —— 这是关键细节，避免把正常启动过程误判成故障，因此采样间隔可以取到 6 秒而不产生假阳性；
- 连续 3 次失败 → **failover**：把系统代理回退到你原来的配置，先保证连通性，再以低频持续重试；
- 隧道恢复 → 自动切回住宅路径。

附带单实例文件锁，以及一个"**用户意图标记**"，防止守护与人工操作产生竞态（你手动关掉的，它不抢）。

### 6. 面向免费额度做了设计

Cloudflare Workers / Pages 免费层是 **100,000 请求/日**，UTC 零点重置。

关键计费口径：**WebSocket Upgrade 只计 1 次请求，升级后的通道内数据不再计费。**

实测重度使用（每分约 8.5 条出网连接）6 小时 ≈ 3000 次 ≈ **额度的 3%**。

> ✅ **可以看视频、下大文件。** 常见误解是"Cloudflare 免费层禁止代理视频/大文件"——那条规则（旧 Self-Serve
> 协议 §2.8）**已于 2023 年 5 月被 Cloudflare 自己废除**，内容限制现在只属于 **CDN 服务**，而 Workers / Pages
> Functions 属于 **Developer Platform**，不在其内。官方计费文档同时写明：**不收取数据传输（egress）或吞吐（带宽）费用**。
> 真实天花板是物理带宽：客户端到边缘的 WSS 段实测 ≈2.5–2.9 MB/s（≈20–23 Mbps），1080p 流畅、4K 吃紧。

---

## 快速开始

### 前置条件

- Python 3.8+（仅用标准库，**无第三方依赖**）
- 一个 Cloudflare 账号（免费）
- 一个住宅代理（HTTP CONNECT 或 SOCKS5）—— 或者，只想要条隧道也可以不填

### 1. 部署边缘节点

```bash
# Cloudflare Pages 方式（推荐）
cp server/cloudflare-pages/_worker.js  <你的项目目录>/_worker.js
npx wrangler pages deploy <你的项目目录>
```

然后在 Cloudflare 控制台给项目配置环境变量：

| 变量 | 说明 |
|---|---|
| `AUTH_TOKEN` | 客户端口令，长随机串 |
| `UPSTREAM_HOST` | 住宅代理地址 |
| `UPSTREAM_PORT` | 住宅代理端口 |
| `UPSTREAM_USER` | 账号 |
| `UPSTREAM_PASS` | 密码（建议用 Secret，别用明文变量） |

> **凭证是编译进边缘节点的，不在客户端。** 换代理时改这里并重新部署，改本地配置是没用的。
>
> 其他部署形态（Cloudflare Workers / Deno Deploy / 自己的 VPS）见 `server/` 下各目录的注释。

### 2. 配置客户端

```bash
cp client/wstun.example.json client/wstun.json
# 编辑 endpoint 与 token，与边缘保持一致
```

### 3. 启动

```bash
on.bat        # 起隧道 + 设置系统代理 + 出口自检 + 拉起守护
check-ip.bat  # 随时查看当前出口
off.bat       # 停止守护与隧道，系统代理还原
```

也可以不用系统代理，直接把 `127.0.0.1:10808` 填进任意支持 SOCKS5 的程序。

---

## 项目结构

```
client/
  wstun.py              # 客户端：本地代理 + 连接池 + 分流 + happy-eyeballs
  wstun.example.json     # 配置模板
  china_ip.txt           # 7400+ 条国内 CIDR，用于直连判定
guard.py                 # 兜底守护（抗单点故障 + failover）
server/
  cloudflare-pages/      # Cloudflare Pages 边缘（推荐）
  cloudflare-workers/    # Cloudflare Workers 形态
  deno-deploy/           # Deno Deploy 形态
  vps/                   # 自建 VPS 形态（含 Dockerfile）
tools/
  proxy.py               # 系统代理开关（带备份/还原）
  exit_check.py          # 出口 IP 与纯净度自检
  purity_check.py        # 多源交叉验证出口是否为住宅
  kill_tunnel.py         # 干净地停掉隧道进程
  webrtc_policy.py       # 浏览器 WebRTC 防泄露策略（Windows）
on.bat / off.bat / check-ip.bat
docs/
  PITFALLS.md            # 踩坑记录：13 个真实的坑，含根因与解法
```

---

## 踩过的坑

真正难的不是协议，是环境 —— DNS 行为、代理栈的覆盖范围（TCP vs UDP）、Chromium 的策略命名空间、Windows 的 ACL 与受限令牌模型、云平台免费层的计费口径。

`docs/PITFALLS.md` 里记了 13 条实证结论，例如：

- Edge 与 Chrome 的 WebRTC 策略**键名不通用**，写错一个词就**静默失效**（不报错、不打日志）；
- WebRTC 泄露的真根因是 **UDP 绕过 TCP-only 的系统代理**，它同时解释了"出口国家不一致"那条报告 —— 一因两果；
- `Software\Policies` 的 DACL 让**账户所有者自己也写不进去**；
- 受限令牌会让 `IsInRole(Administrator)` 给出**完全反向**的结论；
- 守护的失败计数必须加**收敛窗口**，否则会把正常启动误判为故障。

---

## 已知限制

- **只代理 TCP。** SOCKS5 的 UDP 转发未实现，QUIC / HTTP3 需要在浏览器里关掉，或使用 HTTP 代理形态。
- **WebRTC 会绕过系统代理。** ICE 候选走 UDP，而系统代理只覆盖 TCP —— UDP 会直接从物理网卡出去，把真实 IP 交给对端。Windows 下用 `tools/webrtc_policy.py` 下发 `disable_non_proxied_udp` 策略封堵。
- **免费额度与条款**：100,000 请求/天；带宽不计费、无 egress 费用。上文"可看视频 / 下大文件"一节已澄清最常见的误解。
- **依赖边缘域名可达。** 若你的网络屏蔽了所选的 CF 域名段，需要更换部署形态或节点。

---

## License

MIT

---

<details>
<summary><b>English</b></summary>

**wstun** — a self-hosted WSS tunnel that egresses through *your own residential proxy*.

The core insight: a clean residential IP is useless if the hop from you to it is in plaintext — any middlebox that can read the target FQDN in `CONNECT host:443` will kill the connection. So the only real fix is to move **"where am I going"** outside the network you're in.

**Design highlights**

- **Residential egress** on a real consumer ASN, not a datacenter range.
- **Fail-closed by design** (`strict_residential`): if the residential path is down, it errors out instead of silently falling back to the edge's datacenter IP. Availability yields to consistency.
- **Smart split routing**: 7,400+ CN CIDR entries + domain rules are pinned to the local route — **66.9%** of connections never touch the tunnel.
- **Performance**: connection-pool pre-warming (**1.13s → 0.01s** per channel), happy-eyeballs-style address racing with persisted good-IPs, `TCP_NODELAY`. Measured: Google homepage **3.21s → 0.81s**, single-stream throughput **252 → 1085 KB/s**.
- **Watchdog** (`guard.py`): a failure-counting state machine with a 45s convergence window, escalating to a proxy failover that keeps you online, then auto-recovering.
- **Free-tier aware**: WebSocket Upgrade counts as exactly 1 request; post-upgrade traffic is not billed. Heavy use ≈ 3% of the daily quota.

Pure Python standard library. No third-party dependencies. MIT licensed.

</details>
