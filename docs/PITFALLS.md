# 踩坑记录

这里记的都是**真踩过的坑**，不是推测。每条都付出了调试代价，写下来是为了别人不用再付一遍。

---

## 一、协议层

### 1. 明文 CONNECT 直连住宅代理 = 白搭

最早的想法很自然：既然住宅代理不限目的地，那直接把系统代理指向它不就行了？

不行。住宅代理的客户端侧是**明文 HTTP 代理协议**，`CONNECT chatgpt.com:443` 这个请求行把目标 FQDN 完整暴露在路径上。中间盒基于 SNI / HTTP 特征做 RST 注入，连接在 TLS 握手阶段就被重置。

实测十个主流目标逐个发起 `CONNECT`，代理侧**全部返回 200**（说明它自己不挑目的地），但**六个在 TLS ClientHello 阶段被 reset**。

结论：问题的本质不是出口的信誉或带宽，而是**域名的暴露时序**。必须让 SNI 第一次出现在线路上的位置在境外。这也直接决定了配置里的 `fallback` **必须保持为空** —— 任何"明文直连住宅代理"的降级路径都是自欺欺人。

### 2. `*.workers.dev` 被整段屏蔽，改用 `*.pages.dev`

初始入口选了 Cloudflare Workers 的默认域名，结果整段不可达。换成 Pages 的 `*.pages.dev` 后正常。

这类"整段域名被屏蔽"和单点 IP 封锁不同，换 IP 没用，只能换**域名空间**。多准备几种部署形态（`server/` 下有四套）是有意义的。

### 3. WSS 通道的固定成本是 1.13 秒

拆开看：

- TCP 三次握手 → 1 RTT
- TLS 握手 → 1 RTT（TLS 1.2 是 2 RTT）
- HTTP/1.1 `101 Switching Protocols` 的 Upgrade 往返 → 1 RTT

合计约 1.13 秒。单个请求感知不到，但一个网页几十个跨域资源就是**逐次重复缴纳**。

**"网页慢"经常不是带宽问题，是 RTT 累积 × 连接数的乘积。** 先做归因，别猜。

### 4. `getaddrinfo` 的顺序阻塞会白等 21 秒

系统解析域名拿到多个候选地址后，默认**按顺序阻塞式尝试第一个**。如果第一个恰好丢包，就要吃满系统超时才轮到下一个 —— 观感就是"网络卡死"，实际是**在傻等**。

改成：已验证的好 IP 优先、每个候选 4 秒硬超时、失败立刻切下一个（Happy-Eyeballs 的简化实现），并把好 IP 集合**持久化落盘**，冷启动直接命中。

### 5. Nagle 与 Delayed ACK 的交互惩罚

默认 Nagle 算法会对小包做约 40ms 的攒批。对 TLS 握手这种一问一答的序列是纯亏损。置 `TCP_NODELAY`。

单看只有 40ms，但握手是 3 个 RTT，叠加起来就不可忽略了。

---

## 二、WebRTC 泄露（这块坑最多）

### 6. 泄露是真的，而且根因只有一个

检测报告给出了一个本机所在地的 IP。默认假设应该是"误报"，但**不能接受假设**，要做反证。

直连三个独立的 IP 回显端点，取到本机真实出口 —— 与报告里那个 IP **落在同一个 /24**。这不是噪声，是确凿的 host / srflx candidate 泄露。

根因：**WebRTC 的 ICE 候选走 UDP，而系统代理（WinINET / WinHTTP 层）只代理 TCP。** UDP 直接绕过代理栈从物理网卡出去，把 NAT 映射后的公网地址交给对端。

顺带解释了报告里另一条"出口国家不一致" —— **同一个根因，两个症状**，不是两个独立缺陷。找到根因就能一次修干净。

### 7. Edge 和 Chrome 的策略名不通用

封堵方案是下发 Chromium 的 `disable_non_proxied_udp`。陷阱在于**键名在 Edge 与 Chrome 的命名空间里不一样**：

- Edge → `WebRtcLocalhostIpHandling`
- Chrome → `WebRtcIPHandlingPolicy`

**键名差一个词，策略静默失效** —— 不报错、不打日志、不产生任何可观测信号。你只会以为"设了但没用"。类型也必须是 `REG_SZ`，写成 DWORD 同样静默失效。

### 8. `Software\Policies` 的 DACL 会把你自己挡在门外

该键被系统加固：

```
NT AUTHORITY\SYSTEM         Allow  FullControl
BUILTIN\Administrators      Allow  FullControl
<你的账户>                  Allow  ReadKey     ← 只有读权限
```

也就是说**普通完整性级别下连账户所有者自己都写不进去**，首次尝试直接 `WinError 5`。

只能做自提权入口：`ShellExecute runas` 触发 Consent UI。脚本内需要一个可靠的方式判断"当前是否已提权"，可用 `cacls %SYSTEMROOT%\system32\config\system` 反查 —— 这个路径普通权限读不了。

### 9. 受限令牌（restricted token）会让权限判断完全反向

最反直觉的一环：第一次判定"当前用户是否属于管理员组"，结论是**否**。如果就此采信，整个方案方向都会跑偏。

复核发现真正原因是：**判定进程本身处于受限令牌状态，管理员 SID 被过滤**，所以它看任何人都"不是管理员"。

改用 `Get-LocalGroupMember -SID S-1-5-32-544` 与 `Win32_GroupUser` CIM 双路交叉验证，确认账户确实在 Administrators 组。

**结论：在受限 / 沙箱环境下，`IsInRole(Administrator)` 是负可信信号，不能作为权限判定依据。**

### 10. 策略是 `Dynamic Policy Refresh: No`，只能靠重启浏览器生效

该策略不热加载。判断它是否生效，唯一可靠的方法是**时序比对**：

- 注册表键的 `LastWriteTime`
- vs 浏览器**本体**进程的创建时间（`GetProcessTimes` 取 CreationTime FILETIME）

用的是进程创建时间，**不是**任务管理器里的进程数量。

这里还埋着第二个坑：`msedgewebview2.exe` 是系统组件、长期驻留，创建时间可能在两天前。如果按进程名前缀 `msedge` 模糊统计，就会误判成"浏览器没重启"。必须精确区分浏览器本体与 WebView2 运行时。

---

## 三、架构与配置

### 11. 凭证在边缘，不在客户端

换住宅代理时才发现：`host / port / user / pass` 是作为常量编译进**边缘节点**的（现已改为环境变量注入）。只改本地 `wstun.json` 完全无效，出口不变。

所以完整链路是：**改边缘配置 → 重新部署边缘 → 重启隧道 → 出口自检**。少一步都不行。

### 12. fail-closed 的取舍

住宅路径不可达时，允许静默降级到边缘节点的机房出口，是个**看起来很合理、实际很危险**的设计。

一旦回落，流量会在你不知情的情况下被 ASN 分类器打上 `datacenter` / `proxy` 标签，造成**污染且不可回溯**。

所以 `strict_residential: true` 会物理切断一切 direct 通路（路由函数永远返回住宅路径，连底层连接函数也不允许建 direct 连接）。这是典型的 fail-closed：**代价是可见的失败，收益是不可见的一致性。**

### 13. 守护状态机的收敛窗口（关键细节）

如果简单地"探测失败就计一次失败"，那么采样间隔取小就会把**正常启动过程**误判成故障，白切一次代理。

正确做法：**只有"拉起 + 等满 45 秒收敛窗口后仍不可用"才递增失败计数。**

有了这个窗口，采样间隔就可以取到 6 秒 —— 只影响"发现"的延迟，不产生假阳性。断网最多 6 秒被救回。

另外两个必备件：
- **单实例文件锁**，避免重复拉起；
- **用户意图标记** —— 用户手动关掉的，守护不抢。防止守护与人工操作产生竞态。

---

## 四、Windows 工具链

| 坑 | 现状 |
|---|---|
| `wmic` | 已被微软移除，调用直接 `FileNotFoundError`。改用 `tasklist /FO CSV` 或 CIM |
| `sc.exe` | 存在于程序黑名单，查服务一律被拦。改读注册表 `HKLM\SYSTEM\CurrentControlSet\Services` |
| 从 Bash 调 PowerShell | 被安全策略拒绝（bypasses PowerShell security checks）。改用原生 PS 调用 |
| PowerShell stdout 不回传 | 某些环境下 stdout 静默丢失。改用"**写文件 → 读文件**"的中转模式 |
| 批处理中文乱码 | `.bat` 必须用 GBK / CP936 写入；`.vbs` 同理。UTF-8 会满屏乱码 |
| 沙箱对 `shutil.rmtree` 的钩子 | 对含大量子项的目录会报 `Some operations were aborted`。改用 `SHFileOperationW` + `FOF_ALLOWUNDO`，逐项送回收站，顺便获得可还原性 |

---

## 五、给后来者的一句话

这套东西的复杂度**不在协议实现**，而在**环境**：DNS 行为、代理栈的覆盖范围（TCP vs UDP）、浏览器的策略命名空间、Windows 的 ACL 与令牌模型、以及云平台免费层的计费口径。

协议代码不到一千行，剩下的全是跟这些打交道。
