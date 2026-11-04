```
   ███████╗ ██████╗ ██╗   ██╗██████╗  ██████╗███████╗
   ██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝
   ███████╗██║   ██║██║   ██║██████╔╝██║     █████╗
   ╚════██║██║   ██║██║   ██║██╔══██╗██║     ██╔══╝
   ███████║╚██████╔╝╚██████╔╝██║  ██║╚██████╗███████╗
   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝
```

# Source

**CDN 判定 + 真实 IP 溯源工具 · 用证据评分代替"猜 IP"**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-4.0-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)]()

---

大多数"CDN 绕过工具"给你一堆 IP，然后让你自己去猜哪个是真的。

**Source 不干这个。** 它给你一份带分数、带证据链、带可信度分级的候选清单——每个 IP 为什么可信、可信到什么程度、哪些证据是硬的、哪些已经过期，全部摊开给你看。

```
  [★命中]   92.0  203.0.xx.xx
          [+40] 来源: mnemonic, shodan-dns, otx
          [+20] 该 IP 上无其它无关域名（独占主机）
          [+25] TLS 证书 SAN 含目标域名 ★铁证
          [+30] InternetDB hostnames 含目标域名 ★★★
          [+20] favicon mmh3 与目标一致 ★
          [+15] 页面 title 与 CDN 侧一致: 某某科技官网
```

---

## 为什么需要它

做 CDN 溯源的人都遇到过这几个坑：

| 痛点 | 常规工具的答案 | Source 的答案 |
|---|---|---|
| 历史 IP 挖出十几个，不知道哪个还活着 | 全列出来，自己试 | **时间衰减**：30 天内满权，超一年直接标注"可能已废弃" |
| 挖到的 IP 是共享虚拟主机，一查几百个域名 | 无感知 | **共享主机降噪**：无关域名 >100 个直接扣 18 分 |
| 明明 IP 不对，工具说"验证通过" | 无感知 | **代理污染自检**：非 CDN 段的 IP 返回 cf-ray 头 → 判定代理劫持，结果作废 |
| 源站 IP 已经下线，白忙一场 | 无解 | **站群扩展**：反查同机域名，自动找没走 CDN 的活入口 |
| 扫出来端口全开，一访问全超时 | 无感知 | **端口二次验证**：TCP 通不算数，要拿到真实 HTTP 响应 |
| 每个 IP 要手工比对证书/favicon/title | 手工 | 全自动，结果并进评分 |

---

## 特点

### 一、证据权重评分，不是 IP 列表

8 个维度打分，分数可追溯、可复核：

| 维度 | 分值 | 判定依据 |
|---|---|---|
| 来源权重 | **+40** | 多个独立数据源交叉证实，去重累加 |
| 新鲜度 | **+30** | 最近解析 30 天内满权，90 天 +22，超一年归零 |
| 专属性 | **+20 / −18** | 该 IP 上无关域名 0 个 +20；>100 个 −18（共享主机）|
| 同机关联 | **+8** | 该 IP 上解析过目标域名的其它名称 |
| 端口响应 | **+10** | 443/80 返回 200/301/302/401/403 |
| **证书 SAN** | **+25** | TLS 证书里含目标域名 —— 铁证 |
| **favicon** | **+20** | 直取候选 IP 图标算 mmh3，与目标一致 |
| **InternetDB hostnames** | **+30** | Shodan InternetDB 记录的主机名含目标域名 —— 铁证 |
| title | **+15** | 页面标题与 CDN 侧一致 |
| 301 跳转 | **+10** | 跳转到目标域名 |

输出五级分级：`confirmed`（≥70 且有硬证据）/ `likely`（≥45）/ `possible`（≥25）/ `weak` / `polluted`。

**只有 confirmed 才叫"拿到了"，其余都明说是推测。**

### 二、13 个数据源，免费源占多数

| 类型 | 数据源 | 需要 Key |
|---|---|---|
| 被动 DNS | **mnemonic**（带 first/last seen）、otx、rapiddns、hackertarget、bufferover、threatminer、subdomain.center | ❌ |
| 证书透明 | **crt.sh**、certspotter | ❌ |
| 指纹库 | **Shodan InternetDB**（端口 + hostnames + CVE） | ❌ |
| 测绘引擎 | **FOFA**、Shodan、Censys、ZoomEye、Quake、Hunter | ✅ |

**免 key 就能跑出完整结果**。测绘引擎按需补，额度不足自动降级跳过，不会卡住流程。

### 三、站群扩展：源站死了照样有突破点

源站 IP 下线是常态。Source 会反查候选 IP 上解析过的**全部域名**，自动二次解析，筛出仍然直连、没走 CDN 的：

```
★ 站群未走 CDN 的活入口 (34):
    test.xyz       → ['160.251.xx.xx']     ← 80 端口 302 跳回主站，Apache 裸机
    csm.com     → ['156.254.xx.xx']
    gzi.cn       → ['129.148.xx.xx', '202.95.xx.xx']
```

同一台服务器上的兄弟站往往还裸奔着——那些就是绕过点，比跟 Cloudflare 硬碰硬有效得多。

### 四、环境自检：不给你假阳性

工具在**被 TUN 代理劫持的网络环境**下会给出完全错误的结论——你指定 IP 直连，代理按域名把流量转发到 CDN，于是每个 IP 都"验证通过"。

Source 会自动识别：

```
[!] 检测到本机代理劫持：非 CDN IP 返回了 Cloudflare 响应头。
[!] 证书/favicon/title 类硬证据不可信，请关闭 TUN 代理后重跑，或改用 VPS。
[!] 评分中的『来源』『新鲜度』『专属性』三项仍然有效。
```

同理还有 **DNS 污染检测**（双 DoH 交叉解析）、**端口扫描二次验证**（防防火墙 SYN-ACK 欺骗）。

### 五、零依赖，Windows 原生

纯 Python 标准库，不需要 pip install、不需要 nmap/dig/openssl、不需要编译。

下载即用：

```
Source -d example.com --deep
```

---

## 快速开始

### 环境要求

- Python 3.8+
- 无第三方依赖

### 获取

```bash
git clone https://github.com/<your-name>/Source.git
cd Source
```

### 运行

```bash
# 全流程溯源
python recon/cdn_hunter.py -d example.com --deep

# 查看中文帮助
python recon/cdn_hunter.py -h

# Windows 双击启动
recon\hunt.bat
```

---

## 用法

```
Source -d <目标域名> [选项]
Source -f <域名列表.txt> [选项]
Source -i <IP1,IP2> -t <目标域名>
Source --sweep <网段>
```

| 参数 | 说明 |
|---|---|
| `-d, --domain` | 目标域名，可重复写多个 |
| `-f, --file` | 域名列表，每行一个 |
| `-i, --ips` | 已有候选 IP，逗号分隔，配合 `-t` 直接评分 |
| `-t, --target` | 配合 `-i`：这些 IP 对应的目标域名 |
| `--fast` | 快速：只跑最快的数据源，适合先探路 |
| `--deep` | 深度：全源 + 180 条子域爆破 + 站群扩展 + 外部验证 + 端口扫描 |
| `--scan-ports` | 对候选源站扫端口，如 `80,443,22,3306` |
| `--no-scan` | 关闭端口扫描 |
| `--sweep` | C 段 HTTP 存活探测 |
| `--external-check` | check-host 全球节点验证端口（不受本机代理影响）|
| `--threads` | 并发线程数，默认 30 |
| `-c, --config` | 配置文件路径 |
| `-o, --outdir` | 输出目录 |

### 三种典型用法

**1. 从零开始溯源**

```bash
Source -d target.com --deep
```

跑完给三样东西：可确认源站、高度疑似列表、没走 CDN 的站群入口。

**2. 已有 IP 列表，只要可信度**

```bash
Source -i 203.0.xx.xx,198.51.100.7 -t target.com
```

从日志、邮件头、证书逆查里拿到一批 IP，一次评分排好序，省掉手工比对。

**3. 只做 C 段探测**

```bash
Source --sweep 203.0.113.0/24
```

只认有真实 HTTP 响应的主机，不认 TCP connect 假阳性。

---

## 工作流程

```
       ┌──────────────┐
       │  目标域名     │
       └──────┬───────┘
              ▼
   ┌─────────────────────┐
   │ 1. CDN 判定 + 污染检测 │  DNS 双 DoH 交叉 / 25 厂商 CIDR
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ 2. 多源采集           │  9 个免 key 源 + 6 个测绘引擎（真并发）
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ 3. 子域爆破 + 解析     │  180 条字典，含边缘资产命名
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ 4. CDN 段过滤          │  25 厂商 CIDR + org 兜底
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ 5. 反查 + 指纹         │  同机域名 / 证书 / favicon / title / InternetDB
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ 6. 证据评分 + 分级     │  8 维度打分，输出证据链
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ 7. 站群扩展           │  同机域名二次解析，找没走 CDN 的
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ 8. 端口扫描 + 二次验证 │  TCP 通不算数，要真实响应
   └──────────┬──────────┘
              ▼
       ┌──────────────┐
       │  分级报告      │
       └──────────────┘
```

标准模式约 80 秒，深度模式约 2-3 分钟。

---

## 输出

```
out/<域名>/
├── report.md        人读报告（候选排行 + 证据明细 + 站群表）
├── report.json      全量结构化数据（每个候选的完整证据链）
├── origin.txt       confirmed / likely 分级清单
├── candidates.txt   候选 IP 按分数排序，可直接 nmap -iL
└── favicon_hash.txt icon_hash，可直接喂 FOFA / Shodan
```

`candidates.txt` 可以直接接后续扫描：

```bash
nmap -Pn -p 22,80,443,3389,8080 -iL out/target.com/candidates.txt --open
```

---

## 配置 API Key

免费源开箱即用。要接入测绘引擎，在 `recon/config.json` 里填：

```json
{
  "fofa":    { "key": "your-fofa-key", "enabled": true },
  "shodan":  { "key": "your-shodan-key", "enabled": true },
  "censys":  { "token": "censys_xxx", "api_id": "", "api_secret": "", "enabled": true },
  "zoomeye": { "key": "", "enabled": false },
  "quake":   { "key": "", "enabled": false },
  "hunter":  { "key": "", "enabled": false }
}
```

也支持从环境变量读（优先级更高）：

```bash
export FOFA_KEY=xxx
export SHODAN_KEY=xxx
export CENSYS_TOKEN=censys_xxx
```

**额度不足不会崩**，脚本会分类标记并跳过该引擎：

```
[FAIL] fofa[icon_hash="-1234"]   0 条 [quota] F点余额不足
       FOFA 额度不足，跳过剩余 FOFA 查询
[FAIL] censys[0]                 0 条 [plan] requires an organization ID
```

标签含义：`[quota]` 额度用尽 / `[plan]` 计划不够 / `[deprecated]` 接口下线。

---

## 常见问题

**Q：为什么验证结果全是 polluted？**

你的机器在跑 TUN 模式代理（clash / sing-box / v2ray 等）。代理会按域名分流，你指定 IP 直连它也会把流量送到 CDN，于是每个 IP 都"验证通过"。

解决：关闭 TUN、或给目标 IP 配 DIRECT 规则、或把脚本拷到 VPS 上跑。评分里的来源/新鲜度/专属性三项仍然有效。

**Q：候选 IP 全部分数很低？**

正常。说明目标确实把源站藏好了——大概率用了 Cloudflare Tunnel，源站没有公网入口。这时候看站群扩展那一栏，找同机兄弟站。

**Q：历史 IP 显示"超一年可能已废弃"？**

源站迁移了。这类 IP 本身没用了，但它的**同机域名**往往还在，站群扩展会挖出来。

**Q：为什么扫出来的端口全开但访问超时？**

部分机房防火墙对所有端口回 SYN-ACK。Source 会做二次验证，没真实响应的会标记 `疑防火墙欺骗`。

**Q：中文乱码 / bat 报错？**

bat 必须保持纯 ASCII（不能写 `chcp 65001`，会破坏 cmd 行解析）。编码由 Python 内部处理，无需手动设置。

---

## 免责声明

本工具用于**授权的安全测试、攻击面管理、资产清点与教学研究**。

使用者应确保对目标拥有明确授权。在未授权情况下使用本工具攻击他人系统可能触犯法律，作者不对任何滥用行为承担责任。

---

## License

MIT License —— 详见 [LICENSE](LICENSE)

---

## 致谢

数据源：mnemonic passiveDNS、crt.sh、Cert Spotter、AlienVault OTX、RapidDNS、HackerTarget、BufferOver、ThreatMiner、Subdomain Center、Shodan InternetDB、check-host.net

---

**作者**：Soren
**版本**：v4.0
