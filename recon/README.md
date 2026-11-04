```
   ███████╗ ██████╗ ██╗   ██╗██████╗  ██████╗███████╗
   ██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝
   ███████╗██║   ██║██║   ██║██████╔╝██║     █████╗
   ╚════██║██║   ██║██║   ██║██╔══██╗██║     ██╔══╝
   ███████║╚██████╔╝╚██████╔╝██║  ██║╚██████╗███████╗
   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝
```

# Source v4.0 —— CDN 判定 + 真实 IP 溯源

纯 Python 标准库，Windows 原生可跑。核心不是"多找几个 IP"，而是**把找出来的 IP 排出可信度**。

## 文件

```
recon/
├── cdn_hunter.py     主程序（编排 + 评分 + 端口扫描 + C段探测 + 输出）
├── engines.py        数据源层（13 个源 + 原始 socket 指纹探测）
├── cdndb.py          CDN 段库（25 厂商 CIDR + org 关键词兜底）
├── config.json       API key 与选项
├── hunt.bat          双击启动器
└── out/<域名>/       结果
```

## 用法

```
Source -d <目标域名> [选项]
Source -f <域名列表.txt> [选项]
Source -i <IP1,IP2> -t <目标域名>
Source --sweep <网段>
```

完整中文帮助：`python recon\cdn_hunter.py -h` 或双击 `recon\hunt.bat`

| 参数 | 说明 |
|---|---|
| `-d, --domain` | 目标域名，可重复写多个 |
| `-f, --file` | 域名列表，每行一个 |
| `-i, --ips` | 已有候选 IP，逗号分隔，配合 `-t` 直接评分 |
| `-t, --target` | 配合 `-i`：这些 IP 对应的目标域名 |
| `--fast` | 快速：只跑最快的数据源 |
| `--deep` | 深度：全源 + 180 条子域爆破 + 站群扩展 + 外部验证 + 端口扫描 |
| `--scan-ports` | 对候选源站扫端口，如 `80,443,22,3306` |
| `--no-scan` | 关闭端口扫描 |
| `--sweep` | C 段 HTTP 存活探测，如 `203.0.113.0/24` |
| `--external-check` | check-host 全球节点验证端口（不受本机代理影响）|
| `--threads` | 并发线程数，默认 30 |
| `-c, --config` | 配置文件路径 |
| `-o, --outdir` | 输出目录 |

示例：

```powershell
Source -d example.com --deep                    # 全流程
Source -i 1.2.3.4,5.6.7.8 -t example.com        # 已有 IP 评分
Source -d example.com --scan-ports 80,443,22    # 顺带扫端口
Source --sweep 203.0.113.0/24                   # 只做 C 段探测
Source -f targets.txt --fast                    # 批量探路
```

## 准确率的八层设计

### 1. 证据权重评分

| 维度 | 分值 | 说明 |
|---|---|---|
| 来源权重 | +40 | mnemonic 12 / 测绘引擎 10 / otx 8 / resolve 7，去重累加 |
| 新鲜度 | +30 | 30 天内 +30，90 天内 +22，180 天内 +13，一年内 +6，超一年 0 |
| 专属性 | +20 | 无关域名 0 个 +20，1-5 个 +12，6-20 个 +5 |
| 同机关联 | +8 | 该 IP 上解析过目标域名的其它名称 |
| 端口响应 | +10 | 443/80 返回 200/301/302/401/403 |
| **证书 SAN** | **+25** | TLS 证书里含目标域名 —— 铁证 |
| **favicon** | **+20** | 直取候选 IP 图标算 mmh3，与目标一致 |
| **InternetDB hostnames** | **+30** | Shodan InternetDB 记录的主机名含目标域名 —— 铁证 |
| **title** | **+15** | 页面标题与 CDN 侧一致 |
| 301 跳转 | +10 | 跳转到目标域名 |
| InternetDB 端口 | +8 | 记录到 80/443 开放 |

分级：`confirmed`（≥70 且有硬证据）/ `likely`（≥45）/ `possible`（≥25）/ `weak` / `polluted`

### 2. 共享主机降噪

反查候选 IP 上解析过的全部域名：无关域名 >100 直接 **-18**，判定为共享虚拟主机。
实测 `156.241.132.56` 有 25 个无关域名被压到 12 分，`156.241.132.248` 只有 3 个保持 32 分。

### 3. 时间衰减

`last_seen` 越近权重越高，超一年的历史 IP 会明确标注"可能已废弃"，不假装是活源站。

### 4. 站群扩展

从候选 IP 反查出的同机域名自动二次解析，筛出仍然直连、没走 CDN 的——那些就是绕过点。
实测 yxymk.com 挖出 34 个，其中 `yxym.xyz` 直接 302 跳回主站且走 Apache 裸机。

### 5. 代理污染自检

**非 CDN 段的 IP 却返回 `cf-ray` / `Server: cloudflare`** → 本地代理按域名分流的铁证，
该结果标 `polluted`，硬证据作废并告警，不会给假阳性。

### 6. DNS 污染检测

双 DoH（Google + Cloudflare）交叉解析，不一致直接告警。

### 7. 端口扫描带二次验证

TCP connect 通不代表真开放——部分机房防火墙对所有端口回 SYN-ACK。
所以扫出的端口会再发真实 HTTP 请求确认，无响应的标记"疑防火墙欺骗"。

### 8. 引擎真并发

`as_completed` 调度，单源超时不拖累全局。标准模式约 2 分钟。

## 输出

```
out/<域名>/
├── report.md        人读报告（候选排行 + 证据明细 + 站群表）
├── report.json      全量结构化数据（含每个候选完整证据链）
├── origin.txt       confirmed / likely 分级清单
├── candidates.txt   候选 IP 按分数排序，可直接 nmap -iL
└── favicon_hash.txt
```

`--sweep` 结果单独存 `out/sweep_<网段>.json`。

## API Key

已写入 `C:\Users\Administrator\.dsh\.env` 与 `recon\config.json`：

| 引擎 | 状态 |
|---|---|
| **Shodan InternetDB** | **免 key 完全可用** —— 端口/hostnames/CVE，脚本自动启用 |
| mnemonic / crt.sh / certspotter / otx / rapiddns / hackertarget | 免 key 可用 |
| FOFA | key 有效，账号 `F点余额不足`，需充值或升级 VIP |
| Shodan | OSS 免费账号，查询类 API 全关 |
| Censys | token 有效但免费层无 API 权限（v2 已下线 / v3 需 Organization），标 `[plan]` 跳过 |
| ZoomEye / Quake / Hunter | 留空，补 key 后自动启用 |

Censys 两种认证都已支持，升级后无需改代码：

```json
"censys": {
  "token": "censys_xxx",
  "api_id": "", "api_secret": "",
  "enabled": true
}
```

错误分类：`[plan]` 计划不够 / `[quota]` 额度用尽 / `[deprecated]` 接口下线，命中后跳过该引擎，不影响其它源。

## 本机环境注意

这台机器跑着 clash / sing-box / xray，TUN 模式接管全部出站。
**任何"目标 IP + Host/SNI = 目标域名"的请求都会被代理按域名规则转发到 CDN**，
证书/favicon/title 类硬验证默认失效——脚本自动检测并标 `polluted`。

要拿真实硬证据，三选一：

1. 关闭 TUN，或给目标 IP 配 DIRECT 规则后重跑
2. 在 `config.json` 的 `proxy.http` 填代理端口
3. 把脚本拷到 VPS 上跑（最干净）

`--external-check` 的 check-host.net 验证不受本机代理影响。
