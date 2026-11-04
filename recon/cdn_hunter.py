#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cdn_hunter.py v3.0  ——  CDN 判定 + 真实 IP 溯源（准确率优先版）

核心变化（相对 v2）：
  1. 【证据权重评分】不再输出一堆平铺 IP，而是给每个候选打分 + 列证据链，
     按 score 排序，分 confirmed / likely / possible / weak / polluted 五级
  2. 【共享主机降噪】反查候选 IP 上解析过的全部域名：
     无关域名 >100 判定为共享虚拟主机，大幅降权（这类 IP 占历史误报的八成）
  3. 【硬验证】直连候选 IP 取 TLS 证书，证书 SAN 含目标域名 = 铁证 +25；
     从候选 IP 直取 favicon 算 mmh3 比对 +20；title 一致 +15；301 跳转 +10
  4. 【时间衰减】last_seen 越近权重越高，30 天内满权，一年以上归零
  5. 【污染自检】非 CDN IP 返回 cf-ray 即判定本机代理劫持，硬证据整体作废
  6. 【DNS 污染检测】双 DoH 交叉解析，结果不一致直接告警
  7. 【引擎真并发】as_completed，单源超时不拖累全局，总耗时压到 20-40 秒

用法：
    python cdn_hunter.py -d example.com            # 标准
    python cdn_hunter.py -d example.com --fat      # 见 --fast
    python cdn_hunter.py -d example.com --deep     # 全源 + 子域爆破 + 外部验证
    python cdn_hunter.py -d example.com --fast     # 只跑最快的源
    python cdn_hunter.py -i 1.2.3.4,5.6.7.8 -t example.com
    python cdn_hunter.py -f targets.txt --deep
"""
import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cdndb
import engines as E

VERSION = "4.0"

LOGO = r"""
   ███████╗ ██████╗ ██╗   ██╗██████╗  ██████╗███████╗
   ██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝
   ███████╗██║   ██║██║   ██║██████╔╝██║     █████╗
   ╚════██║██║   ██║██║   ██║██╔══██╗██║     ██╔══╝
   ███████║╚██████╔╝╚██████╔╝██║  ██║╚██████╗███████╗
   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝
"""

BANNER_SUB = "  CDN 判定 · 真实IP溯源 · 证据评分      v{V}  作者:Soren"


def _init_console():
    """Windows 控制台编码修复

    bat 里不能写 chcp —— cmd 会先按 GBK 算好行偏移，切到 65001 后同一行
    重新解码就错位，导致 setlocal / cd 被吃掉。改由 Python 自己切并重配流。
    """
    if os.name == "nt":
        try:
            os.system("chcp 65001 >nul 2>&1")
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def banner(stream=None):
    """打印程序 logo 与版本信息"""
    import sys as _sys
    out = stream or _sys.stdout
    print(LOGO, file=out)
    print(BANNER_SUB.format(V=VERSION), file=out)
    print("  " + "─" * 62, file=out)
    print("", file=out)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# ---------------------------------------------------------------- 子域字典
SUBDOMAIN_WORDS = """
www m wap h5 web web1 web2 web3 web-auto webapp app apps mobile api apis api1 api2
open gw gateway sso auth login passport account user users member vip pay payment
cashier order orders shop mall card game games cdn static img image images pic asset
assets file files upload uploads download dl res source sources js css media video
admin manage manager console panel dashboard system sys oa erp crm hr mail email
webmail smtp pop imap mx ns1 ns2 dns dns1 dns2 vpn ssl fe feproxy proxy nginx
haproxy lb cache redis mysql db database mongo es kibana grafana
git gitlab gitea svn jenkins ci cd build repo registry docker k8s kube harbor
test testing test1 test2 dev develop development staging stage uat pre preprod
beta demo sandbox lab temp tmp old new backup bak bak1 data dataservice service
services server server1 node node1 host monitor zabbix nagios status health ping
log logs logger trace apm sentry store membercenter point points
bbs forum blog news help support kf cs chat im tg telegram
direct origin real realserver src backend back upstream
idc vps cloud host1 host2 colo dedi nat kvm
usdt wallet finance funds trade market
""".split()

# ---------------------------------------------------------------- 来源权重
SOURCE_WEIGHT = {
    "mnemonic": 12, "mnemonic-rev": 6,
    "shodan-dns": 9, "otx": 8,
    "fofa": 10, "censys": 10, "shodan": 9, "zoomeye": 8, "quake": 8, "hunter": 8,
    "hackertarget": 6, "rapiddns": 5, "bufferover": 5,
    "bruteforce": 7, "resolve": 7, "dns_now": 8,
}
MAX_SOURCE_SCORE = 40

# 判定阈值
TH_CONFIRMED = 70
TH_LIKELY = 45
TH_POSSIBLE = 25

DEFAULT_CONFIG = {
    "fofa": {"key": "", "enabled": True, "size": 100},
    "shodan": {"key": "", "enabled": True},
    "censys": {"api_id": "", "api_secret": "", "enabled": False},
    "zoomeye": {"key": "", "enabled": False},
    "quake": {"key": "", "enabled": False},
    "hunter": {"key": "", "enabled": False},
    "proxy": {"socks5": "", "http": ""},
    "options": {"threads": 30, "timeout": 10, "subdomain_bruteforce": True,
                "verify_origin": True, "external_port_check": False,
                "max_candidates": 200, "reverse_limit": 30},
}

ENV_MAP = {
    ("fofa", "key"): "FOFA_KEY",
    ("shodan", "key"): "SHODAN_KEY",
    ("censys", "token"): "CENSYS_TOKEN",
    ("censys", "api_id"): "CENSYS_API_ID",
    ("censys", "api_secret"): "CENSYS_API_SECRET",
    ("zoomeye", "key"): "ZOOMEYE_KEY",
    ("quake", "key"): "QUAKE_KEY",
    ("hunter", "key"): "HUNTER_KEY",
}


def _read_env_file():
    out = {}
    home = os.path.expanduser("~")
    for p in (os.path.join(home, ".dsh", ".env"), os.path.join(home, ".dsh", "redteam", ".env")):
        if os.path.exists(p):
            try:
                for line in open(p, encoding="utf-8", errors="ignore"):
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
            except Exception:
                pass
    return out


def load_config(path=None):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg_path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if os.path.exists(cfg_path):
        try:
            user = json.load(open(cfg_path, encoding="utf-8"))
            for k, v in user.items():
                if isinstance(v, dict) and k in cfg:
                    cfg[k].update(v)
                elif k in cfg:
                    cfg[k] = v
        except Exception as e:
            print(f"[!] config.json 解析失败: {e}")
    envfile = _read_env_file()
    for (sec, field), envname in ENV_MAP.items():
        val = os.environ.get(envname) or envfile.get(envname) or cfg.get(sec, {}).get(field)
        if val:
            cfg[sec][field] = val
            cfg[sec]["enabled"] = True
    return cfg


# ---------------------------------------------------------------- 基础 HTTP
def _ssl_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def http_get(url, timeout=12, raw=False, headers=None):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            data = r.read()
            return data if raw else data.decode("utf-8", "replace")
    except Exception:
        return None


def resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        return []


def get_baseline(domain):
    """取 CDN 侧基准响应，作为候选比对锚点"""
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{domain}/", headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15, context=_ssl_ctx()) as r:
                body = r.read(120000).decode("utf-8", "replace")
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                return {"scheme": scheme, "status": r.status, "len": len(body),
                        "title": (m.group(1).strip()[:90] if m else ""),
                        "server": r.headers.get("Server", "")}
        except Exception:
            continue
    return {}


def favicon_of(domain):
    """取 favicon mmh3，带重试（首次常因 TLS 慢而失败）"""
    for attempt in range(3):
        for scheme in ("https", "http"):
            for path in ("/favicon.ico", "/favicon.png"):
                data = http_get(f"{scheme}://{domain}{path}", timeout=10, raw=True)
                if data and len(data) > 16 and not data.lstrip()[:1] == b"<":
                    h = E.favicon_hash_bytes(data)
                    if h is not None:
                        return h
        time.sleep(0.6)
    return None


# ---------------------------------------------------------------- 日期
def _days_ago(datestr):
    if not datestr:
        return None
    s = str(datestr)[:10]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            d = datetime.strptime(s, fmt)
            return (now - d).days
        except Exception:
            continue
    return None


# ---------------------------------------------------------------- 评分
def score_candidate(ip, info, domain, baseline, target_favicon, reverse=None, fp=None, idb=None):
    """给候选 IP 打分并给出证据链 + 惩罚项"""
    score = 0.0
    ev, pen = [], []

    # --- 1. 来源权重（去重后累加，上限 40）
    srcs = set()
    for w in info.get("why", []):
        base = str(w).split(":")[0].split("[")[0]
        srcs.add(base if base in SOURCE_WEIGHT else "resolve")
    src_score = min(sum(SOURCE_WEIGHT.get(s, 4) for s in sorted(srcs)), MAX_SOURCE_SCORE)
    if src_score:
        score += src_score
        ev.append(f"[+{src_score}] 来源: {', '.join(sorted(srcs))}")

    # --- 2. 新鲜度（最多 30）
    days = _days_ago(info.get("last"))
    if days is not None:
        if days <= 30:
            score += 30; ev.append(f"[+30] 最近解析 {days} 天前")
        elif days <= 90:
            score += 22; ev.append(f"[+22] 最近解析 {days} 天前")
        elif days <= 180:
            score += 13; ev.append(f"[+13] 最近解析 {days} 天前")
        elif days <= 365:
            score += 6; ev.append(f"[+6] 最近解析 {days} 天前")
        else:
            pen.append(f"[-] 最近解析已 {days} 天前（超一年，可能已废弃）")

    # --- 3. 专属性 / 共享主机降噪
    if reverse and reverse.get("ok"):
        un = reverse.get("unrelated_count", 0)
        rel = len(reverse.get("related") or [])
        if un == 0:
            score += 20; ev.append("[+20] 该 IP 上无其它无关域名（独占主机）")
        elif un <= 5:
            score += 12; ev.append(f"[+12] 该 IP 上仅 {un} 个无关域名")
        elif un <= 20:
            score += 5; ev.append(f"[+5] 该 IP 上 {un} 个无关域名")
        elif un <= 100:
            ev.append(f"[0] 该 IP 上 {un} 个无关域名（疑共享主机）")
        else:
            score -= 18
            pen.append(f"[-18] 该 IP 上 {un} 个无关域名，判定为共享虚拟主机")
        if rel:
            score += 8
            ev.append(f"[+8] 该 IP 上解析过目标域名的 {rel} 个名称")

    # --- 4. InternetDB（Shodan 免 key 通道）
    if idb and idb.get("ok"):
        hs = idb.get("hostnames") or []
        if any(h == domain or h.endswith("." + domain) for h in hs):
            score += 30
            ev.append(f"[+30] InternetDB hostnames 含目标域名 ★★★ {hs[:3]}")
        elif hs:
            ev.append(f"[0] InternetDB hostnames: {', '.join(hs[:4])}")
        iports = sorted(idb.get("ports") or [])
        if any(p in iports for p in (80, 443)):
            score += 8
            ev.append(f"[+8] InternetDB 开放端口: {iports[:10]}")
        elif iports:
            ev.append(f"[0] InternetDB 开放端口: {iports[:10]}")
        if idb.get("vulns"):
            ev.append(f"[!] InternetDB CVE: {', '.join((idb.get('vulns') or [])[:5])}")

    # --- 5. 硬验证
    if fp:
        if fp.get("polluted"):
            return {"ip": ip, "score": -1.0, "grade": "polluted",
                    "evidence": ev, "penalty": pen + [fp.get("reason", "代理劫持")],
                    "reverse": reverse, "fingerprint": fp}
        st = fp.get("status")
        if st in (200, 301, 302, 401, 403):
            score += 10
            ev.append(f"[+10] 端口 {fp.get('port')} 返回 {st} "
                      f"(server={str(fp.get('server',''))[:20]})")
        if fp.get("cert_has_host"):
            score += 25
            ev.append("[+25] TLS 证书 SAN 含目标域名 ★铁证")
        if fp.get("favicon_match"):
            score += 20
            ev.append("[+20] favicon mmh3 与目标一致 ★")
        if fp.get("title_match"):
            score += 15
            ev.append(f"[+15] 页面 title 与 CDN 侧一致: {str(fp.get('title',''))[:40]}")
        if fp.get("redirect_to_target"):
            score += 10
            ev.append("[+10] 跳转到目标域名（源站强制 HTTPS）")

    # --- 6. 分级
    idb_host_hit = bool(idb and idb.get("ok") and any(
        h == domain or h.endswith("." + domain) for h in (idb.get("hostnames") or [])))
    hard = bool((fp and (fp.get("cert_has_host") or fp.get("favicon_match")
                         or fp.get("title_match"))) or idb_host_hit)
    if score >= TH_CONFIRMED and hard:
        grade = "confirmed"
    elif score >= TH_LIKELY:
        grade = "likely"
    elif score >= TH_POSSIBLE:
        grade = "possible"
    else:
        grade = "weak"

    return {"ip": ip, "score": round(score, 1), "grade": grade,
            "evidence": ev, "penalty": pen, "reverse": reverse, "fingerprint": fp}


# ---------------------------------------------------------------- 指纹探测
def fingerprint_ip(ip, domain, target_favicon, baseline, ports=(443, 80), timeout=6):
    """直连候选 IP 取证书/favicon/title，带污染自检"""
    out = {"ip": ip, "attempts": [], "polluted": False}
    for port in ports:
        tls = port in (443, 8443)
        r = E.raw_request(ip, domain, port, tls, timeout)
        out["attempts"].append({k: r.get(k) for k in
                                ("port", "status", "server", "len", "title",
                                 "cf", "cert_has_host", "error")})
        if r.get("error"):
            continue
        if r.get("cf") and not cdndb.cdn_vendor_of(ip):
            out["polluted"] = True
            out["reason"] = (f"{ip}:{port} 返回 Cloudflare 特征头，但该 IP 不在任何 CDN 段内 "
                             f"→ 本机代理劫持")
            return out
        st = r.get("status")
        if st not in (200, 301, 302, 401, 403):
            continue
        out.update({"status": st, "port": port, "server": r.get("server", ""),
                    "title": r.get("title", ""), "len": r.get("len", 0),
                    "cert_has_host": bool(r.get("cert_has_host"))})
        loc = (r.get("headers") or {}).get("location", "")
        if loc and domain in loc:
            out["redirect_to_target"] = True
        if baseline.get("title") and r.get("title"):
            a, b = baseline["title"][:30], r["title"][:30]
            if a and b and (a == b or a in b or b in a):
                out["title_match"] = True
        if target_favicon is not None and port in (443, 80):
            fh = E.favicon_from_ip(ip, domain, port, tls, timeout)
            if fh is not None and fh == target_favicon:
                out["favicon_match"] = True
        return out
    return out


# ---------------------------------------------------------------- 子域爆破
def bruteforce_subdomains(domain, threads=30):
    hosts = [f"{w.strip()}.{domain}" for w in SUBDOMAIN_WORDS if w.strip()]
    found = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(resolve, h): h for h in hosts}
        for f in as_completed(futs):
            try:
                ips = f.result()
                if ips:
                    found[futs[f]] = ips
            except Exception:
                pass
    return found


# ---------------------------------------------------------------- 站群扩展
def expand_siblings(scored, domain, threads=30):
    """从候选 IP 反查出的同机域名里，找出仍然直连（未走 CDN）的活入口

    这是绕 CDN 最实用的一步：源站 IP 可能已经下线，但同一台服务器上
    往往还挂着运营方的其它域名，其中总有一两个没上 CDN。
    """
    sib = {}
    for r in scored:
        rv = r.get("reverse") or {}
        for h in (rv.get("unrelated") or []):
            h = str(h).lower().strip()
            if not h or h.endswith("." + domain) or h == domain:
                continue
            if re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", h):
                sib[h] = r["ip"]
    if not sib:
        return {}

    resolved = {}
    with ThreadPoolExecutor(max_workers=min(threads, 30)) as ex:
        futs = {h: ex.submit(resolve, h) for h in sib}
        for h, f in futs.items():
            try:
                ips = f.result(timeout=12)
            except Exception:
                ips = []
            if ips:
                resolved[h] = ips

    out = {}
    for h, ips in resolved.items():
        clean = [ip for ip in ips if not cdndb.cdn_vendor_of(ip)]
        if clean:
            out[h] = {"live_ips": clean, "all_ips": ips,
                      "parent_ip": sib.get(h), "behind_cdn": clean != ips}
    return out


# ---------------------------------------------------------------- 端口扫描 / C 段存活
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445,
                873, 888, 1080, 1433, 1521, 2049, 2375, 3000, 3128, 3306, 3389,
                4440, 4848, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 7001, 7002,
                8000, 8008, 8010, 8069, 8080, 8081, 8088, 8090, 8161, 8443, 8888,
                8983, 9000, 9001, 9060, 9080, 9090, 9200, 9300, 9443, 10000,
                11211, 15672, 27017, 27018, 50000]


def tcp_scan(ip, ports, timeout=1.2, threads=60):
    """TCP 端口扫描（注意：部分机房防火墙会对所有端口回 SYN-ACK，需 phalanx 校验）"""
    def one(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                return p
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return None

    opened = []
    with ThreadPoolExecutor(max_workers=min(threads, len(ports))) as ex:
        for r in ex.map(one, ports):
            if r:
                opened.append(r)
    return sorted(opened)


def verify_ports(ip, ports, timeout=4):
    """对 TCP 连通性做二次确认：能拿到真实响应的才算真开放（防 SYN-ACK 欺骗）"""
    real = {}
    for p in ports:
        tls = p in (443, 8443, 9443)
        r = E.raw_request(ip, ip, p, tls, timeout, "/", max_bytes=8192)
        if r.get("status") or r.get("server"):
            real[p] = {"status": r.get("status"), "server": r.get("server", ""),
                       "title": r.get("title", "")}
    return real


def sweep_cidr(cidr, threads=100, timeout=3):
    """C 段 HTTP 存活探测：只认有真实 HTTP 响应的主机"""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {"error": f"网段格式不对: {cidr}"}
    ips = [str(x) for x in net.hosts()]
    if len(ips) > 1024:
        return {"error": f"网段过大（{len(ips)} 个地址），请用 /24 或更小"}

    def one(ip):
        for port, tls in ((80, False), (443, True)):
            r = E.raw_request(ip, ip, port, tls, timeout, "/", max_bytes=8192)
            if r.get("status"):
                return {"ip": ip, "port": port, "status": r.get("status"),
                        "server": r.get("server", ""), "title": r.get("title", "")}
        return None

    alive = []
    with ThreadPoolExecutor(max_workers=min(threads, len(ips))) as ex:
        for r in ex.map(one, ips):
            if r:
                alive.append(r)
    return {"cidr": str(net), "scanned": len(ips), "alive": alive}


# ---------------------------------------------------------------- 主流程
def hunt(domain, cfg, mode="normal", verbose=True):
    domain = domain.strip().lower().lstrip(".")
    opt = cfg.get("options", {})
    threads = int(opt.get("threads", 30))
    do_brute = mode == "deep" and opt.get("subdomain_bruteforce", True)
    do_engines = mode != "fast"
    # 外部验证很慢（每个 IP 约 15s），只在 deep 或显式开启时跑
    ext_check = bool(opt.get("external_port_check_force")) or mode == "deep"

    rep = {"domain": domain, "version": VERSION, "mode": mode,
           "ts": time.strftime("%Y-%m-%d %H:%M:%S"), "engines": {}, "steps": {}}

    def log(m=""):
        if verbose:
            print(m, flush=True)

    # ---- 1. 解析 + CDN 判定 + DNS 污染检测
    dnsinfo = E.dns_multi(domain)
    cur = dnsinfo.get("ips") or resolve(domain)
    if dnsinfo.get("disagree"):
        log(f"  [!] DNS 分裂解析 {dnsinfo.get('per_resolver')} —— 可能本地 DNS 被污染")
    cur_v = [(ip, cdndb.cdn_vendor_of(ip)) for ip in cur]
    using_cdn = bool(cur) and all(v for _, v in cur_v)
    rep["using_cdn"] = using_cdn
    rep["steps"].update({"dns_now": cur, "cdn_verdict_now": cur_v,
                         "dns_per_resolver": dnsinfo.get("per_resolver", {})})
    log(f"  当前解析   : {cur}")
    log(f"  是否 CDN   : {'是' if using_cdn else '否/部分'}  {cur_v}")

    # ---- 2. 基线 + favicon
    baseline = get_baseline(domain)
    if baseline:
        log(f"  基线响应   : {baseline.get('status')} len={baseline.get('len')} "
            f"title={baseline.get('title')!r}")
    tgt_fav = favicon_of(domain)
    rep["baseline"] = baseline
    rep["favicon_mmh3"] = tgt_fav
    log(f"  favicon    : {tgt_fav}")

    # ---- 3. 被动 DNS（真并发）
    tasks = [
        ("mnemonic", lambda: E.mnemonic(domain)),
        ("otx", lambda: E.otx(domain)),
        ("crtsh", lambda: E.crtsh(domain)),
        ("certspotter", lambda: E.certspotter(domain)),
        ("hackertarget", lambda: E.hackertarget(domain)),
        ("rapiddns", lambda: E.rapiddns(domain)),
    ]
    if mode != "fast":
        tasks += [
            ("bufferover", lambda: E.bufferover(domain)),
            ("subdomain.center", lambda: E.subdomain_center(domain)),
            ("threatminer", lambda: E.threatminer(domain)),
        ]
    results = E.run_parallel(tasks, max_workers=9, per_timeout=80)
    all_recs = []
    for name in [t[0] for t in tasks]:
        r = results.get(name) or {"ok": False, "error": "missing", "records": []}
        rep["engines"][name] = {"ok": r.get("ok"), "error": r.get("error"),
                                "count": len(r.get("records") or []),
                                "note": r.get("note", "")}
        all_recs.extend(r.get("records") or [])
        log(f"  [{'OK ' if r.get('ok') else 'FAIL'}] {name:<18} "
            f"{len(r.get('records') or []):>4} 条 {str(r.get('error') or '')[:46]}")

    # ---- 4. 测绘引擎
    if do_engines:
        fc = cfg.get("fofa", {})
        if fc.get("enabled") and fc.get("key"):
            for q in E.fofa_domain_queries(domain, tgt_fav):
                r = E.fofa_search(q, fc["key"], int(fc.get("size", 100)))
                key = f"fofa[{q[:26]}]"
                rep["engines"][key] = {"ok": r.get("ok"), "error": r.get("error"),
                                       "count": len(r.get("records") or [])}
                all_recs.extend(r.get("records") or [])
                log(f"  [{'OK ' if r.get('ok') else 'FAIL'}] {key[:44]:<44} "
                    f"{len(r.get('records') or []):>4} 条 {str(r.get('error') or '')[:36]}")
                if r.get("error") and "quota" in str(r.get("error")):
                    log("         FOFA 额度不足，跳过剩余 FOFA 查询")
                    break

        sc = cfg.get("shodan", {})
        if sc.get("enabled") and sc.get("key"):
            sub = [("shodan-dns", lambda: E.shodan_dns_domain(domain, sc["key"]))]
            if tgt_fav is not None:
                sub.append(("shodan-favicon",
                            lambda: E.shodan_search(f"http.favicon.hash:{tgt_fav}", sc["key"])))
            sub.append(("shodan-hostname",
                        lambda: E.shodan_search('hostname:"%s"' % domain, sc["key"])))
            r2 = E.run_parallel(sub, max_workers=3, per_timeout=45)
            for k in [x[0] for x in sub]:
                r = r2.get(k) or {"ok": False, "error": "missing", "records": []}
                rep["engines"][k] = {"ok": r.get("ok"), "error": r.get("error"),
                                     "count": len(r.get("records") or [])}
                all_recs.extend(r.get("records") or [])
                log(f"  [{'OK ' if r.get('ok') else 'FAIL'}] {k[:44]:<44} "
                    f"{len(r.get('records') or []):>4} 条 {str(r.get('error') or '')[:36]}")

        cc = cfg.get("censys", {})
        if cc.get("enabled") and (cc.get("token") or cc.get("api_id")):
            qs = ['services.tls.certificates.leaf_data.subject.common_name: "%s"' % domain,
                  'services.tls.certificates.leaf_data.names: "%s"' % domain,
                  'names: "%s"' % domain]
            sub = [(f"censys[{i}]", (lambda q=q: E.censys_search(
                q, cc.get("api_id"), cc.get("api_secret"), cc.get("token"))))
                for i, q in enumerate(qs)]
            r3 = E.run_parallel(sub, max_workers=3, per_timeout=50)
            for k in [x[0] for x in sub]:
                r = r3.get(k) or {"ok": False, "error": "missing", "records": []}
                rep["engines"][k] = {"ok": r.get("ok"), "error": r.get("error"),
                                     "count": len(r.get("records") or [])}
                all_recs.extend(r.get("records") or [])
                log(f"  [{'OK ' if r.get('ok') else 'FAIL'}] {k[:44]:<44} "
                    f"{len(r.get('records') or []):>4} 条 {str(r.get('error') or '')[:36]}")

        extra = []
        for sec, fn in (("zoomeye", E.zoomeye_search), ("quake", E.quake_search),
                        ("hunter", E.hunter_search)):
            c = cfg.get(sec, {})
            if c.get("enabled") and c.get("key"):
                extra.append((sec, (lambda f=fn, k=c["key"]: f('cert:"%s"' % domain, k))))
        if extra:
            r4 = E.run_parallel(extra, max_workers=3, per_timeout=45)
            for k in [x[0] for x in extra]:
                r = r4.get(k) or {"ok": False, "error": "missing", "records": []}
                rep["engines"][k] = {"ok": r.get("ok"), "error": r.get("error"),
                                     "count": len(r.get("records") or [])}
                all_recs.extend(r.get("records") or [])
                log(f"  [{'OK ' if r.get('ok') else 'FAIL'}] {k[:44]:<44} "
                    f"{len(r.get('records') or []):>4} 条 {str(r.get('error') or '')[:36]}")

    # ---- 5. 子域爆破
    if do_brute:
        log(f"  子域爆破   : {len(SUBDOMAIN_WORDS)} 条字典 ...")
        bf = bruteforce_subdomains(domain, threads)
        rep["steps"]["bruteforce"] = bf
        for h, ips in bf.items():
            for ip in ips:
                all_recs.append({"host": h, "ip": ip, "port": None, "src": "bruteforce",
                                 "first": None, "last": None, "extra": {}})
        log(f"  子域爆破   : 命中 {len(bf)} 个")

    # ---- 6. 子域解析
    hosts = {domain}
    for r in all_recs:
        h = (r.get("host") or "").lower().rstrip(".")
        if h and (h.endswith("." + domain) or h == domain):
            hosts.add(h)
    sub_ips = {}
    if hosts:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {h: ex.submit(resolve, h) for h in sorted(hosts)}
            for h, f in futs.items():
                try:
                    ips = f.result(timeout=15)
                except Exception:
                    ips = []
                if ips:
                    sub_ips[h] = ips
    rep["steps"].update({"subdomain_count": len(hosts), "subdomain_ips": sub_ips})

    # ---- 7. 候选聚合
    cand = {}

    def add(ip, why, host=None, first=None, last=None):
        if not ip or not E._valid_ip(ip):
            return
        if str(ip).startswith(("10.", "127.", "192.168.", "0.", "169.254.", "100.64.")):
            return
        if int(str(ip).rsplit(".", 1)[-1]) in (0, 255):
            return
        d = cand.setdefault(ip, {"why": set(), "hosts": set(), "first": None, "last": None})
        d["why"].add(why)
        if host:
            d["hosts"].add(host)
        if first and (not d["first"] or first < d["first"]):
            d["first"] = first
        if last and (not d["last"] or last > d["last"]):
            d["last"] = last

    for r in all_recs:
        add(r.get("ip"), r.get("src", "?"), r.get("host"), r.get("first"), r.get("last"))
    for h, ips in sub_ips.items():
        for ip in ips:
            add(ip, "resolve:" + h, h)

    # ---- 8. CDN 过滤
    filtered = {ip: v for ip, v in cand.items() if not cdndb.cdn_vendor_of(ip)}
    dropped = len(cand) - len(filtered)
    rep["steps"]["candidates_all"] = len(cand)
    rep["steps"]["candidates_cdn_dropped"] = dropped
    log(f"  候选 IP    : 共 {len(cand)} 个，剔除 CDN 段 {dropped} 个，剩 {len(filtered)} 个")

    # ---- 9. 反查 + 指纹 + 评分
    limit = int(opt.get("max_candidates", 200))
    ordered = sorted(filtered.items(),
                     key=lambda kv: (kv[1]["last"] or "", len(kv[1]["why"])),
                     reverse=True)[:limit]
    rev_limit = min(int(opt.get("reverse_limit", 30)), len(ordered))
    scored = []

    if ordered:
        log(f"  反查+验证  : 前 {rev_limit} 个候选 ...")
        rev_map, fp_map = {}, {}
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(E.reverse_domains, ip, domain): ip
                    for ip, _ in ordered[:rev_limit]}
            for f in as_completed(futs):
                ip = futs[f]
                try:
                    rev_map[ip] = f.result(timeout=30)
                except Exception:
                    rev_map[ip] = {"ok": False}
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(fingerprint_ip, ip, domain, tgt_fav, baseline): ip
                    for ip, _ in ordered[:rev_limit]}
            for f in as_completed(futs):
                ip = futs[f]
                try:
                    fp_map[ip] = f.result(timeout=40)
                except Exception:
                    fp_map[ip] = {}

        # InternetDB（Shodan 免 key 通道）：端口 / hostnames / CVE
        idb_map = {}
        if opt.get("internetdb", True):
            with ThreadPoolExecutor(max_workers=8) as ex:
                futs = {ex.submit(E.internetdb, ip): ip for ip, _ in ordered[:rev_limit]}
                for f in as_completed(futs):
                    ip = futs[f]
                    try:
                        idb_map[ip] = f.result(timeout=15)
                    except Exception:
                        idb_map[ip] = {"ok": False}

        for ip, info in ordered:
            scored.append(score_candidate(
                ip,
                {"why": sorted(info["why"]), "hosts": sorted(info["hosts"]),
                 "first": info["first"], "last": info["last"]},
                domain, baseline, tgt_fav, rev_map.get(ip), fp_map.get(ip),
                idb_map.get(ip)))
        scored.sort(key=lambda x: -x["score"])

    # ---- 9.5 站群扩展：同机域名里找没走 CDN 的活入口
    sib = {}
    if scored:
        log("  站群扩展   : 反查出的同机域名二次解析 ...")
        sib = expand_siblings(scored, domain, threads)
        rep["siblings"] = sib
        if sib:
            log(f"  站群扩展   : {len(sib)} 个域名未走 CDN ★")
            for h, v in list(sib.items())[:12]:
                log(f"    → {h:<34} {v['live_ips']}")
        else:
            log("  站群扩展   : 无未走 CDN 的同机域名")

    rep["scored"] = scored
    rep["candidates"] = {r["ip"]: r for r in scored}
    rep["verified_origin"] = [r["ip"] for r in scored if r["grade"] == "confirmed"]
    rep["likely_origin"] = [r["ip"] for r in scored if r["grade"] == "likely"]
    rep["polluted_env"] = any(r["grade"] == "polluted" for r in scored)

    # ---- 9.6 候选端口扫描（融合端口探测能力）
    scan_list = opt.get("scan_ports")
    if scan_list and scored:
        tgts = [r["ip"] for r in scored[:int(opt.get("scan_targets", 5))]]
        log(f"  端口扫描   : {len(tgts)} 个候选 × {len(scan_list)} 端口 ...")
        pscan = {}
        for ip in tgts:
            raw_open = tcp_scan(ip, scan_list)
            real = verify_ports(ip, raw_open) if raw_open else {}
            pscan[ip] = {"tcp_open": raw_open, "verified": real}
            if raw_open:
                fake = [p for p in raw_open if p not in real]
                line = f"    {ip:<16} TCP开放 {raw_open}"
                if fake:
                    line += f"  ⚠ {fake} 无真实响应(疑防火墙欺骗)"
                log(line)
            else:
                log(f"    {ip:<16} 无开放端口")
        rep["steps"]["port_scan"] = pscan

    # ---- 10. 打印排行
    if scored:
        log("")
        log("  " + "=" * 78)
        log("  候选排行（按置信度）")
        log("  " + "=" * 78)
        for r in scored[:12]:
            flag = {"confirmed": "★命中", "likely": "◎可能", "possible": "○存疑",
                    "weak": "· 弱", "polluted": "✗污染"}.get(r["grade"], "?")
            log(f"  [{flag}] {r['score']:>6.1f}  {r['ip']}")
            for e in r["evidence"][:7]:
                log(f"          {e}")
            for p in r["penalty"][:3]:
                log(f"          {p}")
            rv = r.get("reverse") or {}
            if rv.get("unrelated"):
                log(f"          同机其它域名: {', '.join(rv['unrelated'][:6])}")
            fpv = r.get("fingerprint") or {}
            if fpv.get("polluted"):
                log(f"          {fpv.get('reason', '')}")
        log("")

    if rep["polluted_env"]:
        log("  " + "!" * 72)
        log("  [!] 本机代理劫持已确认：非 CDN IP 返回了 Cloudflare 响应头。")
        log("  [!] 证书/favicon/title 类硬证据不可信，请关闭 TUN 代理后重跑，或改用 VPS。")
        log("  [!] 评分中的『来源』『新鲜度』『专属性』三项仍然有效。")
        log("  " + "!" * 72)

    # ---- 11. 外部端口验证
    if ext_check and filtered:
        log("  外部验证   : check-host.net 探测前 6 个 ...")
        ext = {}
        for ip, _ in ordered[:6]:
            r = E.checkhost_tcp(ip, 443, nodes=5)
            ext[ip] = {"open_nodes": r.get("open_nodes", []), "alive": r.get("ok")}
            log(f"    {ip:<16} 443={'OPEN' if r.get('ok') else 'closed'} "
                f"({len(r.get('open_nodes') or [])} 节点可达)")
        rep["steps"]["external_check"] = ext

    return rep


# ---------------------------------------------------------------- 输出
def save_report(rep, outdir):
    d = os.path.join(outdir, rep["domain"])
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "report.json"), "w", encoding="utf-8").write(
        json.dumps(rep, indent=2, ensure_ascii=False, default=str))
    with open(os.path.join(d, "candidates.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(r["ip"] for r in rep.get("scored", [])))
    conf = rep.get("verified_origin") or []
    likely = rep.get("likely_origin") or []
    if conf or likely:
        with open(os.path.join(d, "origin.txt"), "w", encoding="utf-8") as f:
            f.write("# confirmed\n" + "\n".join(conf))
            if likely:
                f.write("\n# likely\n" + "\n".join(likely))
    if rep.get("favicon_mmh3") is not None:
        with open(os.path.join(d, "favicon_hash.txt"), "w", encoding="utf-8") as f:
            f.write(f'icon_hash="{rep["favicon_mmh3"]}"\n')

    md = [f"# {rep['domain']} CDN 溯源报告", "",
          f"- 时间: {rep['ts']}",
          f"- 版本: v{rep['version']} (mode={rep['mode']})",
          f"- 当前解析: {rep['steps'].get('dns_now')}",
          f"- 是否 CDN: {'是' if rep.get('using_cdn') else '否/部分'}",
          f"- favicon mmh3: {rep.get('favicon_mmh3')}",
          f"- 污染环境: {'是（代理劫持，硬证据不可信）' if rep.get('polluted_env') else '否'}",
          ""]
    if rep.get("siblings"):
        md += ["## 站群扩展（未走 CDN 的同机域名）", "",
               "| 域名 | 存活 IP | 与被查域名的关系 |", "|---|---|---|"]
        for h, v in rep["siblings"].items():
            md.append(f"| {h} | {', '.join(v['live_ips'])} | 曾与 {v.get('parent_ip')} 同机 |")
        md.append("")
    if rep.get("scored"):
        md += ["## 候选排行", "", "| 等级 | 分数 | IP | 关键证据 |", "|---|---|---|---|"]
        for r in rep["scored"][:20]:
            last_ev = (r["evidence"][-1] if r["evidence"] else "")[:70]
            md.append(f"| {r['grade']} | {r['score']} | {r['ip']} | {last_ev} |")
        md.append("")
        md.append("## 证据明细")
        for r in rep["scored"][:10]:
            md.append(f"\n### {r['ip']}  ({r['grade']}, {r['score']})")
            for e in r["evidence"]:
                md.append(f"- {e}")
            for p in r["penalty"]:
                md.append(f"- {p}")
    open(os.path.join(d, "report.md"), "w", encoding="utf-8").write("\n".join(md))
    return d


HELP_TEXT = """
  用法
    Source -d <目标域名> [选项]
    Source -f <域名列表.txt> [选项]
    Source -i <IP1,IP2> -t <目标域名>
    Source --sweep <网段>

  ── 目标 ────────────────────────────────────────────────────────────
    -d, --domain <域名>     目标域名，可重复写多个：-d a.com -d b.com
    -f, --file <文件>       域名列表，每行一个，# 开头为注释
    -i, --ips <IP列表>      已有候选 IP，逗号分隔，配合 -t 直接做评分验证
    -t, --target <域名>     配合 -i：这些 IP 对应的目标域名

  ── 扫描模式（三选一，默认标准）─────────────────────────────────────
    --fast                  快速：只跑最快的数据源，适合先探路
    --deep                  深度：全源 + 180条子域爆破 + 站群扩展 + 外部验证
    （默认）                标准：全源 + 站群扩展

  ── 附加探测 ────────────────────────────────────────────────────────
    --scan-ports <端口>     对候选源站扫端口，如 80,443,22,3306,6379
                            --deep 下默认扫 60 个常用端口，TCP 连通后还会验证真实响应
    --no-scan               关闭端口扫描
    --sweep <网段>          C 段 HTTP 存活探测，如 203.0.113.0/24
    --external-check        用 check-host.net 全球节点验证端口（不受本机代理影响）
    --threads <N>           并发线程数，默认 30
    -c, --config <文件>     配置文件，默认 recon/config.json
    -o, --outdir <目录>     输出目录，默认 recon/out

  ── 评分维度（分数越高越可信）──────────────────────────────────────
    来源权重 +40   多个独立数据源交叉证实，去重累加
    新鲜度   +30   最近解析 30 天内满权，超一年归零
    专属性   +20   该 IP 上无关域名越少越可信，>100 个直接 -18（共享主机）
    证书     +25   TLS 证书 SAN 含目标域名 —— 铁证
    favicon  +20   直取候选 IP 的图标算 mmh3 比对
    hostnames +30  Shodan InternetDB 记录的主机名含目标域名 —— 铁证
    title    +15   页面标题与 CDN 侧一致
    跳转     +10   301 跳转到目标域名

    分级：confirmed ≥70 且有硬证据 / likely ≥45 / possible ≥25 / weak / polluted

  ── 示例 ────────────────────────────────────────────────────────────
    Source -d example.com --deep
        → 全流程溯源，含子域爆破与站群扩展

    Source -i 1.2.3.4,5.6.7.8 -t example.com
        → 已有 IP 直接评分，不重新收集

    Source -d example.com --scan-ports 80,443,22,8080
        → 顺带扫候选源站端口

    Source --sweep 203.0.113.0/24
        → 只做 C 段存活探测

    Source -f targets.txt --fast
        → 批量快速探路

  ── 输出 ────────────────────────────────────────────────────────────
    recon/out/<域名>/report.md        人读报告（候选排行 + 证据链）
    recon/out/<域名>/report.json      全量结构化数据
    recon/out/<域名>/origin.txt       confirmed / likely 分级清单
    recon/out/<域名>/candidates.txt   候选 IP，按分数排序，可喂 nmap -iL

  ── 数据源 ──────────────────────────────────────────────────────────
    免key   mnemonic 被动DNS / crt.sh / certspotter / otx / rapiddns
            hackertarget / bufferover / subdomain.center / threatminer
            Shodan InternetDB（端口+hostnames+CVE）
    需key   FOFA / Shodan / Censys / ZoomEye / Quake / Hunter
            在 recon/config.json 里填，额度不足会自动降级跳过
"""


class CnParser(argparse.ArgumentParser):
    """参数错误输出中文"""

    def error(self, message):
        msg = str(message)
        mapping = {
            "unrecognized arguments": "无法识别的参数",
            "invalid int value": "需要整数",
            "expected one argument": "缺少参数值",
            "argument -d/--domain: expected one argument": "-d 后面要跟域名",
        }
        for k, v in mapping.items():
            msg = msg.replace(k, v)
        print(f"\n  ✗ 参数有误：{msg}\n")
        print("  输入 -h 查看完整中文用法\n")
        sys.exit(2)


def print_help():
    banner()
    print(HELP_TEXT)


def main():
    _init_console()
    argv = sys.argv[1:]
    if not argv or any(x in ("-h", "--help", "-help", "/?") for x in argv):
        print_help()
        return

    ap = CnParser(prog="Source", add_help=False)
    ap.add_argument("-d", "--domain", action="append", default=[])
    ap.add_argument("-f", "--file")
    ap.add_argument("-i", "--ips")
    ap.add_argument("-t", "--target")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--no-engines", action="store_true")
    ap.add_argument("--no-brute", action="store_true")
    ap.add_argument("--scan-ports")
    ap.add_argument("--no-scan", action="store_true")
    ap.add_argument("--sweep")
    ap.add_argument("--external-check", action="store_true")
    ap.add_argument("--threads", type=int)
    ap.add_argument("-c", "--config")
    ap.add_argument("-o", "--outdir", default="recon/out")
    a = ap.parse_args(argv)

    banner()

    cfg = load_config(a.config)
    E.set_proxy(cfg.get("proxy", {}).get("http") or None)
    if a.threads:
        cfg["options"]["threads"] = a.threads
    if a.external_check:
        cfg["options"]["external_port_check_force"] = True

    # ---- C 段存活探测（独立功能）
    if a.sweep:
        print(f"  目标网段   : {a.sweep}")
        print(f"  探测方式   : HTTP 80/443 真实响应（不是 TCP connect，避免防火墙欺骗）\n")
        t0 = time.time()
        r = sweep_cidr(a.sweep, threads=int(cfg["options"].get("threads", 30)) * 3)
        if r.get("error"):
            print(f"  ✗ {r['error']}")
            return
        print(f"  扫描 {r['scanned']} 个地址，存活 {len(r['alive'])} 台，"
              f"耗时 {time.time() - t0:.1f}s\n")
        for h in r["alive"]:
            print(f"    {h['ip']:<16} :{h['port']:<5} {h['status']:<4} "
                  f"{str(h['server'])[:18]:<18} {h['title'][:40]}")
        os.makedirs(a.outdir, exist_ok=True)
        out = os.path.join(a.outdir, f"sweep_{a.sweep.replace('/', '_')}.json")
        open(out, "w", encoding="utf-8").write(
            json.dumps(r, indent=2, ensure_ascii=False, default=str))
        print(f"\n  结果已存: {out}")
        return

    # ---- 单 IP 评分验证模式
    if a.ips and a.target:
        domain = a.target.strip().lower()
        print(f"  目标域名   : {domain}")
        baseline = get_baseline(domain)
        tf = favicon_of(domain)
        print(f"  基线响应   : {baseline.get('status')} len={baseline.get('len')} "
              f"title={baseline.get('title')!r}")
        print(f"  favicon    : {tf}\n")
        for ip in [x.strip() for x in a.ips.split(",") if x.strip()]:
            fp = fingerprint_ip(ip, domain, tf, baseline)
            idb = E.internetdb(ip)
            r = score_candidate(ip, {"why": ["manual"], "hosts": [],
                                     "first": None, "last": None},
                                domain, baseline, tf, None, fp, idb)
            print(f"  [{r['grade'].upper():<9}] {r['score']:>6.1f}  {ip}")
            for e in r["evidence"]:
                print(f"          {e}")
            for p in r["penalty"]:
                print(f"          {p}")
            for at in fp.get("attempts", []):
                if at.get("error"):
                    print(f"          {at['port']} → {at['error']}")
                elif at.get("status"):
                    print(f"          {at['port']} → {at['status']} len={at.get('len')} "
                          f"server={str(at.get('server',''))[:18]} "
                          f"cert_host={at.get('cert_has_host')} cf={at.get('cf')}")
            print("")
        return

    # ---- 域名溯源模式
    domains = list(a.domain)
    if a.file:
        try:
            domains += [l.strip() for l in open(a.file, encoding="utf-8")
                        if l.strip() and not l.startswith("#")]
        except Exception as e:
            print(f"  ✗ 读取域名列表失败: {e}")
            return
    if not domains:
        print("  ✗ 没有指定目标。\n")
        print("  试试:  Source -d example.com --deep")
        print("  或:    Source -h  查看完整中文用法\n")
        return

    mode = "deep" if a.deep else ("fast" if a.fast else "normal")
    if a.no_brute and mode == "deep":
        mode = "normal"
    if a.no_engines and mode == "normal":
        mode = "fast"

    # 端口扫描策略
    if a.no_scan:
        cfg["options"]["scan_ports"] = None
    elif a.scan_ports:
        try:
            cfg["options"]["scan_ports"] = [int(x) for x in a.scan_ports.split(",") if x.strip()]
        except ValueError:
            print("  ✗ --scan-ports 格式错误，示例：80,443,22,3306")
            return
    elif mode == "deep":
        cfg["options"]["scan_ports"] = COMMON_PORTS
    else:
        cfg["options"]["scan_ports"] = None

    mode_cn = {"fast": "快速", "normal": "标准", "deep": "深度"}[mode]
    os.makedirs(a.outdir, exist_ok=True)

    for d in domains:
        print(f"  {'=' * 66}")
        print(f"  目标: {d}    模式: {mode_cn}")
        print(f"  {'=' * 66}")
        t0 = time.time()
        rep = hunt(d, cfg, mode=mode)
        out = save_report(rep, a.outdir)
        dt = time.time() - t0
        print(f"\n  耗时 {dt:.1f}s    报告: {os.path.join(out, 'report.md')}")
        conf = rep.get("verified_origin") or []
        likely = rep.get("likely_origin") or []
        if conf:
            print(f"  ★ 已确认源站: {conf}")
        if likely:
            print(f"  ◎ 高度疑似: {likely}")
        if not conf and not likely:
            top = (rep.get("scored") or [])[:3]
            print(f"  ○ 存疑候选: {[(r['ip'], r['score']) for r in top]}" if top
                  else "  ✗ 未发现非 CDN 候选")
        sib = rep.get("siblings") or {}
        if sib:
            print(f"  ★ 站群未走 CDN 的活入口 ({len(sib)}):")
            for h, v in list(sib.items())[:10]:
                print(f"      {h:<34} → {v['live_ips']}")
        print("")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  已中断\n")
        sys.exit(130)
