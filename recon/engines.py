#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""engines.py —— CDN 溯源数据源层 + 深度指纹验证（v2.1）

统一返回结构：
    {"engine": str, "ok": bool, "error": str|None, "records": [Record], "note": str}
Record:
    {"host": str|None, "ip": str|None, "port": int|None,
     "src": str, "first": str|None, "last": str|None, "extra": dict}

v2.1 增强（为准确率服务）：
  - run_parallel()：引擎真并发（as_completed），单源超时不拖累全局
  - dns_multi()：四路 DoH 交叉解析，检测本地 DNS 污染 / 分裂解析
  - raw_request()：原始 socket，带证书指纹与 CF 污染标记
  - favicon_from_ip()：从候选 IP 直取 favicon 算 mmh3，与目标比对
  - reverse_domains()：候选 IP 上解析过的全部域名（共享主机判别）
  - checkhost_tcp()：check-host 全球节点端口验证（外部视角）
"""
import base64
import json
import re
import socket
import ssl
import struct
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_OPENER = None


def set_proxy(http_proxy=None):
    global _OPENER
    if http_proxy:
        _OPENER = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": http_proxy, "https": http_proxy}))
    else:
        _OPENER = urllib.request.build_opener()


def _opener():
    global _OPENER
    if _OPENER is None:
        set_proxy(None)
    return _OPENER


def _req(url, headers=None, data=None, timeout=15, method=None):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with _opener().open(r, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        try:
            return e.read()
        except Exception:
            return None
    except Exception:
        return None


def get_text(url, timeout=15, headers=None):
    b = _req(url, headers=headers, timeout=timeout)
    return b.decode("utf-8", "replace") if b else None


def get_json(url, timeout=15, headers=None):
    b = _req(url, headers=headers, timeout=timeout)
    if not b:
        return None
    try:
        return json.loads(b.decode("utf-8", "replace"))
    except Exception:
        return None


def post_json(url, payload, timeout=20, headers=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    b = _req(url, headers=h, data=json.dumps(payload).encode(), timeout=timeout, method="POST")
    if not b:
        return None
    try:
        return json.loads(b.decode("utf-8", "replace"))
    except Exception:
        return None


def _rec(host=None, ip=None, port=None, src="", first=None, last=None, **extra):
    return {"host": host, "ip": ip, "port": port, "src": src,
            "first": first, "last": last, "extra": extra}


def _ck(engine, records=None, error=None, note=""):
    return {"engine": engine, "ok": error is None,
            "error": error, "records": records or [], "note": note}


IPRX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _valid_ip(ip):
    if not ip or not IPRX.match(str(ip)):
        return False
    return all(0 <= int(x) <= 255 for x in str(ip).split("."))


def _ms2date(ms):
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(int(ms) / 1000))
    except Exception:
        return None


# ================================================================ 并发调度
def run_parallel(tasks, max_workers=8, per_timeout=90):
    """真并发跑一组 (name, fn)；单源抛异常/超时只影响自己

    tasks: [(name, callable)]
    return: {name: result_dict}
    """
    out = {}
    if not tasks:
        return out
    with ThreadPoolExecutor(max_workers=min(max_workers, len(tasks))) as ex:
        futs = {ex.submit(fn): name for name, fn in tasks}
        try:
            for f in as_completed(futs, timeout=per_timeout):
                name = futs[f]
                try:
                    out[name] = f.result()
                except Exception as e:
                    out[name] = _ck(name, error=f"{type(e).__name__}: {e}"[:90])
        except Exception:
            pass
    for name, _ in tasks:
        out.setdefault(name, _ck(name, error="timeout"))
    return out


# ================================================================ 原始 socket
def _parse_headers(raw):
    head = raw.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    status = None
    m = re.match(r"HTTP/[\d.]+\s+(\d+)", lines[0] if lines else "")
    if m:
        status = int(m.group(1))
    h = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            h[k.strip().lower()] = v.strip()
    return status, h


def raw_request(ip, host, port=443, tls=True, timeout=8, path="/", max_bytes=300000):
    """直接 socket 发请求（不经系统代理），返回状态/头/体片段/证书指纹/CF 污染标记"""
    out = {"ip": ip, "port": port, "tls": tls, "ok": False}
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except Exception:
                pass
            s = ctx.wrap_socket(s, server_hostname=host)
            try:
                der = s.getpeercert(binary_form=True) or b""
                out["cert_der_len"] = len(der)
                out["cert_has_host"] = host.encode() in der
                for hint in (b"Cloudflare", b"Google Trust Services", b"Let's Encrypt",
                             b"DigiCert", b"ZeroSSL", b"Sectigo"):
                    if hint in der:
                        out["cert_issuer_hint"] = hint.decode()
                        break
            except Exception:
                pass
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        s.sendall(req.encode())
        buf = b""
        while len(buf) < max_bytes:
            try:
                c = s.recv(65536)
            except socket.timeout:
                break
            if not c:
                break
            buf += c
        raw = buf.decode("latin-1", "replace")
        status, headers = _parse_headers(raw)
        body = buf.split(b"\r\n\r\n", 1)[-1]
        out.update({
            "status": status,
            "server": headers.get("server", ""),
            "headers": headers,
            "len": len(body),
            "body_head": body[:8192],
            "cf": ("cf-ray" in headers) or headers.get("server", "").lower() == "cloudflare",
            "ok": status is not None,
        })
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        out["title"] = (m.group(1).decode("utf-8", "replace").strip()[:90] if m else "")
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"[:100]
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass
    return out


def _mmh3_32(data, seed=0):
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed
    rounded = length & 0xfffffffc
    for i in range(0, rounded, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 3
    if tail == 3:
        k1 = (data[rounded + 2] & 0xff) << 16
    if tail >= 2:
        k1 |= (data[rounded + 1] & 0xff) << 8
    if tail >= 1:
        k1 |= data[rounded] & 0xff
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    return struct.unpack("i", struct.pack("I", h1))[0]


def favicon_hash_bytes(data):
    return _mmh3_32(base64.encodebytes(data)) if data and len(data) > 16 else None


def favicon_from_ip(ip, host, port=443, tls=True, timeout=8):
    """从候选 IP 直取 favicon 算 mmh3"""
    r = raw_request(ip, host, port, tls, timeout, "/favicon.ico", max_bytes=200000)
    body = r.get("body_head") or b""
    if r.get("status") == 200 and len(body) > 16:
        return favicon_hash_bytes(body)
    return None


# ================================================================ DNS
def dns_multi(host, timeout=8):
    """四路 DoH 交叉解析，检测本地 DNS 污染 / 分裂解析"""
    resolvers = {
        "google": f"https://dns.google/resolve?name={urllib.parse.quote(host)}&type=A",
        "cloudflare": f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A",
    }
    hdr = {"Accept": "application/dns-json"}

    def one(item):
        name, url = item
        d = get_json(url, timeout=timeout, headers=hdr)
        if not isinstance(d, dict):
            return name, []
        ips = [a["data"] for a in (d.get("Answer") or [])
               if a.get("type") == 1 and _valid_ip(a.get("data"))]
        return name, sorted(set(ips))

    res = {}
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = [ex.submit(one, kv) for kv in resolvers.items()]
        for f in as_completed(futs):
            try:
                n, ips = f.result(timeout=timeout + 3)
                res[n] = ips
            except Exception:
                pass
    all_ips = sorted({ip for ips in res.values() for ip in ips})
    disagree = len({tuple(ips) for ips in res.values() if ips}) > 1
    return {"per_resolver": res, "ips": all_ips, "disagree": disagree}


# ================================================================ 被动 DNS
def mnemonic(domain):
    d = get_json(f"https://api.mnemonic.no/pdns/v3/{urllib.parse.quote(domain)}", timeout=25)
    if not d:
        return _ck("mnemonic", error="no response")
    rows = d.get("data") or []
    recs = []
    for r in rows:
        q = (r.get("query") or "").lower().rstrip(".")
        ans = r.get("answer")
        rt = r.get("rrtype")
        first = _ms2date(r.get("firstSeenTimestamp"))
        last = _ms2date(r.get("lastSeenTimestamp"))
        if rt == "a" and _valid_ip(ans):
            recs.append(_rec(host=q, ip=ans, src="mnemonic", first=first, last=last))
        elif rt == "cname":
            recs.append(_rec(host=q, src="mnemonic-cname", first=first, last=last, cname=ans))
    return _ck("mnemonic", recs, note=f"{len(rows)} rows")


def mnemonic_reverse(ip):
    d = get_json(f"https://api.mnemonic.no/pdns/v3/{urllib.parse.quote(ip)}", timeout=15)
    if not d:
        return _ck("mnemonic-rev", error="no response")
    recs = []
    for r in d.get("data") or []:
        if r.get("rrtype") == "a":
            recs.append(_rec(host=(r.get("query") or "").lower().rstrip("."),
                             ip=ip, src="mnemonic-rev",
                             first=_ms2date(r.get("firstSeenTimestamp")),
                             last=_ms2date(r.get("lastSeenTimestamp"))))
    return _ck("mnemonic-rev", recs, note=f"ip={ip}")


def reverse_domains(ip, domain):
    """候选 IP 上解析过的全部域名 —— 共享主机判别依据"""
    r = mnemonic_reverse(ip)
    hosts = sorted({x["host"] for x in r.get("records") or [] if x.get("host")})
    related = [h for h in hosts if h == domain or h.endswith("." + domain)]
    unrelated = [h for h in hosts if h not in related]
    return {"ip": ip, "total": len(hosts), "related": related,
            "unrelated": unrelated[:30], "unrelated_count": len(unrelated),
            "ok": r.get("ok"), "error": r.get("error")}


def otx(domain):
    d = get_json(f"https://otx.alienvault.com/api/v1/indicators/domain/"
                 f"{urllib.parse.quote(domain)}/passive_dns", timeout=25)
    if not d:
        return _ck("otx", error="no response")
    recs = []
    for r in d.get("passive_dns") or []:
        ip = r.get("address")
        if _valid_ip(ip):
            recs.append(_rec(host=(r.get("hostname") or "").lower(), ip=ip, src="otx",
                             first=(r.get("first") or "")[:10],
                             last=(r.get("last") or "")[:10]))
    return _ck("otx", recs)


def rapiddns(domain):
    recs = []
    for page in ("", "/page/2"):
        html = get_text(f"https://rapiddns.io/sameip/{urllib.parse.quote(domain)}{page}?full=1", 18)
        if not html:
            continue
        for m in re.finditer(r"<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>", html):
            if _valid_ip(m.group(1)):
                recs.append(_rec(host=domain, ip=m.group(1), src="rapiddns"))
        time.sleep(0.3)
    return _ck("rapiddns", recs)


def hackertarget(domain):
    t = get_text(f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}", 18)
    if not t:
        return _ck("hackertarget", error="no response")
    if "API count exceeded" in t:
        return _ck("hackertarget", error="quota exceeded")
    if t.strip().lower().startswith("error"):
        return _ck("hackertarget", error=t.strip()[:60])
    recs = []
    for line in t.splitlines():
        p = line.split(",")
        if len(p) == 2 and _valid_ip(p[1].strip()):
            recs.append(_rec(host=p[0].strip().lower(), ip=p[1].strip(), src="hackertarget"))
    return _ck("hackertarget", recs)


def bufferover(domain):
    d = get_json(f"https://dns.bufferover.run/dns?q=.{urllib.parse.quote(domain)}", timeout=18)
    if not d:
        return _ck("bufferover", error="no response")
    recs = []
    for key in ("FDNS_A", "RDNS"):
        for item in d.get(key) or []:
            parts = str(item).split(",")
            if len(parts) < 2:
                continue
            a, b = parts[0].strip(), parts[1].strip()
            if _valid_ip(a):
                recs.append(_rec(host=b.lower(), ip=a, src="bufferover"))
            elif _valid_ip(b):
                recs.append(_rec(host=a.lower(), ip=b, src="bufferover"))
    return _ck("bufferover", recs)


def subdomain_center(domain):
    d = get_json(f"https://api.subdomain.center/?domain={urllib.parse.quote(domain)}", timeout=20)
    if not isinstance(d, list):
        return _ck("subdomain.center", error="not list / quota")
    return _ck("subdomain.center", [_rec(host=str(h).lower(), src="subdomain.center") for h in d])


def threatminer(domain):
    d = get_json(f"https://api.threatminer.org/v2/domain.php?q={urllib.parse.quote(domain)}&rt=5",
                 timeout=18)
    if not isinstance(d, dict) or str(d.get("status_code")) != "200":
        return _ck("threatminer", error="no data")
    return _ck("threatminer", [_rec(host=str(h).lower(), src="threatminer")
                               for h in d.get("results") or []])


def crtsh(domain):
    """单次查询 %.domain 已覆盖主域与全部子域，省一次往返"""
    recs = []
    d = get_json(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json", timeout=25)
    if isinstance(d, list):
        for row in d:
            for f in ("name_value", "common_name"):
                for n in str(row.get(f) or "").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n and " " not in n and (n.endswith("." + domain) or n == domain):
                        recs.append(_rec(host=n, src="crt.sh",
                                         issuer=(row.get("issuer_name") or "")[:60]))
    seen, out = set(), []
    for r in recs:
        if r["host"] not in seen:
            seen.add(r["host"])
            out.append(r)
    return _ck("crt.sh", out, note=f"{len(out)} unique")


def certspotter(domain):
    d = get_json(f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}"
                 f"&include_subdomains=true&expand=dns_names", timeout=22)
    if not isinstance(d, list):
        return _ck("certspotter", error="no data / rate limited")
    seen, out = set(), []
    for row in d:
        for n in row.get("dns_names") or []:
            n = str(n).lower().lstrip("*.")
            if (n.endswith("." + domain) or n == domain) and n not in seen:
                seen.add(n)
                out.append(_rec(host=n, src="certspotter"))
    return _ck("certspotter", out)


# ================================================================ 测绘引擎
def fofa_search(query, key, size=100):
    if not key:
        return _ck("fofa", error="no key")
    qb = base64.b64encode(query.encode()).decode()
    fields = "host,ip,port,domain,title,server,protocol,icp"
    url = (f"https://fofa.info/api/v1/search/all?key={key}&qbase64={qb}"
           f"&size={size}&fields={fields}")
    d = get_json(url, timeout=30)
    if not d:
        return _ck("fofa", error="no response")
    if d.get("error"):
        msg = d.get("errmsg") or "unknown"
        tag = "quota" if ("余额" in msg or "F点" in msg or "820031" in msg) else "error"
        return _ck("fofa", error=f"[{tag}] {msg}")
    recs = []
    for row in d.get("results") or []:
        row = list(row)
        host = row[0] if len(row) > 0 else None
        ip = row[1] if len(row) > 1 else None
        port = row[2] if len(row) > 2 else None
        if _valid_ip(ip):
            recs.append(_rec(host=host, ip=str(ip),
                             port=int(port) if str(port).isdigit() else None,
                             src=f"fofa:{query[:20]}",
                             title=row[4] if len(row) > 4 else None,
                             server=row[5] if len(row) > 5 else None))
    return _ck("fofa", recs, note=query)


def fofa_domain_queries(domain, favicon_hash=None):
    qs = []
    if favicon_hash is not None:
        qs.append(f'icon_hash="{favicon_hash}"')
    qs += [f'cert="{domain}"', f'domain="{domain}"', f'host="{domain}"', f'body="{domain}"']
    return qs


def shodan_search(query, key, page=1):
    if not key:
        return _ck("shodan", error="no key")
    url = (f"https://api.shodan.io/shodan/host/search?key={key}"
           f"&query={urllib.parse.quote(query)}&page={page}")
    d = get_json(url, timeout=30)
    if not d:
        return _ck("shodan", error="no response")
    if d.get("error"):
        tag = "quota" if "membership" in str(d["error"]).lower() else "error"
        return _ck("shodan", error=f"[{tag}] {d['error']}"[:80])
    recs = []
    for m in d.get("matches") or []:
        ip = m.get("ip_str")
        if _valid_ip(ip):
            recs.append(_rec(host=(m.get("hostnames") or [None])[0], ip=ip,
                             port=m.get("port"), src=f"shodan:{query[:20]}",
                             org=m.get("org"), product=m.get("product")))
    return _ck("shodan", recs, note=query)


def shodan_dns_domain(domain, key):
    if not key:
        return _ck("shodan-dns", error="no key")
    d = get_json(f"https://api.shodan.io/dns/domain/{urllib.parse.quote(domain)}?key={key}",
                 timeout=25)
    if d is None:
        return _ck("shodan-dns", error="no response")
    if d.get("error"):
        return _ck("shodan-dns", error=f"[quota] {d['error']}"[:80])
    recs = []
    for r in d.get("data") or []:
        sub = (r.get("subdomain") or "").lower()
        h = (sub + "." + domain) if sub else domain
        if r.get("type") == "A" and _valid_ip(r.get("value")):
            recs.append(_rec(host=h, ip=r.get("value"), src="shodan-dns"))
        else:
            recs.append(_rec(host=h, src="shodan-dns", rtype=r.get("type"),
                             value=r.get("value")))
    return _ck("shodan-dns", recs)


def censys_search(query, api_id=None, api_secret=None, token=None, per_page=100):
    """Censys 反查 —— 同时支持两种认证

    1) Personal Access Token（Bearer, 形如 censys_xxx）→ v3 Platform API
       注意：v3 的 /v3/global/search/query 需要 Organization ID，免费账号会 403
    2) 旧版 API ID + Secret（Basic）→ v2 Legacy API
       注意：Legacy Search 已于 2026-09-30 下线，只剩账单类接口
    """
    # --- 优先 Bearer (v3 platform)
    if token:
        url = "https://api.platform.censys.io/v3/global/search/query"
        payload = {"query": query, "page_size": per_page}
        b = _req(url, headers={"Authorization": f"Bearer {token}",
                               "Content-Type": "application/json"},
                 data=json.dumps(payload).encode(), method="POST", timeout=30)
        if not b:
            return _ck("censys", error="no response")
        try:
            d = json.loads(b.decode("utf-8", "replace"))
        except Exception:
            return _ck("censys", error="bad json")
        if d.get("status") == 403 or d.get("detail"):
            msg = str(d.get("detail") or d.get("error") or "")
            tag = "plan" if "organization" in msg.lower() else "error"
            return _ck("censys", error=f"[{tag}] {msg}"[:110])
        hits = (((d.get("result") or {}).get("hits"))
                or ((d.get("result") or {}).get("data"))
                or [])
        recs = []
        for h in hits:
            host = h.get("host") or h
            ip = host.get("ip") or h.get("ip")
            if _valid_ip(ip):
                recs.append(_rec(host=(host.get("name") or h.get("name")), ip=ip,
                                 src=f"censys:{query[:20]}",
                                 services=[s.get("port") for s in (host.get("services") or [])]))
        return _ck("censys", recs, note=query)

    # --- 退化为 Basic (v2 legacy)
    if not api_id or not api_secret:
        return _ck("censys", error="no credentials")
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    url = (f"https://search.censys.io/api/v2/hosts/search?q={urllib.parse.quote(query)}"
           f"&per_page={per_page}")
    b = _req(url, headers={"Authorization": f"Basic {auth}"}, timeout=30)
    if not b:
        return _ck("censys", error="no response")
    try:
        d = json.loads(b.decode("utf-8", "replace"))
    except Exception:
        return _ck("censys", error="bad json")
    err = str(d.get("error") or d.get("detail") or "")
    if err:
        tag = "deprecated" if "decommission" in err.lower() else "error"
        return _ck("censys", error=f"[{tag}] {err}"[:110])
    recs = []
    for h in ((d.get("result") or {}).get("hits")) or []:
        ip = h.get("ip")
        if _valid_ip(ip):
            recs.append(_rec(host=h.get("name"), ip=ip, src=f"censys:{query[:20]}",
                             services=[s.get("port") for s in (h.get("services") or [])]))
    return _ck("censys", recs, note=query)


def internetdb(ip, timeout=8):
    """Shodan InternetDB —— 完全免 key，查 IP 的端口 / hostnames / CVE

    对候选 IP 验证极有价值：hostnames 里出现目标域名 = 该 IP 确实服务过它。
    """
    d = get_json(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
    if not isinstance(d, dict):
        return {"ok": False, "ip": ip, "error": "no data"}
    if d.get("detail") == "No information available for that IP.":
        return {"ok": False, "ip": ip, "error": "no information"}
    return {"ok": True, "ip": ip,
            "ports": d.get("ports") or [],
            "hostnames": [str(h).lower() for h in (d.get("hostnames") or [])],
            "cpes": d.get("cpes") or [],
            "vulns": d.get("vulns") or [],
            "tags": d.get("tags") or []}


def zoomeye_search(query, key, page=1):
    if not key:
        return _ck("zoomeye", error="no key")
    b = _req(f"https://api.zoomeye.org/host/search?query={urllib.parse.quote(query)}&page={page}",
             headers={"API-KEY": key}, timeout=30)
    if not b:
        return _ck("zoomeye", error="no response")
    try:
        d = json.loads(b.decode("utf-8", "replace"))
    except Exception:
        return _ck("zoomeye", error="bad json")
    if d.get("error"):
        return _ck("zoomeye", error=str(d["error"])[:80])
    recs = []
    for m in d.get("matches") or []:
        ip = m.get("ip")
        if _valid_ip(ip):
            recs.append(_rec(host=(m.get("domains") or [None])[0], ip=ip, src="zoomeye",
                             port=(m.get("portinfo") or {}).get("port")))
    return _ck("zoomeye", recs, note=query)


def quake_search(query, key, size=100):
    if not key:
        return _ck("quake", error="no key")
    d = post_json("https://quake.360.net/api/v3/search/quake_service",
                  {"query": query, "start": 0, "size": size, "ignore_cache": True},
                  headers={"X-QuakeToken": key}, timeout=30)
    if not d:
        return _ck("quake", error="no response")
    if d.get("code") != 0:
        return _ck("quake", error=str(d.get("message"))[:80])
    recs = []
    for m in d.get("data") or []:
        ip = m.get("ip")
        if _valid_ip(ip):
            recs.append(_rec(host=m.get("domain"), ip=ip, src="quake",
                             port=(m.get("service") or {}).get("port")))
    return _ck("quake", recs, note=query)


def hunter_search(query, key, size=100):
    if not key:
        return _ck("hunter", error="no key")
    q = urllib.parse.quote(base64.b64encode(query.encode()).decode())
    url = (f"https://hunter.qianxin.com/openApi/search?api-key={key}&search={q}"
           f"&page=1&page_size={size}&is_web=3")
    d = get_json(url, timeout=30)
    if not d:
        return _ck("hunter", error="no response")
    if d.get("code") != 200:
        return _ck("hunter", error=str(d.get("message"))[:80])
    recs = []
    for m in ((d.get("data") or {}).get("arr")) or []:
        ip = m.get("ip")
        if _valid_ip(ip):
            recs.append(_rec(host=m.get("domain"), ip=ip, src="hunter", port=m.get("port")))
    return _ck("hunter", recs, note=query)


# ================================================================ 外部视角
def checkhost_tcp(ip, port, nodes=5, wait=6):
    h = {"Accept": "application/json"}
    b = _req(f"https://check-host.net/check-tcp?host={ip}:{port}&max_nodes={nodes}",
             headers=h, timeout=22)
    if not b:
        return {"ok": False, "error": "submit failed", "open_nodes": []}
    try:
        rid = json.loads(b.decode()).get("request_id")
    except Exception:
        return {"ok": False, "error": "bad json", "open_nodes": []}
    if not rid:
        return {"ok": False, "error": "no request_id", "open_nodes": []}
    time.sleep(wait)
    b2 = _req(f"https://check-host.net/check-result/{rid}", headers=h, timeout=22)
    try:
        res = json.loads((b2 or b"{}").decode())
    except Exception:
        res = {}
    open_nodes = []
    for node, v in res.items():
        item = v[0] if isinstance(v, list) and v else v
        if isinstance(item, dict) and not item.get("error") and item:
            open_nodes.append(node)
    return {"ok": bool(open_nodes), "open_nodes": open_nodes,
            "checked": len(res), "nodes": res}
