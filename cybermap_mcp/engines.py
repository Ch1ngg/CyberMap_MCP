"""Engine adapters for 10 cyberspace mapping / threat-intel platforms.

Each adapter normalizes platform responses into a unified `Asset` schema.
All async methods take an `httpx.AsyncClient` so callers control timeouts
and connection reuse.

API endpoints verified against official docs (2026-10):
  Fofa       GET  https://fofa.info/api/v1/search/all
  Hunter     GET  https://hunter.qianxin.com/openApi/search
  Quake      POST https://quake.360.net/api/v3/search/quake_service
  Shodan     GET  https://api.shodan.io/shodan/host/search
  Censys     GET  https://search.censys.io/api/v2/hosts/search
  ZoomEye    GET  https://api.zoomeye.org/host/search
  0.zone     POST https://0.zone/api/data/
  DayDayMap  POST https://www.daydaymap.com/api/v1/raymap/search/all
  ThreatBook POST https://api.threatbook.cn/v3/scene/ip_reputation
  VirusTotal GET  https://www.virustotal.com/api/v3/ip_addresses|domains/{id}
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field

import httpx


class EngineError(Exception):
    """Raised on auth/config/API failures; message is model-readable."""

    def __init__(self, engine: str, message: str):
        super().__init__(f"[{engine}] {message}")
        self.engine = engine


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


@dataclass
class Asset:
    """Unified asset record across engines."""

    ip: str | None = None
    port: int | None = None
    host: str | None = None
    domain: str | None = None
    url: str | None = None
    title: str | None = None
    service: str | None = None
    product: str | None = None
    protocol: str | None = None
    org: str | None = None
    country: str | None = None
    city: str | None = None
    sources: list[str] = field(default_factory=list)

    def dedup_key(self) -> tuple | None:
        if not (self.ip or self.host or self.domain):
            return None
        return (self.ip, self.port, self.host or self.domain, self.protocol)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [])}


def merge_assets(assets: list[Asset]) -> list[Asset]:
    """Dedup by (ip, port, host/domain, protocol); merge `sources`."""
    merged: dict[tuple, Asset] = {}
    tail: list[Asset] = []
    for a in assets:
        k = a.dedup_key()
        if k is None:
            tail.append(a)
            continue
        if k in merged:
            m = merged[k]
            for s in a.sources:
                if s not in m.sources:
                    m.sources.append(s)
            for f in ("ip", "port", "host", "domain", "url", "title",
                      "service", "product", "protocol", "org", "country", "city"):
                if getattr(m, f) is None and getattr(a, f) is not None:
                    setattr(m, f, getattr(a, f))
        else:
            merged[k] = a
    return list(merged.values()) + tail


class Engine:
    name: str = ""
    env_vars: tuple[str, ...] = ()
    api_doc: str = ""

    def key(self, var: str) -> str:
        return os.environ.get(var, "").strip()

    @property
    def configured(self) -> bool:
        return all(self.key(v) for v in self.env_vars)

    def require(self) -> None:
        if not self.configured:
            raise EngineError(
                self.name,
                f"missing key(s): {', '.join(self.env_vars)}; see {self.api_doc}",
            )

    def _asset(self, **kw) -> Asset:
        kw["sources"] = [self.name]
        return Asset(**kw)

    async def search(self, client: httpx.AsyncClient, query: str,
                     limit: int, page: int) -> list[Asset]:
        raise NotImplementedError(f"{self.name}: search not supported")


# ---------------------------------------------------------------- search --


class Fofa(Engine):
    name = "fofa"
    env_vars = ("FOFA_EMAIL", "FOFA_KEY")
    api_doc = "https://fofa.info/userInfo"
    _fields = "ip,host,port,title,domain,server,protocol,country_name,city,as_organization"

    async def search(self, client, query, limit, page):
        self.require()
        r = await client.get(
            "https://fofa.info/api/v1/search/all",
            params={
                "email": self.key("FOFA_EMAIL"),
                "key": self.key("FOFA_KEY"),
                "qbase64": b64(query),
                "size": max(1, min(limit, 10000)),
                "page": page,
                "fields": self._fields,
            },
        )
        r.raise_for_status()
        data = r.json()
        if data.get("error"):
            raise EngineError(self.name, str(data.get("errmsg")))
        cols = self._fields.split(",")
        out: list[Asset] = []
        for row in data.get("results") or []:
            v = dict(zip(cols, row))
            host = v.get("host") or None
            out.append(self._asset(
                ip=v.get("ip") or None,
                port=int(v["port"]) if v.get("port") else None,
                host=host,
                domain=v.get("domain") or None,
                url=host if host and "://" in host else None,
                title=v.get("title") or None,
                service=v.get("server") or None,
                protocol=v.get("protocol") or None,
                org=v.get("as_organization") or None,
                country=v.get("country_name") or None,
                city=v.get("city") or None,
            ))
        return out


class Hunter(Engine):
    name = "hunter"
    env_vars = ("HUNTER_KEY",)
    api_doc = "https://hunter.qianxin.com/home/personalInfo?to=api"

    async def search(self, client, query, limit, page):
        self.require()
        r = await client.get(
            "https://hunter.qianxin.com/openApi/search",
            params={
                "api-key": self.key("HUNTER_KEY"),
                "search": b64(query),
                "page": page,
                "page_size": max(1, min(limit, 100)),
                "is_web": 3,
            },
        )
        r.raise_for_status()
        data = r.json()
        if data.get("code") != 200:
            raise EngineError(self.name, str(data.get("message")))
        d = data.get("data") or {}
        items = d.get("arr") or d.get("result_arr") or []
        out: list[Asset] = []
        for e in items:
            wt = e.get("web_title") or {}
            out.append(self._asset(
                ip=e.get("ip") or None,
                port=int(e["port"]) if e.get("port") else None,
                domain=e.get("domain") or None,
                url=e.get("url") or None,
                title=(wt.get("title") if isinstance(wt, dict) else wt) or e.get("title"),
                service=e.get("server") or None,
                protocol=e.get("protocol") or None,
                org=e.get("company") or e.get("as_org") or None,
                country=e.get("country") or None,
                city=e.get("city") or None,
            ))
        return out


class Quake(Engine):
    name = "quake"
    env_vars = ("QUAKE_KEY",)
    api_doc = "https://quake.360.net/quake/#/personal?tab=message"
    _include = [
        "ip", "port", "transport", "hostname", "domain", "org",
        "service.name", "service.product", "service.http.host",
        "service.http.title", "location.country_cn", "location.city_cn",
    ]

    async def search(self, client, query, limit, page):
        self.require()
        size = max(1, min(limit, 5000))
        r = await client.post(
            "https://quake.360.net/api/v3/search/quake_service",
            headers={"X-QuakeToken": self.key("QUAKE_KEY")},
            json={
                "query": query,
                "start": (page - 1) * size,
                "size": size,
                "include": self._include,
            },
        )
        r.raise_for_status()
        data = r.json()
        if data.get("code") != 0:
            raise EngineError(self.name, str(data.get("message")))
        out: list[Asset] = []
        for e in data.get("data") or []:
            svc = e.get("service") or {}
            http = svc.get("http") or {}
            loc = e.get("location") or {}
            out.append(self._asset(
                ip=e.get("ip") or None,
                port=int(e["port"]) if e.get("port") else None,
                host=http.get("host") or e.get("hostname") or None,
                domain=e.get("domain") or None,
                title=http.get("title") or None,
                service=svc.get("name") or None,
                product=svc.get("product") or None,
                protocol=e.get("transport") or None,
                org=e.get("org") or None,
                country=loc.get("country_cn") or None,
                city=loc.get("city_cn") or None,
            ))
        return out


class Shodan(Engine):
    name = "shodan"
    env_vars = ("SHODAN_KEY",)
    api_doc = "https://account.shodan.io/"

    async def search(self, client, query, limit, page):
        self.require()
        r = await client.get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key": self.key("SHODAN_KEY"),
                "query": query,
                "page": page,
            },
        )
        r.raise_for_status()
        data = r.json()
        out: list[Asset] = []
        for m in data.get("matches") or []:
            http = m.get("http") or {}
            loc = m.get("location") or {}
            hostnames = m.get("hostnames") or []
            out.append(self._asset(
                ip=m.get("ip_str") or None,
                port=m.get("port"),
                host=hostnames[0] if hostnames else None,
                domain=hostnames[0] if hostnames else None,
                title=http.get("title") or None,
                service=(m.get("data") or "")[:200] or None,
                product=m.get("product") or None,
                protocol=m.get("transport") or None,
                org=m.get("org") or None,
                country=loc.get("country_name") or None,
                city=loc.get("city") or None,
            ))
        return out


class Censys(Engine):
    name = "censys"
    env_vars = ("CENSYS_ID", "CENSYS_SECRET")
    api_doc = "https://search.censys.io/account/api"

    async def search(self, client, query, limit, page):
        self.require()
        auth = (self.key("CENSYS_ID"), self.key("CENSYS_SECRET"))
        r = await client.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": query, "per_page": max(1, min(limit, 100)),
                    "virtual_hosts": "EXCLUDE"},
            auth=auth,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "OK":
            raise EngineError(self.name, str(data.get("error") or data.get("status")))
        out: list[Asset] = []
        for h in (data.get("result") or {}).get("hits") or []:
            loc = h.get("location") or {}
            asn = h.get("autonomous_system") or {}
            for svc in h.get("services") or []:
                software = svc.get("software") or []
                out.append(self._asset(
                    ip=h.get("ip") or None,
                    port=svc.get("port"),
                    service=svc.get("service_name") or None,
                    product=software[0].get("name") if software else None,
                    protocol="tcp" if svc.get("transport_protocol") == "TCP" else
                             (svc.get("transport_protocol") or None),
                    org=asn.get("name") or None,
                    country=loc.get("country") or None,
                    city=loc.get("city") or None,
                ))
        return out


class ZoomEye(Engine):
    name = "zoomeye"
    env_vars = ("ZOOMEYE_KEY",)
    api_doc = "https://www.zoomeye.org/profile"

    async def search(self, client, query, limit, page):
        self.require()
        r = await client.get(
            "https://api.zoomeye.org/host/search",
            params={"query": query, "page": page},
            headers={"API-KEY": self.key("ZOOMEYE_KEY")},
        )
        r.raise_for_status()
        data = r.json()
        if data.get("status") != 200:
            raise EngineError(self.name, str(data.get("message") or data.get("status")))
        out: list[Asset] = []
        for m in data.get("matches") or []:
            pi = m.get("portinfo") or {}
            geo = m.get("geoinfo") or {}
            title = m.get("title")
            if isinstance(title, list):
                title = title[0] if title else None
            cn = ((geo.get("country") or {}).get("names") or {}).get("zh-CN") \
                or ((geo.get("country") or {}).get("names") or {}).get("en")
            city = ((geo.get("city") or {}).get("names") or {}).get("zh-CN") \
                or ((geo.get("city") or {}).get("names") or {}).get("en")
            out.append(self._asset(
                ip=m.get("ip") or None,
                port=pi.get("port"),
                host=m.get("hostname") or None,
                domain=m.get("domain") or None,
                title=title,
                service=pi.get("service") or None,
                product=pi.get("app") or None,
                protocol="tcp",
                org=m.get("organization") or (geo.get("organization") or None),
                country=cn,
                city=city,
            ))
        return out


class Zone0(Engine):
    """零零信安 0.zone 暴露面搜索。query 用其自有语法，如
    `(company=xxx有限公司)||(title=xxx)`，query_type 默认 site（信息系统）。"""

    name = "0zone"
    env_vars = ("ZONE0_KEY",)
    api_doc = "https://0.zone/apply"

    def __init__(self, query_type: str = "site"):
        self.query_type = query_type

    async def search(self, client, query, limit, page):
        self.require()
        r = await client.post(
            "https://0.zone/api/data/",
            json={
                "query": query,
                "query_type": self.query_type,
                "page": page,
                "pagesize": max(1, min(limit, 40)),
                "zone_key_id": self.key("ZONE0_KEY"),
            },
        )
        r.raise_for_status()
        data = r.json()
        if data.get("code") != 0:
            raise EngineError(self.name, str(data.get("message")).strip())
        out: list[Asset] = []
        for e in data.get("data") or []:
            out.append(self._asset(
                ip=e.get("ip") or None,
                port=int(e["port"]) if e.get("port") else None,
                url=e.get("url") or None,
                title=e.get("title") or None,
                service=e.get("service") or None,
                org=e.get("group") or None,
                city=e.get("city") or None,
            ))
        return out


class DayDayMap(Engine):
    name = "daydaymap"
    env_vars = ("DAYDAYMAP_KEY",)
    api_doc = "https://www.daydaymap.com/help/document?type=api-auth"

    async def search(self, client, query, limit, page):
        self.require()
        r = await client.post(
            "https://www.daydaymap.com/api/v1/raymap/search/all",
            headers={"api-key": self.key("DAYDAYMAP_KEY")},
            json={
                "page": page,
                "page_size": max(1, min(limit, 100)),
                "keyword": b64(query),
            },
        )
        r.raise_for_status()
        data = r.json()
        code = data.get("code")
        if code not in (None, 200):
            raise EngineError(self.name,
                              f"code {code}: {data.get('msg') or data.get('message')}")
        body = data.get("data") or {}
        items = body.get("data") or body.get("results") or body.get("list") or []
        out: list[Asset] = []
        for e in items:
            out.append(self._asset(
                ip=e.get("ip") or None,
                port=int(e["port"]) if e.get("port") else None,
                host=e.get("host") or None,
                domain=e.get("domain") or None,
                title=e.get("title") or None,
                service=e.get("protocol") or e.get("service") or None,
                protocol=e.get("protocol") or None,
                org=e.get("asn_org") or e.get("isp") or None,
                country=e.get("country") or None,
                city=e.get("city") or None,
            ))
        return out


# ------------------------------------------------------------- intel-only --

class ThreatBook(Engine):
    """微步在线 IP 信誉/情报查询（不参与全量资产搜索）。"""

    name = "threatbook"
    env_vars = ("THREATBOOK_KEY",)
    api_doc = "https://x.threatbook.com/v5/myApi"

    async def ip_reputation(self, client: httpx.AsyncClient, ip: str) -> dict:
        self.require()
        r = await client.post(
            "https://api.threatbook.cn/v3/scene/ip_reputation",
            json={"apikey": self.key("THREATBOOK_KEY"), "resource": ip},
        )
        r.raise_for_status()
        data = r.json()
        if data.get("response_code") != 0:
            raise EngineError(self.name, str(data.get("verbose_msg")))
        rep = (data.get("data") or {}).get(ip) or {}
        basic = rep.get("basic") or {}
        loc = basic.get("location") or {}
        return {
            "engine": self.name,
            "ip": ip,
            "severity": rep.get("severity"),
            "judgments": rep.get("judgments"),
            "tags_classes": rep.get("tags_classes"),
            "location": {k: loc.get(k) for k in ("country", "province", "city") if loc.get(k)},
            "carrier": basic.get("carrier"),
            "confidence": rep.get("confidence_level"),
            "update_time": rep.get("update_time"),
        }


class VirusTotal(Engine):
    name = "virustotal"
    env_vars = ("VT_KEY",)
    api_doc = "https://www.virustotal.com/gui/user/<user>/apikey"

    async def report(self, client: httpx.AsyncClient, target: str) -> dict:
        self.require()
        import ipaddress as _ip
        kind = "ip_addresses"
        try:
            _ip.ip_address(target)
        except ValueError:
            kind = "domains"
        r = await client.get(
            f"https://www.virustotal.com/api/v3/{kind}/{target}",
            headers={"x-apikey": self.key("VT_KEY")},
        )
        r.raise_for_status()
        attrs = ((r.json().get("data") or {}).get("attributes")) or {}
        return {
            "engine": self.name,
            "target": target,
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "reputation": attrs.get("reputation"),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "network": attrs.get("network"),
            "tags": attrs.get("tags"),
            "crowdsourced_tags": attrs.get("crowdsourced_context"),
        }


SEARCH_ENGINES: list[Engine] = [
    Fofa(), Hunter(), Quake(), Shodan(), Censys(),
    ZoomEye(), Zone0(), DayDayMap(),
]
INTEL_ENGINES: list[Engine] = [ThreatBook(), VirusTotal()]
