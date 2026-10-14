import asyncio
import base64
import json

import httpx
import pytest

from cybermap_mcp.engines import Censys, DayDayMap, EngineError, ZoomEye, Zone0
from tests.conftest import make_client


def run(coro):
    return asyncio.run(coro)


# ---- censys ----

def test_censys_basic_auth_and_service_expansion(monkeypatch):
    monkeypatch.setenv("CENSYS_ID", "cid")
    monkeypatch.setenv("CENSYS_SECRET", "csec")
    captured = {}

    def handler(request):
        captured["auth"] = request.headers.get("Authorization")
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"status": "OK", "result": {"hits": [{
            "ip": "5.5.5.5",
            "location": {"country": "US", "city": "LA"},
            "autonomous_system": {"name": "ASN1"},
            "services": [
                {"port": 443, "service_name": "HTTPS",
                 "transport_protocol": "TCP",
                 "software": [{"name": "nginx"}]},
                {"port": 22, "service_name": "SSH",
                 "transport_protocol": "TCP", "software": []},
            ],
        }]}})

    async def go():
        async with make_client(handler) as c:
            return await Censys().search(c, "services.service_name: HTTP", 999, 1)

    assets = run(go())
    assert captured["auth"] == "Basic " + base64.b64encode(b"cid:csec").decode()
    assert captured["params"]["per_page"] == "100"  # README: Censys <= 100
    assert len(assets) == 2  # 每个 service 一条资产
    assert (assets[0].port, assets[0].product, assets[0].protocol) == \
        (443, "nginx", "tcp")
    assert assets[1].product is None


def test_censys_error_status_raises(monkeypatch):
    monkeypatch.setenv("CENSYS_ID", "cid")
    monkeypatch.setenv("CENSYS_SECRET", "csec")

    def handler(request):
        return httpx.Response(200, json={"status": "Unauthorized",
                                         "error": "bad credentials"})

    async def go():
        async with make_client(handler) as c:
            await Censys().search(c, "x", 20, 1)

    with pytest.raises(EngineError, match="bad credentials"):
        run(go())


# ---- zoomeye ----

def test_zoomeye_parses_portinfo_and_list_title(monkeypatch):
    monkeypatch.setenv("ZOOMEYE_KEY", "zk")
    captured = {}

    def handler(request):
        captured["headers"] = request.headers
        return httpx.Response(200, json={"status": 200, "matches": [{
            "ip": "6.6.6.6", "hostname": "z.com", "domain": "z.com",
            "title": ["ZT"], "organization": "ZORG",
            "portinfo": {"port": 8080, "service": "http", "app": "Tomcat"},
            "geoinfo": {
                "country": {"names": {"zh-CN": "中国", "en": "China"}},
                "city": {"names": {"zh-CN": "杭州"}},
            },
        }]})

    async def go():
        async with make_client(handler) as c:
            return await ZoomEye().search(c, 'app:"Tomcat"', 20, 1)

    assets = run(go())
    assert captured["headers"]["API-KEY"] == "zk"
    a = assets[0]
    assert (a.title, a.port, a.product, a.country, a.city) == \
        ("ZT", 8080, "Tomcat", "中国", "杭州")


def test_zoomeye_error_status_raises(monkeypatch):
    monkeypatch.setenv("ZOOMEYE_KEY", "zk")

    def handler(request):
        return httpx.Response(200, json={"status": 401, "message": "invalid key"})

    async def go():
        async with make_client(handler) as c:
            await ZoomEye().search(c, "x", 20, 1)

    with pytest.raises(EngineError, match="invalid key"):
        run(go())


# ---- 0.zone ----

def test_zone0_post_body_and_clamp(monkeypatch):
    monkeypatch.setenv("ZONE0_KEY", "zk0")
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"code": 0, "data": [{
            "ip": "7.7.7.7", "port": 80, "url": "http://z0.com",
            "title": "Z0", "service": "http", "group": "某公司", "city": "深圳",
        }]})

    async def go():
        async with make_client(handler) as c:
            return await Zone0().search(c, "(company=某公司)", 999, 1)

    assets = run(go())
    body = captured["body"]
    assert body["zone_key_id"] == "zk0"
    assert body["query_type"] == "site"
    assert body["pagesize"] == 40  # README: 0.zone 单页 <= 40
    a = assets[0]
    assert (a.ip, a.org, a.title) == ("7.7.7.7", "某公司", "Z0")


def test_zone0_error_code_raises(monkeypatch):
    monkeypatch.setenv("ZONE0_KEY", "zk0")

    def handler(request):
        return httpx.Response(200, json={"code": 400, "message": " 余额不足 "})

    async def go():
        async with make_client(handler) as c:
            await Zone0().search(c, "x", 20, 1)

    with pytest.raises(EngineError, match="余额不足"):
        run(go())


# ---- daydaymap ----

def test_daydaymap_header_and_b64_keyword(monkeypatch):
    monkeypatch.setenv("DAYDAYMAP_KEY", "ddk")
    captured = {}

    def handler(request):
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"code": 200, "data": {"data": [{
            "ip": "8.8.8.8", "port": 443, "host": "dd.com", "domain": "dd.com",
            "title": "DD", "protocol": "https", "asn_org": "DORG",
            "country": "中国", "city": "广州",
        }]}})

    async def go():
        async with make_client(handler) as c:
            return await DayDayMap().search(c, 'domain="dd.com"', 20, 3)

    assets = run(go())
    assert captured["headers"]["api-key"] == "ddk"
    body = captured["body"]
    assert base64.b64decode(body["keyword"]).decode() == 'domain="dd.com"'
    assert body["page"] == 3 and body["page_size"] == 20
    a = assets[0]
    assert (a.ip, a.port, a.service, a.protocol) == ("8.8.8.8", 443, "https", "https")


def test_daydaymap_error_code_raises(monkeypatch):
    monkeypatch.setenv("DAYDAYMAP_KEY", "ddk")

    def handler(request):
        return httpx.Response(200, json={"code": 500, "msg": "auth failed"})

    async def go():
        async with make_client(handler) as c:
            await DayDayMap().search(c, "x", 20, 1)

    with pytest.raises(EngineError, match="auth failed"):
        run(go())
