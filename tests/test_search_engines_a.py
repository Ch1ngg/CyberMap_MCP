import asyncio
import base64
import json

import httpx
import pytest

from cybermap_mcp.engines import EngineError, Fofa, Hunter, Quake, Shodan
from tests.conftest import make_client


def run(coro):
    return asyncio.run(coro)


# ---- fofa ----

def test_fofa_parses_results_and_sends_auth(monkeypatch):
    monkeypatch.setenv("FOFA_EMAIL", "u@x.com")
    monkeypatch.setenv("FOFA_KEY", "secret")
    captured = {}

    def handler(request):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"error": False, "results": [[
            "1.2.3.4", "http://1.2.3.4:8080/", "8080", "Tomcat", "d.com",
            "nginx", "http", "China", "Beijing", "ACME",
        ]]})

    async def go():
        async with make_client(handler) as c:
            return await Fofa().search(c, 'app="Tomcat"', 20, 1)

    assets = run(go())
    p = captured["params"]
    assert p["email"] == "u@x.com" and p["key"] == "secret"
    assert base64.b64decode(p["qbase64"]).decode() == 'app="Tomcat"'
    a = assets[0]
    assert (a.ip, a.port, a.title, a.protocol, a.country) == \
        ("1.2.3.4", 8080, "Tomcat", "http", "China")
    assert a.url == "http://1.2.3.4:8080/"
    assert a.sources == ["fofa"]


def test_fofa_api_error_raises_engine_error(monkeypatch):
    monkeypatch.setenv("FOFA_EMAIL", "u@x.com")
    monkeypatch.setenv("FOFA_KEY", "bad")

    def handler(request):
        return httpx.Response(200, json={"error": True, "errmsg": "Invalid key"})

    async def go():
        async with make_client(handler) as c:
            await Fofa().search(c, "x", 20, 1)

    with pytest.raises(EngineError, match="Invalid key"):
        run(go())


def test_engine_not_configured_raises(monkeypatch):
    monkeypatch.delenv("FOFA_EMAIL", raising=False)
    monkeypatch.delenv("FOFA_KEY", raising=False)

    async def go():
        async with make_client(lambda r: httpx.Response(200, json={})) as c:
            await Fofa().search(c, "x", 20, 1)

    with pytest.raises(EngineError, match="missing key"):
        run(go())


# ---- hunter ----

def test_hunter_parses_and_clamps_page_size(monkeypatch):
    monkeypatch.setenv("HUNTER_KEY", "hk")
    captured = {}

    def handler(request):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"code": 200, "data": {"arr": [{
            "ip": "2.2.2.2", "port": 443, "domain": "h.com",
            "url": "https://h.com", "web_title": {"title": "H"},
            "server": "nginx", "protocol": "https", "company": "C",
            "country": "中国", "city": "北京",
        }]}})

    async def go():
        async with make_client(handler) as c:
            return await Hunter().search(c, 'app="x"', 9999, 2)

    assets = run(go())
    p = captured["params"]
    assert p["api-key"] == "hk"
    assert base64.b64decode(p["search"]).decode() == 'app="x"'
    assert p["page_size"] == "100"  # README: Hunter page_size <= 100
    assert p["page"] == "2"
    a = assets[0]
    assert (a.ip, a.port, a.title, a.protocol) == ("2.2.2.2", 443, "H", "https")


def test_hunter_non_200_code_raises(monkeypatch):
    monkeypatch.setenv("HUNTER_KEY", "hk")

    def handler(request):
        return httpx.Response(200, json={"code": 401, "message": "积分不足"})

    async def go():
        async with make_client(handler) as c:
            await Hunter().search(c, "x", 20, 1)

    with pytest.raises(EngineError, match="积分不足"):
        run(go())


def test_hunter_rounds_up_page_size_and_slices_to_limit(monkeypatch):
    """Hunter rejects page_size outside {1,10,20,50,100} (400 页大小不合法)."""
    monkeypatch.setenv("HUNTER_KEY", "hk")
    captured = {}

    def handler(request):
        captured["params"] = dict(request.url.params)
        rows = [{"ip": f"10.0.0.{i}", "port": 80} for i in range(10)]
        return httpx.Response(200, json={"code": 200, "data": {"arr": rows}})

    async def go():
        async with make_client(handler) as c:
            return await Hunter().search(c, "x", 5, 1)

    assets = run(go())
    assert captured["params"]["page_size"] == "10"
    assert len(assets) == 5


# ---- quake ----

def test_quake_parses_nested_and_uses_clamped_start(monkeypatch):
    monkeypatch.setenv("QUAKE_KEY", "qk")
    captured = {}

    def handler(request):
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"code": 0, "data": [{
            "ip": "3.3.3.3", "port": 80, "transport": "tcp",
            "hostname": "q.com", "domain": "q.com", "org": "QORG",
            "service": {"name": "http", "product": "nginx",
                        "http": {"host": "q.com", "title": "QT"}},
            "location": {"country_cn": "中国", "city_cn": "上海"},
        }]})

    async def go():
        async with make_client(handler) as c:
            return await Quake().search(c, 'app:"x"', 99999, 2)

    assets = run(go())
    assert captured["headers"]["X-QuakeToken"] == "qk"
    body = captured["body"]
    assert body["size"] == 5000
    assert body["start"] == 5000  # (page-1) * clamped size, NOT (page-1) * 99999
    a = assets[0]
    assert (a.ip, a.port, a.title, a.product, a.city) == \
        ("3.3.3.3", 80, "QT", "nginx", "上海")


def test_quake_error_code_raises(monkeypatch):
    monkeypatch.setenv("QUAKE_KEY", "qk")

    def handler(request):
        return httpx.Response(200, json={"code": 500, "message": "invalid token"})

    async def go():
        async with make_client(handler) as c:
            await Quake().search(c, "x", 20, 1)

    with pytest.raises(EngineError, match="invalid token"):
        run(go())


# ---- shodan ----

def test_shodan_parses_matches_and_truncates_banner(monkeypatch):
    monkeypatch.setenv("SHODAN_KEY", "sk")
    captured = {}
    banner = "B" * 500

    def handler(request):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"matches": [{
            "ip_str": "4.4.4.4", "port": 22, "hostnames": ["s.com"],
            "data": banner, "product": "OpenSSH", "transport": "tcp",
            "org": "SORG", "http": {},
            "location": {"country_name": "US", "city": "NYC"},
        }]})

    async def go():
        async with make_client(handler) as c:
            return await Shodan().search(c, "port:22", 20, 1)

    assets = run(go())
    assert captured["params"]["key"] == "sk"
    assert captured["params"]["query"] == "port:22"
    a = assets[0]
    assert a.host == "s.com" and a.domain == "s.com"
    assert a.service is not None and len(a.service) <= 200
    assert (a.product, a.org, a.city) == ("OpenSSH", "SORG", "NYC")
