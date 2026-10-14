import asyncio
import json

import httpx
import pytest

from cybermap_mcp.engines import EngineError, ThreatBook, VirusTotal
from tests.conftest import make_client


def run(coro):
    return asyncio.run(coro)


def test_threatbook_parses_reputation(monkeypatch):
    monkeypatch.setenv("THREATBOOK_KEY", "tbk")
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "response_code": 0,
            "data": {"9.9.9.9": {
                "severity": "high",
                "judgments": ["malicious"],
                "tags_classes": ["c2"],
                "basic": {"carrier": "电信",
                          "location": {"country": "中国", "province": "北京",
                                       "city": "北京"}},
                "confidence_level": "高",
                "update_time": "2026-10-01",
            }},
        })

    async def go():
        async with make_client(handler) as c:
            return await ThreatBook().ip_reputation(c, "9.9.9.9")

    rep = run(go())
    assert captured["body"] == {"apikey": "tbk", "resource": "9.9.9.9"}
    assert rep["severity"] == "high"
    assert rep["location"] == {"country": "中国", "province": "北京", "city": "北京"}
    assert rep["carrier"] == "电信"


def test_threatbook_error_raises(monkeypatch):
    monkeypatch.setenv("THREATBOOK_KEY", "tbk")

    def handler(request):
        return httpx.Response(200, json={"response_code": -1,
                                         "verbose_msg": "KEY错误"})

    async def go():
        async with make_client(handler) as c:
            await ThreatBook().ip_reputation(c, "9.9.9.9")

    with pytest.raises(EngineError, match="KEY错误"):
        run(go())


def test_virustotal_ip_uses_ip_endpoint(monkeypatch):
    monkeypatch.setenv("VT_KEY", "vtk")
    captured = {}

    def handler(request):
        captured["path"] = request.url.path
        captured["headers"] = request.headers
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 3},
            "reputation": -10, "country": "US", "as_owner": "GOOGLE",
            "network": "8.8.8.0/24", "tags": ["dns"],
        }}})

    async def go():
        async with make_client(handler) as c:
            return await VirusTotal().report(c, "8.8.8.8")

    rep = run(go())
    assert captured["path"] == "/api/v3/ip_addresses/8.8.8.8"
    assert captured["headers"]["x-apikey"] == "vtk"
    assert rep["last_analysis_stats"] == {"malicious": 3}
    assert rep["as_owner"] == "GOOGLE"


def test_virustotal_domain_uses_domains_endpoint(monkeypatch):
    monkeypatch.setenv("VT_KEY", "vtk")
    captured = {}

    def handler(request):
        captured["path"] = request.url.path
        return httpx.Response(200, json={"data": {"attributes":
                                                  {"reputation": 0}}})

    async def go():
        async with make_client(handler) as c:
            return await VirusTotal().report(c, "example.com")

    rep = run(go())
    assert captured["path"] == "/api/v3/domains/example.com"
    assert rep["reputation"] == 0
