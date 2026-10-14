import asyncio

import pytest

from cybermap_mcp import server
from cybermap_mcp.engines import (INTEL_ENGINES, SEARCH_ENGINES, Asset,
                                  EngineError)

ALL_ENV = ["FOFA_EMAIL", "FOFA_KEY", "HUNTER_KEY", "QUAKE_KEY", "SHODAN_KEY",
           "CENSYS_ID", "CENSYS_SECRET", "ZOOMEYE_KEY", "ZONE0_KEY",
           "DAYDAYMAP_KEY", "THREATBOOK_KEY", "VT_KEY"]


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for v in ALL_ENV:
        monkeypatch.delenv(v, raising=False)


def test_engine_status_lists_all_10_engines():
    rows = server.engine_status_impl()
    assert len(rows) == 10
    names = [r["engine"] for r in rows]
    assert names == ["fofa", "hunter", "quake", "shodan", "censys",
                     "zoomeye", "0zone", "daydaymap", "threatbook",
                     "virustotal"]
    assert all(r["configured"] is False for r in rows)
    assert all(r["env_vars"] for r in rows)


def test_map_search_no_keys_returns_hint():
    out = run(server.map_search_impl("x"))
    assert out["assets"] == []
    assert "no engine key configured" in out["hint"]["message"]
    assert len(out["hint"]["configure"]) == 8


def test_map_search_unknown_engine_raises():
    with pytest.raises(ValueError, match="unknown engine"):
        run(server.map_search_impl("x", engines=["nope"]))


def test_map_search_merges_and_isolates_errors(monkeypatch):
    monkeypatch.setenv("FOFA_EMAIL", "u@x.com")
    monkeypatch.setenv("FOFA_KEY", "k")
    monkeypatch.setenv("QUAKE_KEY", "qk")
    monkeypatch.setenv("HUNTER_KEY", "hk")

    fofa = next(e for e in SEARCH_ENGINES if e.name == "fofa")
    quake = next(e for e in SEARCH_ENGINES if e.name == "quake")
    hunter = next(e for e in SEARCH_ENGINES if e.name == "hunter")

    async def fofa_search(client, query, limit, page):
        return [Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
                      sources=["fofa"], title="T")]

    async def quake_search(client, query, limit, page):
        return [Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
                      sources=["quake"])]

    async def hunter_search(client, query, limit, page):
        raise EngineError("hunter", "积分不足")

    monkeypatch.setattr(fofa, "search", fofa_search)
    monkeypatch.setattr(quake, "search", quake_search)
    monkeypatch.setattr(hunter, "search", hunter_search)

    out = run(server.map_search_impl("x", engines=["fofa", "quake", "hunter"]))
    assert out["total_raw"] == 2 and out["total_dedup"] == 1
    assert out["assets"][0]["sources"] == ["fofa", "quake"]
    assert out["assets"][0]["title"] == "T"
    assert len(out["errors"]) == 1 and "积分不足" in out["errors"][0]


def test_map_search_query_dict_routes_per_engine(monkeypatch):
    monkeypatch.setenv("FOFA_EMAIL", "u@x.com")
    monkeypatch.setenv("FOFA_KEY", "k")
    monkeypatch.setenv("SHODAN_KEY", "sk")
    received = {}

    def fake_search(name):
        async def _s(client, query, limit, page):
            received[name] = query
            return [Asset(ip="1.1.1.1", port=80, sources=[name])]
        return _s

    for name in ("fofa", "shodan"):
        e = next(e for e in SEARCH_ENGINES if e.name == name)
        monkeypatch.setattr(e, "search", fake_search(name))

    out = run(server.map_search_impl(
        {"fofa": 'app="x"', "shodan": "product:x"}))
    assert received == {"fofa": 'app="x"', "shodan": "product:x"}
    assert out["total_raw"] == 2


def test_map_search_query_dict_unknown_engine_raises():
    with pytest.raises(ValueError, match="unknown engine"):
        run(server.map_search_impl({"nope": "x"}))


def test_map_search_query_dict_no_selected_match_raises():
    with pytest.raises(ValueError, match="no entry"):
        run(server.map_search_impl({"fofa": "x"}, engines=["quake"]))


def test_host_intel_ip_calls_both_engines(monkeypatch):
    monkeypatch.setenv("THREATBOOK_KEY", "tbk")
    monkeypatch.setenv("VT_KEY", "vtk")
    tb = next(e for e in INTEL_ENGINES if e.name == "threatbook")
    vt = next(e for e in INTEL_ENGINES if e.name == "virustotal")

    async def tb_rep(client, ip):
        return {"engine": "threatbook", "severity": "low"}

    async def vt_rep(client, target):
        return {"engine": "virustotal", "reputation": 0}

    monkeypatch.setattr(tb, "ip_reputation", tb_rep)
    monkeypatch.setattr(vt, "report", vt_rep)

    out = run(server.host_intel_impl("1.2.3.4"))
    assert set(out["intel"]) == {"threatbook", "virustotal"}
    assert out["errors"] == []


def test_host_intel_domain_calls_only_virustotal(monkeypatch):
    monkeypatch.setenv("THREATBOOK_KEY", "tbk")
    monkeypatch.setenv("VT_KEY", "vtk")
    tb = next(e for e in INTEL_ENGINES if e.name == "threatbook")
    vt = next(e for e in INTEL_ENGINES if e.name == "virustotal")
    calls = []

    async def tb_rep(client, ip):
        calls.append("tb")
        return {}

    async def vt_rep(client, target):
        calls.append("vt")
        return {"engine": "virustotal"}

    monkeypatch.setattr(tb, "ip_reputation", tb_rep)
    monkeypatch.setattr(vt, "report", vt_rep)

    out = run(server.host_intel_impl("example.com"))
    assert calls == ["vt"]
    assert set(out["intel"]) == {"virustotal"}


def test_host_intel_no_keys_reports_error():
    out = run(server.host_intel_impl("1.2.3.4"))
    assert out["intel"] == {}
    assert "no intel engine configured" in out["errors"][0]
