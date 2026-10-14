# CyberMap MCP 验证与加固实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为已存在的 CyberMap MCP 实现补齐自动化验证（mock 级单元测试 + 真实 smoke），并修复验证中暴露的 3 个已知缺陷。

**Architecture:** 代码已完整（`cybermap_mcp/engines.py` 10 个引擎适配器，`cybermap_mcp/server.py` 3 个 MCP 工具），本计划不重写功能，只为每个适配器建立 `httpx.MockTransport` 级别的请求/响应解析与错误路径测试，再用真实 API key 做一次端到端 smoke。

**Tech Stack:** Python ≥3.10, httpx, mcp[cli], pytest（无 pytest-asyncio，统一 `asyncio.run` 驱动协程）。

**Spec:** `README.md`（引擎清单、环境变量表、工具签名、配额约束以此为准）

## Global Constraints

- 不新增运行时依赖；测试仅加 `pytest` 到 dev extras。
- 测试一律用 `httpx.MockTransport`，禁止真实网络访问（Task 7 的 smoke 除外）。
- 引擎名、环境变量名必须与 README 表逐字一致：`FOFA_EMAIL, FOFA_KEY, HUNTER_KEY, QUAKE_KEY, SHODAN_KEY, CENSYS_ID, CENSYS_SECRET, ZOOMEYE_KEY, ZONE0_KEY, DAYDAYMAP_KEY, THREATBOOK_KEY, VT_KEY`。
- 每个测试函数用 `monkeypatch.setenv/delenv` 隔离环境变量，禁止污染真实环境。
- 配额钳制保持 README 声明值：Hunter page_size ≤ 100，0.zone pagesize ≤ 40，Censys per_page ≤ 100。

## Review Focus

1. **Shodan `service` 字段塞整条 banner**（`m.get("data")`，可达数 KB，污染聚合输出）→ Task 3 修复为截断 200 字符并用测试钉死。
2. **Quake `start` 用未钳制的 `limit` 计算**（`size` 钳到 ≤5000 但 `start=(page-1)*limit`）→ 第 2 页起分页错位；Task 3 修复为先钳制再算 start，测试钉死。
3. **`merge_assets` 合并时丢弃后到的非 sources 字段**（fofa 无 title、quake 有 title 时 title 丢失）→ Task 2 修复为空字段回填合并，测试钉死。
4. **引擎 API 响应结构漂移**（README 写"API endpoints verified 2026-10"，但无测试证明解析正确）→ Task 3/4/5 每个适配器的解析测试即防漂移契约。
5. **README 声明与实现漂移**（入口点、env 表、配额）→ Task 7 smoke 逐项核对。

---
### Task 1: 测试脚手架

**Files:**
- Modify: `pyproject.toml`（加 dev extras 与 pytest 配置）
- Create: `tests/__init__.py`（空文件）
- Create: `tests/conftest.py`

**Interfaces:**
- Produces: `make_client(handler) -> httpx.AsyncClient`（tests/conftest.py 中的模块级函数，所有后续任务直接 import 使用，不是 fixture）；dev 依赖 `pytest>=8`。

- [ ] **Step 1: pyproject 加 dev extras 与 pytest 配置**

```toml
[project.optional-dependencies]
dev = ["pytest>=8"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: 写 conftest.py**

```python
# tests/conftest.py
"""Shared test helpers. Engine adapters take an httpx.AsyncClient, so tests
inject httpx.MockTransport — no real network, no extra deps."""
import httpx


def make_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))
```

```bash
touch tests/__init__.py
```

- [ ] **Step 3: 验证 pytest 可运行**

Run: `pip install -e '.[dev]' && pytest -q`
Expected: `no tests ran`（退出码 5，属正常）

- [ ] **Step 4: Commit**（若目录非 git 仓库先 `git init`）

```bash
git add pyproject.toml tests/
git commit -m "test: pytest scaffold with MockTransport helper"
```

---

### Task 2: Asset / merge_assets 核心逻辑 + 空字段回填修复

**Files:**
- Modify: `cybermap_mcp/engines.py`（`merge_assets` 函数）
- Test: `tests/test_merge.py`

**Interfaces:**
- Consumes: 现有 `Asset`、`Asset.dedup_key()`、`Asset.as_dict()`。
- Produces: `merge_assets` 新行为——同 key 合并时除 `sources` 外，先到资产为 None 的字段用后到资产的非 None 值回填；`sources` 仍按出现顺序去重追加。

- [ ] **Step 1: 写失败测试**

```python
# tests/test_merge.py
from cybermap_mcp.engines import Asset, merge_assets


def test_dedup_key_host_or_domain():
    assert Asset(ip="1.1.1.1", port=80, domain="d.com").dedup_key() == \
        ("1.1.1.1", 80, "d.com", None)
    assert Asset().dedup_key() is None


def test_as_dict_omits_none_and_empty():
    d = Asset(ip="1.1.1.1", sources=["fofa"]).as_dict()
    assert d == {"ip": "1.1.1.1", "sources": ["fofa"]}


def test_merge_dedups_and_merges_sources():
    a1 = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
               sources=["fofa"], title="first")
    a2 = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
               sources=["quake"])
    merged = merge_assets([a1, a2])
    assert len(merged) == 1
    assert merged[0].sources == ["fofa", "quake"]
    assert merged[0].title == "first"


def test_merge_backfills_empty_fields_from_later_asset():
    sparse = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
                   sources=["fofa"])
    rich = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
                 sources=["quake"], title="Tomcat", org="ACME")
    merged = merge_assets([sparse, rich])
    assert merged[0].title == "Tomcat"
    assert merged[0].org == "ACME"


def test_merge_does_not_overwrite_existing_fields():
    a1 = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
               sources=["fofa"], title="first")
    a2 = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
               sources=["quake"], title="second")
    assert merge_assets([a1, a2])[0].title == "first"


def test_merge_keeps_unkeyable_records_in_order():
    a = Asset(title="no identifiers", sources=["0zone"])
    b = Asset(url="http://x", sources=["0zone"])
    assert merge_assets([a, b]) == [a, b]
```

- [ ] **Step 2: 跑测试确认失败**

Run: `pytest tests/test_merge.py -q`
Expected: `test_merge_backfills_empty_fields_from_later_asset` FAIL（其余通过）

- [ ] **Step 3: 修改 merge_assets 实现回填**

`cybermap_mcp/engines.py` 中 `merge_assets` 的合并分支改为：

```python
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
```

- [ ] **Step 4: 跑测试确认通过**

Run: `pytest tests/test_merge.py -q`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add cybermap_mcp/engines.py tests/test_merge.py
git commit -m "fix: merge_assets backfills empty fields from later duplicates"
```

---
### Task 3: 搜索适配器测试 A（fofa / hunter / quake / shodan）+ Shodan banner 截断 + Quake start 修复

**Files:**
- Modify: `cybermap_mcp/engines.py`（`Shodan.search`、`Quake.search`）
- Test: `tests/test_search_engines_a.py`

**Interfaces:**
- Consumes: `tests/conftest.py: make_client(handler)`；各引擎 `search(client, query, limit, page) -> list[Asset]`。
- Produces: Shodan `service` 字段 = banner 前 200 字符（截断行为）；Quake 请求体 `start = (page-1) * min(limit, 5000)`。

- [ ] **Step 1: 写失败测试**

```python
# tests/test_search_engines_a.py
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
```

- [ ] **Step 2: 跑测试确认失败**

Run: `pytest tests/test_search_engines_a.py -q`
Expected: `test_shodan_parses_matches_and_truncates_banner` FAIL（service 为 500 字符）；`test_quake_parses_nested_and_uses_clamped_start` FAIL（start=99999）；fofa/hunter 测试通过。

- [ ] **Step 3: 修 Shodan banner 截断**

`cybermap_mcp/engines.py` `Shodan.search` 中：

```python
                service=(m.get("data") or "")[:200] or None,
```

替换原 `service=m.get("data") or None,`。

- [ ] **Step 4: 修 Quake start 钳制**

`cybermap_mcp/engines.py` `Quake.search` 中请求体改为：

```python
            size = max(1, min(limit, 5000))
            json={
                "query": query,
                "start": (page - 1) * size,
                "size": size,
                "include": self._include,
            },
```

（方法签名处先算 `size`，json dict 引用它。）

- [ ] **Step 5: 跑测试确认通过**

Run: `pytest tests/test_search_engines_a.py -q`
Expected: 8 passed

- [ ] **Step 6: Commit**

```bash
git add cybermap_mcp/engines.py tests/test_search_engines_a.py
git commit -m "fix: clamp Quake start to clamped size; truncate Shodan banner; adapter tests"
```

---
### Task 4: 搜索适配器测试 B（censys / zoomeye / 0zone / daydaymap）

**Files:**
- Test: `tests/test_search_engines_b.py`

**Interfaces:**
- Consumes: `tests/conftest.py: make_client`；`Censys/ZoomEye/Zone0/DayDayMap.search`。
- Produces: 无新接口；纯契约测试。

- [ ] **Step 1: 写测试（预期全通过；任何失败即发现解析漂移，先修代码再勾选）**

```python
# tests/test_search_engines_b.py
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
```

- [ ] **Step 2: 跑测试**

Run: `pytest tests/test_search_engines_b.py -q`
Expected: 8 passed。若某个解析断言失败，说明该引擎响应结构处理有漂移：按 mock 中依据官方文档构造的结构修正 `engines.py` 对应适配器，再重跑。

- [ ] **Step 3: Commit**

```bash
git add tests/test_search_engines_b.py
git commit -m "test: censys/zoomeye/0zone/daydaymap adapter contract tests"
```

---
### Task 5: 情报适配器测试（threatbook / virustotal）

**Files:**
- Test: `tests/test_intel_engines.py`

**Interfaces:**
- Consumes: `make_client`；`ThreatBook.ip_reputation(client, ip) -> dict`；`VirusTotal.report(client, target) -> dict`。

- [ ] **Step 1: 写测试**

```python
# tests/test_intel_engines.py
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
```

- [ ] **Step 2: 跑测试**

Run: `pytest tests/test_intel_engines.py -q`
Expected: 4 passed

- [ ] **Step 3: Commit**

```bash
git add tests/test_intel_engines.py
git commit -m "test: threatbook/virustotal intel adapter contract tests"
```

---

### Task 6: server 工具层测试（map_search / host_intel / engine_status）

**Files:**
- Test: `tests/test_server.py`

**Interfaces:**
- Consumes: `cybermap_mcp.server: map_search_impl(query, engines, limit, page) -> dict`；`host_intel_impl(target) -> dict`；`engine_status_impl() -> list[dict]`；`cybermap_mcp.engines: SEARCH_ENGINES, INTEL_ENGINES, Asset, EngineError`。
- Produces: 无新接口。

- [ ] **Step 1: 写测试**

```python
# tests/test_server.py
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
```

- [ ] **Step 2: 跑测试**

Run: `pytest tests/test_server.py -q`
Expected: 7 passed

- [ ] **Step 3: 全量回归**

Run: `pytest -q`
Expected: 全部通过（6 + 8 + 8 + 4 + 7 = 33 个测试）

- [ ] **Step 4: Commit**

```bash
git add tests/test_server.py
git commit -m "test: server tool layer — merge, error isolation, intel routing"
```

---
### Task 7: 端到端 smoke + README 一致性核对

**Files:**
- Modify: `README.md`（仅当核对发现漂移时）

**Interfaces:**
- Consumes: 全部已实现代码；环境中真实存在的引擎 key（有几个验几个）。

- [ ] **Step 1: 安装与入口点验证**

```bash
pip install -e .
python -c "from cybermap_mcp.server import engine_status_impl; [print(r['engine'], r['configured']) for r in engine_status_impl()]"
```

Expected: 打印 10 行；configured 与当前 shell 实际导出的 key 一致。

- [ ] **Step 2: MCP stdio 启动验证**

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}\n' | timeout 10 python -m cybermap_mcp | head -1
```

Expected: 一行 JSON 响应，含 `"serverInfo":{"name":"cybermap"`。（无响应或异常即入口破损，修复后重跑。）

- [ ] **Step 3: 真实引擎 smoke（仅对已配置 key 的引擎）**

```bash
python - <<'EOF'
import asyncio, json, os
from cybermap_mcp.server import map_search_impl, engine_status_impl

configured = [r["engine"] for r in engine_status_impl()
              if r["configured"] and r["mode"] == "search"]
if not configured:
    print("no search engine keys configured; skipping live smoke")
else:
    out = asyncio.run(map_search_impl('domain="example.com"',
                                      engines=configured, limit=3))
    print(json.dumps({"engines": configured, "total_raw": out["total_raw"],
                      "errors": out["errors"]}, ensure_ascii=False, indent=2))
EOF
```

Expected: 每个配置引擎要么返回资产、要么在 `errors` 给出可读的引擎侧错误（如配额/语法）。若某引擎返回解析型错误（KeyError/TypeError 字样），说明真实响应结构与 Task 3/4 的 mock 不符 → 用真实响应修正适配器与对应测试。无 key 则记录"live smoke skipped"，不算阻塞。

- [ ] **Step 4: README 一致性核对（逐项）**

| README 声明 | 核对方式 | 通过标准 |
|---|---|---|
| 10 引擎表格与 env 变量名 | 对照 `engines.py` 各类 `env_vars` | 逐字一致 |
| `map_search(query, engines?, limit=20, page=1)` | `server.py` 工具签名 | 默认值一致 |
| 按 `(ip, port, host/domain, protocol)` 去重 | `Asset.dedup_key` | 一致 |
| 单引擎报错不影响其他引擎 | Task 6 测试 `test_map_search_merges_and_isolates_errors` | 已通过 |
| Hunter page_size ≤ 100 / 0.zone ≤ 40 / Censys ≤ 100 | Task 3/4 钳制断言 | 已通过 |
| `cybermap-mcp` 命令 | `pyproject.toml [project.scripts]` + Step 2 | 一致 |

发现漂移：改 README（以代码事实为准）或改代码（以 README 为 spec，例如工具签名），在 commit message 说明。

- [ ] **Step 5: 最终回归 + Commit**

```bash
pytest -q
git add -A
git commit -m "docs/test: README conformance verified; live smoke results noted"
```

---

## Self-Review 记录

- **Spec coverage：** README 三个工具 → Task 6；引擎表/env → Task 3/4/5 + Task 7 Step 4；去重合并 → Task 2 + Task 6；配额约束 → Task 3/4 钳制断言；入口点/客户端配置 → Task 7 Step 1-2。
- **Placeholder scan：** 无 TBD/TODO；每个代码步骤含完整可运行代码。
- **Type consistency：** `make_client(handler) -> httpx.AsyncClient`（Task 1）在 Task 3/4/5 一致使用；`run(coro)` 辅助在各测试文件内各自定义（避免跨文件导入测试工具）；`SEARCH_ENGINES/INTEL_ENGINES/Asset/EngineError` 名字与 `engines.py` 现状一致。
- **Review Focus：** 5 项风险分别由 Task 2（merge 回填）、Task 3（Shodan 截断、Quake start）、Task 3/4/5（解析契约）、Task 7（README 漂移）覆盖。
