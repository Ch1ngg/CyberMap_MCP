"""FastMCP server exposing three tools:
  - map_search    : unified search across the 8 asset-mapping engines
  - host_intel    : IP/domain intel via ThreatBook + VirusTotal (+Shodan host)
  - engine_status : which engines have keys configured
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import sys

import httpx

from .engines import (
    INTEL_ENGINES,
    SEARCH_ENGINES,
    Asset,
    Engine,
    EngineError,
    Shodan,
    merge_assets,
)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cybermap")

CLIENT_TIMEOUT = httpx.Timeout(30.0, read=90.0)


def _select(names: list[str] | None, pool: list[Engine]) -> list[Engine]:
    if not names:
        return pool
    known = {e.name: e for e in pool}
    bad = [n for n in names if n not in known]
    if bad:
        raise ValueError(f"unknown engine(s): {bad}; available: {sorted(known)}")
    return [known[n] for n in names]


async def _run_engine(engine: Engine, coro):
    """Run one engine call; capture errors into a dict instead of failing all."""
    try:
        return {"results": await coro, "error": None}
    except EngineError as e:
        return {"results": [], "error": str(e)}
    except httpx.HTTPStatusError as e:
        body = e.response.text[:300]
        return {"results": [], "error": f"[{engine.name}] HTTP {e.response.status_code}: {body}"}
    except httpx.HTTPError as e:
        return {"results": [], "error": f"[{engine.name}] network error: {e}"}


async def map_search_impl(query: str, engines: list[str] | None = None,
                          limit: int = 20, page: int = 1) -> dict:
    """Unified search; raw query is passed to every selected engine.

    NOTE: engine DSLs are similar but not identical (e.g. Fofa `app="Tomcat"`
    vs Shodan `http.component:tomcat`). Results are deduped on
    (ip, port, host/domain, protocol) with per-engine `sources` merged.
    """
    selected = _select(engines, SEARCH_ENGINES)
    if not any(e.configured for e in selected):
        missing = [{"engine": e.name, "env": list(e.env_vars), "doc": e.api_doc}
                   for e in selected]
        return {"query": query, "assets": [], "errors": [], "hint":
                {"message": "no engine key configured", "configure": missing}}

    async with httpx.AsyncClient(timeout=CLIENT_TIMEOUT, follow_redirects=True) as client:
        tasks = [_run_engine(e, e.search(client, query, limit, page))
                 for e in selected if e.configured]
        outcomes = await asyncio.gather(*tasks)

    assets: list[Asset] = []
    errors: list[str] = []
    for o in outcomes:
        assets.extend(o["results"])
        if o["error"]:
            errors.append(o["error"])
    merged = merge_assets(assets)
    return {
        "query": query,
        "total_raw": len(assets),
        "total_dedup": len(merged),
        "assets": [a.as_dict() for a in merged],
        "errors": errors,
    }


async def host_intel_impl(target: str) -> dict:
    """IP/domain intel. ThreatBook: IP reputation; VirusTotal: IP/domain report."""
    is_ip = True
    try:
        ipaddress.ip_address(target)
    except ValueError:
        is_ip = False

    out: dict = {"target": target, "intel": {}, "errors": []}

    async with httpx.AsyncClient(timeout=CLIENT_TIMEOUT, follow_redirects=True) as client:
        jobs: dict[str, object] = {}
        if is_ip:
            for e in INTEL_ENGINES:
                if e.configured:
                    jobs[e.name] = e
            for name, e in jobs.items():
                if name == "threatbook":
                    res = await _run_engine(e, e.ip_reputation(client, target))
                else:
                    res = await _run_engine(e, e.report(client, target))
                if res["error"]:
                    out["errors"].append(res["error"])
                else:
                    out["intel"][name] = res["results"][0] if isinstance(
                        res["results"], list) and res["results"] else res["results"]
        else:
            vt = next(e for e in INTEL_ENGINES if e.name == "virustotal")
            if vt.configured:
                res = await _run_engine(vt, vt.report(client, target))
                if res["error"]:
                    out["errors"].append(res["error"])
                else:
                    out["intel"]["virustotal"] = res["results"]

    if not out["intel"] and not out["errors"]:
        out["errors"].append("no intel engine configured: set THREATBOOK_KEY and/or VT_KEY")
    return out


def engine_status_impl() -> list[dict]:
    rows = []
    for e in SEARCH_ENGINES + INTEL_ENGINES:
        rows.append({
            "engine": e.name,
            "mode": "search" if e in SEARCH_ENGINES else "intel",
            "configured": e.configured,
            "env_vars": list(e.env_vars),
            "api_doc": e.api_doc,
        })
    return rows


# ------------------------------------------------------------------ tools --

@mcp.tool()
async def map_search(query: str, engines: list[str] | None = None,
                     limit: int = 20, page: int = 1) -> str:
    """Search cyberspace asset mapping platforms.

    Args:
        query: platform query string. Passed to each selected engine as-is;
            engines use similar but not identical DSLs (Fofa/Hunter/Quake/
            DayDayMap are near-compatible, e.g. app="Tomcat"; Shodan/Censys/
            ZoomEye/0.zone use their own syntax).
        engines: subset of ["fofa","hunter","quake","shodan","censys",
            "zoomeye","0zone","daydaymap"]; default = all configured.
        limit: results per engine per page.
        page: page number (1-based).

    Returns JSON: {query, total_raw, total_dedup, assets:[{ip,port,host,
    domain,url,title,service,product,protocol,org,country,city,sources}],
    errors:[engine-level error strings]}.
    """
    try:
        result = await map_search_impl(query, engines, limit, page)
    except ValueError as e:
        result = {"error": str(e)}
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def host_intel(target: str) -> str:
    """Threat intel for a single IP or domain.

    IP: ThreatBook IP reputation + VirusTotal report.
    Domain: VirusTotal report.

    Returns JSON: {target, intel:{engine: report}, errors:[]}.
    """
    return json.dumps(await host_intel_impl(target), ensure_ascii=False)


@mcp.tool()
def engine_status() -> str:
    """List all supported engines, their env-var keys, and whether each is
    currently configured. Call this first if map_search reports no engines."""
    return json.dumps(engine_status_impl(), ensure_ascii=False)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
