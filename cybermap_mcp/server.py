"""FastMCP server exposing three tools:
  - map_search    : unified search across the 8 asset-mapping engines
  - host_intel    : IP/domain intel via ThreatBook + VirusTotal (+Shodan host)
  - engine_status : which engines have keys configured
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import sys

import httpx

# httpx logs full request URLs at INFO, which would leak API keys
# (Fofa/Hunter/Shodan pass secrets as query params).
logging.getLogger("httpx").setLevel(logging.WARNING)

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


async def map_search_impl(query: str | dict[str, str],
                          engines: list[str] | None = None,
                          limit: int = 20, page: int = 1) -> dict:
    """Unified search.

    `query` is either a plain string (broadcast to every selected engine
    as-is) or a dict {engine_name: query} giving each engine its own DSL
    (e.g. {"fofa": 'app="Tomcat"', "shodan": "http.component:tomcat"}).
    Results are deduped on (ip, port, host/domain, protocol) with
    per-engine `sources` merged.
    """
    selected = _select(engines, SEARCH_ENGINES)
    if isinstance(query, dict):
        known = {e.name for e in SEARCH_ENGINES}
        bad = [k for k in query if k not in known]
        if bad:
            raise ValueError(
                f"unknown engine(s) in query: {bad}; available: {sorted(known)}")
        queries = {e.name: q for e in selected
                   if (q := query.get(e.name)) is not None}
        if not queries:
            raise ValueError("query dict has no entry for any selected engine")
    else:
        queries = {e.name: query for e in selected}

    runnable = [e for e in selected
                if e.name in queries and e.configured]
    if not runnable:
        missing = [{"engine": e.name, "env": list(e.env_vars), "doc": e.api_doc}
                   for e in selected if e.name in queries]
        return {"query": query, "assets": [], "errors": [], "hint":
                {"message": "no engine key configured", "configure": missing}}

    async with httpx.AsyncClient(timeout=CLIENT_TIMEOUT, follow_redirects=True) as client:
        tasks = [_run_engine(e, e.search(client, queries[e.name], limit, page))
                 for e in runnable]
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
async def map_search(query: str | dict[str, str],
                     engines: list[str] | None = None,
                     limit: int = 20, page: int = 1) -> str:
    """Search cyberspace asset mapping platforms.

    Results are deduped on (ip, port, host/domain, protocol) with
    per-engine `sources` merged; one engine's failure does not affect
    the others (see `errors` in the response).

    Args:
        query: a string broadcast to every selected engine as-is, or a
            dict {engine: query} giving each engine its own DSL. PREFER
            the dict form when mixing engines with incompatible syntax,
            e.g. {"fofa": 'app="Tomcat" && country="CN"',
            "shodan": "http.component:tomcat country:CN"}.
            Engines absent from the dict are skipped.
        engines: subset of ["fofa","hunter","quake","shodan","censys",
            "zoomeye","0zone","daydaymap"]; default = all configured.
        limit: results per engine per page.
        page: page number (1-based).

    Engine DSL cheat sheet (use with dict-form query):
        fofa / hunter / quake / daydaymap:
            app="Tomcat" && country="CN"; domain="example.com"; ip="1.2.3.4/24"
        shodan:  http.component:tomcat country:CN; hostname:example.com
        censys:  services.service_name: HTTP and location.country: CN
        zoomeye: app:"Tomcat" country:"CN"
        0zone:   (company=xxx有限公司)||(title=xxx)

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
