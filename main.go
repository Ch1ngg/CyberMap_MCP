package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	flagTransport = flag.String("transport", "stdio", "transport: stdio | http | sse")
	flagAddr      = flag.String("addr", ":8080", "listen address for http/sse transports")
	flagProxy     = flag.String("proxy", "", "proxy URL (http://, https:// or socks5://); "+
		"overrides CYBERMAP_PROXY; HTTP(S)_PROXY env vars are the fallback. "+
		"CYBERMAP_PROXY_ENGINES=shodan,censys limits the proxy to those engines")
	flagToken = flag.String("token", "", "bearer token required for http/sse transports "+
		"(or CYBERMAP_TOKEN); empty = no auth — do not expose the listener without it")
)

const mapSearchDesc = `Search cyberspace asset mapping platforms.

Results are deduped on (ip, port, host/domain, protocol) with
per-engine sources merged; one engine's failure does not affect
the others (see errors in the response).

query: a string broadcast to every selected engine as-is, or an
object {engine: query} giving each engine its own DSL. PREFER the
object form when mixing engines with incompatible syntax, e.g.
{"fofa": "app=\"Tomcat\" && country=\"CN\"",
 "shodan": "http.component:tomcat country:CN"}.
Engines absent from the object are skipped.

Engine DSL cheat sheet (use with object-form query):
  fofa / hunter / quake / daydaymap:
      app="Tomcat" && country="CN"; domain="example.com"; ip="1.2.3.4/24"
  shodan:  http.component:tomcat country:CN; hostname:example.com
  censys:  services.service_name: HTTP and location.country: CN
  zoomeye: app:"Tomcat" country:"CN"
  0zone:   (company=xxx有限公司)||(title=xxx)

Returns JSON: {query, total_raw, total_dedup, assets:[{ip,port,host,
domain,url,title,service,product,protocol,org,country,city,sources}],
errors:[engine-level error strings]}.`

type MapSearchInput struct {
	Query   any      `json:"query" jsonschema:"REQUIRED. Query string broadcast to all selected engines, or object {engine: query} with per-engine DSL syntax (preferred when mixing engines)"`
	Engines []string `json:"engines,omitempty" jsonschema:"subset of [fofa hunter quake shodan censys zoomeye 0zone daydaymap]; default = all configured"`
	Limit   int      `json:"limit,omitempty" jsonschema:"results per engine per page (default 20)"`
	Page    int      `json:"page,omitempty" jsonschema:"page number, 1-based (default 1)"`
}

type HostIntelInput struct {
	Target string `json:"target" jsonschema:"IP address or domain. IP: ThreatBook reputation + VirusTotal report. Domain: VirusTotal report"`
}

type GitHubSearchInput struct {
	Query string `json:"query" jsonschema:"REQUIRED. GitHub search query, e.g. '\"example.com\" apikey' (code dork), 'org:target' (repositories)"`
	Type  string `json:"type,omitempty" jsonschema:"code | repositories | issues (default code). code search requires GITHUB_TOKEN"`
	Limit int    `json:"limit,omitempty" jsonschema:"max results, 1-100 (default 20)"`
}

type CVESearchInput struct {
	Query string `json:"query" jsonschema:"REQUIRED. CVE id (e.g. CVE-2021-44228) or keyword (e.g. log4j, nginx)"`
	Limit int    `json:"limit,omitempty" jsonschema:"max results, 1-100 (default 20)"`
}

type CompanyReconInput struct {
	Keyword      string   `json:"keyword" jsonschema:"REQUIRED. 公司名关键词，如 '腾讯'、'百度'"`
	Sources      []string `json:"sources,omitempty" jsonschema:"subset of [tyc aqc]; default both. tyc=天眼查, aqc=爱企查"`
	Depth        int      `json:"depth,omitempty" jsonschema:"股权穿透深度 1-5，默认 2（即二级公司）"`
	MinPercent   float64  `json:"min_percent,omitempty" jsonschema:"子公司持股比例过滤 0-100，默认 0；50=只看控股子公司"`
	MaxCompanies int      `json:"max_companies,omitempty" jsonschema:"穿透遍历公司数上限 1-100，默认 20"`
	SearchLimit  int      `json:"search_limit,omitempty" jsonschema:"每源搜索返回条数 1-20，默认 10"`
}

type EmptyInput struct{}

func mapSearchHandler(ctx context.Context, _ *mcp.CallToolRequest, in MapSearchInput) (*mcp.CallToolResult, any, error) {
	limit, page := in.Limit, in.Page
	if limit <= 0 {
		limit = 20
	}
	if page <= 0 {
		page = 1
	}
	res, err := MapSearch(ctx, in.Query, in.Engines, limit, page)
	if err != nil {
		return nil, map[string]any{"error": err.Error()}, nil
	}
	return nil, res, nil
}

func hostIntelHandler(ctx context.Context, _ *mcp.CallToolRequest, in HostIntelInput) (*mcp.CallToolResult, any, error) {
	return nil, HostIntel(ctx, in.Target), nil
}

func engineStatusHandler(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
	return nil, map[string]any{"engines": EngineStatus()}, nil
}

func githubSearchHandler(ctx context.Context, _ *mcp.CallToolRequest, in GitHubSearchInput) (*mcp.CallToolResult, any, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	res, err := GitHubSearch(ctx, httpClientFor("github"), in.Query, in.Type, limit)
	if err != nil {
		return nil, map[string]any{"error": err.Error()}, nil
	}
	return nil, res, nil
}

func cveSearchHandler(ctx context.Context, _ *mcp.CallToolRequest, in CVESearchInput) (*mcp.CallToolResult, any, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	res, err := CVESearch(ctx, httpClientFor("nvd"), in.Query, limit)
	if err != nil {
		return nil, map[string]any{"error": err.Error()}, nil
	}
	return nil, res, nil
}

func companyReconHandler(ctx context.Context, _ *mcp.CallToolRequest, in CompanyReconInput) (*mcp.CallToolResult, any, error) {
	kw := strings.TrimSpace(in.Keyword)
	if kw == "" {
		return nil, map[string]any{"error": "keyword is required"}, nil
	}
	depth := in.Depth
	if depth == 0 {
		depth = 2
	}
	maxC := in.MaxCompanies
	if maxC == 0 {
		maxC = 20
	}
	sLimit := in.SearchLimit
	if sLimit == 0 {
		sLimit = 10
	}
	return nil, CompanyRecon(ctx, kw, in.Sources, depth, in.MinPercent, maxC, sLimit), nil
}

func newServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "cybermap", Version: "0.0.1"}, nil)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "map_search",
		Description: mapSearchDesc,
	}, mapSearchHandler)
	mcp.AddTool(s, &mcp.Tool{
		Name: "host_intel",
		Description: "Threat intel for a single IP or domain. " +
			"IP: ThreatBook IP reputation + VirusTotal report. Domain: VirusTotal report. " +
			"Returns JSON: {target, intel:{engine: report}, errors:[]}.",
	}, hostIntelHandler)
	mcp.AddTool(s, &mcp.Tool{
		Name: "engine_status",
		Description: "List all supported engines, their env-var keys, and whether each is " +
			"currently configured. Call this first if map_search reports no engines.",
	}, engineStatusHandler)
	mcp.AddTool(s, &mcp.Tool{
		Name: "github_search",
		Description: "Search GitHub: code (find leaked keys/dorks, requires GITHUB_TOKEN), " +
			"repositories, or issues. Returns JSON: {type, total, items, warnings}. " +
			"Useful for recon: find a target's repos, leaked configs, exposed secrets.",
	}, githubSearchHandler)
	mcp.AddTool(s, &mcp.Tool{
		Name: "cve_search",
		Description: "Search the NVD vulnerability database by CVE id or keyword " +
			"(e.g. a product name found via map_search). Returns JSON: {query, total, " +
			"results:[{id, description, severity, score, published, references}]}. " +
			"NVD_API_KEY env var optional (raises rate limit).",
	}, cveSearchHandler)
	mcp.AddTool(s, &mcp.Tool{
		Name: "company_recon",
		Description: "Search Chinese companies and map subsidiaries + ICP-filed domains " +
			"(天眼查/爱企查, no API key needed). Walks: keyword → best-match company → " +
			"equity tree (subsidiaries, percent >= min_percent, skipping 注销) → ICP domains " +
			"of each company. Returns JSON: {keyword, companies:[{source,id,name,legal_person," +
			"reg_status,reg_capital,estiblish_time,emails,phones,root}], equity_tree:[{source," +
			"id,name,percent,depth,path}], domains:[{domain,company,icp_no,sources}], errors}.",
	}, companyReconHandler)
	return s
}

func main() {
	flag.Parse()
	initProxy(*flagProxy)
	authToken = *flagToken
	if authToken == "" {
		authToken = envKey("CYBERMAP_TOKEN")
	}
	server := newServer()
	ctx := context.Background()

	switch *flagTransport {
	case "stdio":
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
	case "http":
		h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
		log.Printf("cybermap-mcp streamable HTTP listening on %s (POST here, auth: %v)", *flagAddr, authToken != "")
		log.Fatal(http.ListenAndServe(*flagAddr, withAuth(h)))
	case "sse":
		h := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return server }, nil)
		log.Printf("cybermap-mcp SSE listening on %s (auth: %v)", *flagAddr, authToken != "")
		log.Fatal(http.ListenAndServe(*flagAddr, withAuth(h)))
	default:
		log.Fatalf("unknown transport %q: want stdio | http | sse", *flagTransport)
	}
}
