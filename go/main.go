package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	flagTransport = flag.String("transport", "stdio", "transport: stdio | http | sse")
	flagAddr      = flag.String("addr", ":8080", "listen address for http/sse transports")
	flagProxy     = flag.String("proxy", "", "proxy URL (http://, https:// or socks5://); "+
		"overrides CYBERMAP_PROXY; HTTP(S)_PROXY env vars are the fallback. "+
		"CYBERMAP_PROXY_ENGINES=shodan,censys limits the proxy to those engines")
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
	return s
}

func main() {
	flag.Parse()
	initProxy(*flagProxy)
	server := newServer()
	ctx := context.Background()

	switch *flagTransport {
	case "stdio":
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
	case "http":
		h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
		log.Printf("cybermap-mcp streamable HTTP listening on %s (POST here)", *flagAddr)
		log.Fatal(http.ListenAndServe(*flagAddr, h))
	case "sse":
		h := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return server }, nil)
		log.Printf("cybermap-mcp SSE listening on %s", *flagAddr)
		log.Fatal(http.ListenAndServe(*flagAddr, h))
	default:
		log.Fatalf("unknown transport %q: want stdio | http | sse", *flagTransport)
	}
}
