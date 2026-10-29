package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Engine is the common metadata for all platform adapters.
type Engine interface {
	Name() string
	EnvVars() []string
	APIDoc() string
}

// SearchEngine adapts an asset-mapping platform.
type SearchEngine interface {
	Engine
	Search(ctx context.Context, client *http.Client, query string, limit, page int) ([]Asset, error)
}

func envKey(name string) string { return strings.TrimSpace(os.Getenv(name)) }

func configured(envVars []string) bool {
	for _, v := range envVars {
		if envKey(v) == "" {
			return false
		}
	}
	return true
}

func require(name string, envVars []string, doc string) error {
	if !configured(envVars) {
		return &EngineError{name, fmt.Sprintf("missing key(s): %s; see %s", strings.Join(envVars, ", "), doc)}
	}
	return nil
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// --- generic JSON helpers (responses are decoded into map[string]any) ---

func jobj(b []byte) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func sub(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return map[string]any{}
		}
		cur = next
	}
	return cur
}

func arr(m map[string]any, key string) []any {
	if v, ok := m[key].([]any); ok {
		return v
	}
	return nil
}

func jstr(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func jint(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case string:
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return 0
}

func jstrAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

// safeErr 剥离错误中的完整请求 URL（FOFA/Hunter/Shodan/DayDayMap 的 key
// 在 query 里，url.Error 会原样带出），只保留底层原因，防止密钥随
// 工具结果进入模型上下文。
func safeErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// doHTTP executes req, decodes JSON, and converts transport/HTTP failures
// into EngineError (status + first 300 bytes of body, like the Python port).
func doHTTP(engine string, client *http.Client, req *http.Request) (map[string]any, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, &EngineError{engine, "network error: " + safeErr(err)}
	}
	defer resp.Body.Close()
	// Shodan returns multi-MB bodies (banner data for up to 100 matches).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, &EngineError{engine, "read error: " + safeErr(err)}
	}
	if resp.StatusCode >= 400 {
		snip := string(body)
		if len(snip) > 300 {
			snip = snip[:300]
		}
		return nil, &EngineError{engine, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, snip)}
	}
	return jobj(body), nil
}

func getJSON(ctx context.Context, engine string, client *http.Client, url string,
	query map[string]string, headers map[string]string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &EngineError{engine, safeErr(err)}
	}
	q := req.URL.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doHTTP(engine, client, req)
}

func postJSON(ctx context.Context, engine string, client *http.Client, url string,
	payload map[string]any, headers map[string]string) (map[string]any, error) {
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, &EngineError{engine, safeErr(err)}
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doHTTP(engine, client, req)
}

// --- Fofa ---

type Fofa struct{}

func (Fofa) Name() string      { return "fofa" }
func (Fofa) EnvVars() []string { return []string{"FOFA_KEY"} }
func (Fofa) APIDoc() string    { return "https://fofa.info/userInfo" }

var fofaFields = []string{"ip", "host", "port", "title", "domain", "server",
	"protocol", "country_name", "city", "as_organization"}

func (Fofa) Search(ctx context.Context, client *http.Client, query string, limit, page int) ([]Asset, error) {
	if err := require("fofa", Fofa{}.EnvVars(), Fofa{}.APIDoc()); err != nil {
		return nil, err
	}
	data, err := getJSON(ctx, "fofa", client, "https://fofa.info/api/v1/search/all", map[string]string{
		"key":     envKey("FOFA_KEY"),
		"qbase64": b64(query),
		"size":    fmt.Sprint(clamp(limit, 1, 10000)),
		"page":    fmt.Sprint(page),
		"fields":  strings.Join(fofaFields, ","),
	}, nil)
	if err != nil {
		return nil, err
	}
	if e, ok := data["error"]; ok && e != nil && e != false && jstrAny(e) != "" && jstrAny(e) != "false" {
		return nil, &EngineError{"fofa", jstr(data, "errmsg")}
	}
	out := []Asset{}
	for _, row := range arr(data, "results") {
		cols, ok := row.([]any)
		if !ok {
			continue
		}
		v := map[string]any{}
		for i, c := range fofaFields {
			if i < len(cols) {
				v[c] = cols[i]
			}
		}
		host := jstr(v, "host")
		a := Asset{
			IP: jstr(v, "ip"), Port: jint(v, "port"), Host: host,
			Domain: jstr(v, "domain"), Title: jstr(v, "title"),
			Service: jstr(v, "server"), Protocol: jstr(v, "protocol"),
			Org: jstr(v, "as_organization"), Country: jstr(v, "country_name"),
			City: jstr(v, "city"), Sources: []string{"fofa"},
		}
		if strings.Contains(host, "://") {
			a.URL = host
		}
		out = append(out, a)
	}
	return out, nil
}

// --- Hunter ---

type Hunter struct{}

func (Hunter) Name() string      { return "hunter" }
func (Hunter) EnvVars() []string { return []string{"HUNTER_KEY"} }
func (Hunter) APIDoc() string    { return "https://hunter.qianxin.com/home/personalInfo?to=api" }

// hunterPageSize rounds up: Hunter only accepts page_size in {1,10,20,50,100}.
func hunterPageSize(limit int) int {
	size := clamp(limit, 1, 100)
	for _, s := range []int{1, 10, 20, 50, 100} {
		if s >= size {
			return s
		}
	}
	return 100
}

func (Hunter) Search(ctx context.Context, client *http.Client, query string, limit, page int) ([]Asset, error) {
	if err := require("hunter", Hunter{}.EnvVars(), Hunter{}.APIDoc()); err != nil {
		return nil, err
	}
	size := clamp(limit, 1, 100)
	data, err := getJSON(ctx, "hunter", client, "https://hunter.qianxin.com/openApi/search", map[string]string{
		"api-key":   envKey("HUNTER_KEY"),
		"search":    b64(query),
		"page":      fmt.Sprint(page),
		"page_size": fmt.Sprint(hunterPageSize(limit)),
		"is_web":    "3",
	}, nil)
	if err != nil {
		return nil, err
	}
	if jint(data, "code") != 200 {
		return nil, &EngineError{"hunter", jstr(data, "message")}
	}
	d := sub(data, "data")
	items := arr(d, "arr")
	if items == nil {
		items = arr(d, "result_arr")
	}
	out := []Asset{}
	for _, it := range items {
		e, ok := it.(map[string]any)
		if !ok {
			continue
		}
		title := ""
		switch wt := e["web_title"].(type) {
		case map[string]any:
			title = jstr(wt, "title")
		case string:
			title = wt
		}
		if title == "" {
			title = jstr(e, "title")
		}
		out = append(out, Asset{
			IP: jstr(e, "ip"), Port: jint(e, "port"), Domain: jstr(e, "domain"),
			URL: jstr(e, "url"), Title: title, Service: jstr(e, "server"),
			Protocol: jstr(e, "protocol"),
			Org:      first(jstr(e, "company"), jstr(e, "as_org")),
			Country:  jstr(e, "country"), City: jstr(e, "city"),
			Sources: []string{"hunter"},
		})
	}
	// Round-up may over-fetch; slice back to the requested limit.
	if len(out) > size {
		out = out[:size]
	}
	return out, nil
}

func first(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// shodanIP handles both response formats: legacy "ip_str" string and the
// newer numeric "ip" (host-order IPv4 integer).
func shodanIP(m map[string]any) string {
	if s := jstr(m, "ip_str"); s != "" {
		return s
	}
	switch v := m["ip"].(type) {
	case float64:
		n := uint32(v)
		return fmt.Sprintf("%d.%d.%d.%d", n>>24, n>>16&0xff, n>>8&0xff, n&0xff)
	case string:
		return v
	}
	return ""
}

// --- Quake ---

type Quake struct{}

func (Quake) Name() string      { return "quake" }
func (Quake) EnvVars() []string { return []string{"QUAKE_KEY"} }
func (Quake) APIDoc() string    { return "https://quake.360.net/quake/#/personal?tab=message" }

var quakeInclude = []string{"ip", "port", "transport", "hostname", "domain", "org",
	"service.name", "service.product", "service.http.host", "service.http.title",
	"location.country_cn", "location.city_cn"}

func (Quake) Search(ctx context.Context, client *http.Client, query string, limit, page int) ([]Asset, error) {
	if err := require("quake", Quake{}.EnvVars(), Quake{}.APIDoc()); err != nil {
		return nil, err
	}
	size := clamp(limit, 1, 5000)
	data, err := postJSON(ctx, "quake", client, "https://quake.360.net/api/v3/search/quake_service",
		map[string]any{
			"query":   query,
			"start":   (page - 1) * size,
			"size":    size,
			"include": quakeInclude,
		}, map[string]string{"X-QuakeToken": envKey("QUAKE_KEY")})
	if err != nil {
		return nil, err
	}
	if jint(data, "code") != 0 {
		return nil, &EngineError{"quake", jstr(data, "message")}
	}
	out := []Asset{}
	for _, it := range arr(data, "data") {
		e, ok := it.(map[string]any)
		if !ok {
			continue
		}
		svc := sub(e, "service")
		ht := sub(e, "service", "http")
		loc := sub(e, "location")
		out = append(out, Asset{
			IP: jstr(e, "ip"), Port: jint(e, "port"),
			Host:   first(jstr(ht, "host"), jstr(e, "hostname")),
			Domain: jstr(e, "domain"), Title: jstr(ht, "title"),
			Service: jstr(svc, "name"), Product: jstr(svc, "product"),
			Protocol: jstr(e, "transport"), Org: jstr(e, "org"),
			Country: jstr(loc, "country_cn"), City: jstr(loc, "city_cn"),
			Sources: []string{"quake"},
		})
	}
	return out, nil
}

// --- Shodan ---

type Shodan struct{}

func (Shodan) Name() string      { return "shodan" }
func (Shodan) EnvVars() []string { return []string{"SHODAN_KEY"} }
func (Shodan) APIDoc() string    { return "https://account.shodan.io/" }

func (Shodan) Search(ctx context.Context, client *http.Client, query string, limit, page int) ([]Asset, error) {
	if err := require("shodan", Shodan{}.EnvVars(), Shodan{}.APIDoc()); err != nil {
		return nil, err
	}
	data, err := getJSON(ctx, "shodan", client, "https://api.shodan.io/shodan/host/search", map[string]string{
		"key":   envKey("SHODAN_KEY"),
		"query": query,
		"page":  fmt.Sprint(page),
	}, nil)
	if err != nil {
		return nil, err
	}
	out := []Asset{}
	for _, it := range arr(data, "matches") {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		hostnames := arr(m, "hostnames")
		host := ""
		if len(hostnames) > 0 {
			host = jstrAny(hostnames[0])
		}
		banner := jstr(m, "data")
		if len(banner) > 200 {
			banner = banner[:200]
		}
		loc := sub(m, "location")
		out = append(out, Asset{
			IP: shodanIP(m), Port: jint(m, "port"), Host: host, Domain: host,
			Title: jstr(sub(m, "http"), "title"), Service: banner,
			Product: jstr(m, "product"), Protocol: jstr(m, "transport"),
			Org: jstr(m, "org"), Country: jstr(loc, "country_name"),
			City: jstr(loc, "city"), Sources: []string{"shodan"},
		})
	}
	// Shodan has no page-size param (fixed 100/page); clamp client-side.
	if n := clamp(limit, 1, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

// --- Censys ---

type Censys struct{}

func (Censys) Name() string      { return "censys" }
func (Censys) EnvVars() []string { return []string{"CENSYS_ID", "CENSYS_SECRET"} }
func (Censys) APIDoc() string    { return "https://search.censys.io/account/api" }

func (Censys) Search(ctx context.Context, client *http.Client, query string, limit, page int) ([]Asset, error) {
	if err := require("censys", Censys{}.EnvVars(), Censys{}.APIDoc()); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://search.censys.io/api/v2/hosts/search", nil)
	if err != nil {
		return nil, &EngineError{"censys", safeErr(err)}
	}
	q := req.URL.Query()
	q.Set("q", query)
	q.Set("per_page", fmt.Sprint(clamp(limit, 1, 100)))
	q.Set("virtual_hosts", "EXCLUDE")
	req.URL.RawQuery = q.Encode()
	req.SetBasicAuth(envKey("CENSYS_ID"), envKey("CENSYS_SECRET"))
	data, err := doHTTP("censys", client, req)
	if err != nil {
		return nil, err
	}
	if jstr(data, "status") != "OK" {
		return nil, &EngineError{"censys", first(jstrAny(data["error"]), jstr(data, "status"))}
	}
	out := []Asset{}
	for _, h := range arr(sub(data, "result"), "hits") {
		hit, ok := h.(map[string]any)
		if !ok {
			continue
		}
		loc := sub(hit, "location")
		asn := sub(hit, "autonomous_system")
		for _, s := range arr(hit, "services") {
			svc, ok := s.(map[string]any)
			if !ok {
				continue
			}
			product := ""
			if sw := arr(svc, "software"); len(sw) > 0 {
				if m, ok := sw[0].(map[string]any); ok {
					product = jstr(m, "name")
				}
			}
			proto := jstr(svc, "transport_protocol")
			if proto == "TCP" {
				proto = "tcp"
			}
			out = append(out, Asset{
				IP: jstr(hit, "ip"), Port: jint(svc, "port"),
				Service: jstr(svc, "service_name"), Product: product, Protocol: proto,
				Org: jstr(asn, "name"), Country: jstr(loc, "country"),
				City: jstr(loc, "city"), Sources: []string{"censys"},
			})
		}
	}
	return out, nil
}

// --- ZoomEye ---

type ZoomEye struct{}

func (ZoomEye) Name() string      { return "zoomeye" }
func (ZoomEye) EnvVars() []string { return []string{"ZOOMEYE_KEY"} }
func (ZoomEye) APIDoc() string    { return "https://www.zoomeye.org/profile" }

func zoomeyeName(geo map[string]any, key string) string {
	names := sub(geo, key, "names")
	return first(jstr(names, "zh-CN"), jstr(names, "en"))
}

func (ZoomEye) Search(ctx context.Context, client *http.Client, query string, limit, page int) ([]Asset, error) {
	if err := require("zoomeye", ZoomEye{}.EnvVars(), ZoomEye{}.APIDoc()); err != nil {
		return nil, err
	}
	data, err := getJSON(ctx, "zoomeye", client, "https://api.zoomeye.org/host/search",
		map[string]string{"query": query, "page": fmt.Sprint(page)},
		map[string]string{"API-KEY": envKey("ZOOMEYE_KEY")})
	if err != nil {
		return nil, err
	}
	if jint(data, "status") != 200 {
		return nil, &EngineError{"zoomeye", first(jstr(data, "message"), jstrAny(data["status"]))}
	}
	out := []Asset{}
	for _, it := range arr(data, "matches") {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		pi := sub(m, "portinfo")
		geo := sub(m, "geoinfo")
		title := ""
		switch t := m["title"].(type) {
		case []any:
			if len(t) > 0 {
				title = jstrAny(t[0])
			}
		case string:
			title = t
		}
		out = append(out, Asset{
			IP: jstr(m, "ip"), Port: jint(pi, "port"), Host: jstr(m, "hostname"),
			Domain: jstr(m, "domain"), Title: title, Service: jstr(pi, "service"),
			Product: jstr(pi, "app"), Protocol: "tcp",
			Org:     first(jstr(m, "organization"), jstr(geo, "organization")),
			Country: zoomeyeName(geo, "country"), City: zoomeyeName(geo, "city"),
			Sources: []string{"zoomeye"},
		})
	}
	return out, nil
}

// --- 0.zone ---

type Zone0 struct{}

func (Zone0) Name() string      { return "0zone" }
func (Zone0) EnvVars() []string { return []string{"ZONE0_KEY"} }
func (Zone0) APIDoc() string    { return "https://0.zone/apply" }

func (Zone0) Search(ctx context.Context, client *http.Client, query string, limit, page int) ([]Asset, error) {
	if err := require("0zone", Zone0{}.EnvVars(), Zone0{}.APIDoc()); err != nil {
		return nil, err
	}
	data, err := postJSON(ctx, "0zone", client, "https://0.zone/api/data/", map[string]any{
		"query":       query,
		"query_type":  "site",
		"page":        page,
		"pagesize":    clamp(limit, 1, 40),
		"zone_key_id": envKey("ZONE0_KEY"),
	}, nil)
	if err != nil {
		return nil, err
	}
	if jint(data, "code") != 0 {
		return nil, &EngineError{"0zone", strings.TrimSpace(jstr(data, "message"))}
	}
	out := []Asset{}
	for _, it := range arr(data, "data") {
		e, ok := it.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, Asset{
			IP: jstr(e, "ip"), Port: jint(e, "port"), URL: jstr(e, "url"),
			Title: jstr(e, "title"), Service: jstr(e, "service"),
			Org: jstr(e, "group"), City: jstr(e, "city"),
			Sources: []string{"0zone"},
		})
	}
	return out, nil
}

// --- DayDayMap ---

type DayDayMap struct{}

func (DayDayMap) Name() string      { return "daydaymap" }
func (DayDayMap) EnvVars() []string { return []string{"DAYDAYMAP_KEY"} }
func (DayDayMap) APIDoc() string    { return "https://www.daydaymap.com/help/document?type=api-auth" }

func (DayDayMap) Search(ctx context.Context, client *http.Client, query string, limit, page int) ([]Asset, error) {
	if err := require("daydaymap", DayDayMap{}.EnvVars(), DayDayMap{}.APIDoc()); err != nil {
		return nil, err
	}
	data, err := postJSON(ctx, "daydaymap", client, "https://www.daydaymap.com/api/v1/raymap/search/all",
		map[string]any{
			"page":      page,
			"page_size": clamp(limit, 1, 100),
			"keyword":   b64(query),
		}, map[string]string{"api-key": envKey("DAYDAYMAP_KEY")})
	if err != nil {
		return nil, err
	}
	if code, present := data["code"]; present && jint(data, "code") != 200 {
		return nil, &EngineError{"daydaymap",
			fmt.Sprintf("code %v: %s", code, first(jstr(data, "msg"), jstr(data, "message")))}
	}
	body := sub(data, "data")
	items := arr(body, "data")
	if items == nil {
		items = arr(body, "results")
	}
	if items == nil {
		items = arr(body, "list")
	}
	out := []Asset{}
	for _, it := range items {
		e, ok := it.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, Asset{
			IP: jstr(e, "ip"), Port: jint(e, "port"), Host: jstr(e, "host"),
			Domain: jstr(e, "domain"), Title: jstr(e, "title"),
			Service:  first(jstr(e, "protocol"), jstr(e, "service")),
			Protocol: jstr(e, "protocol"),
			Org:      first(jstr(e, "asn_org"), jstr(e, "isp")),
			Country:  jstr(e, "country"), City: jstr(e, "city"),
			Sources: []string{"daydaymap"},
		})
	}
	return out, nil
}

// --- ThreatBook (intel only) ---

type ThreatBook struct{}

func (ThreatBook) Name() string      { return "threatbook" }
func (ThreatBook) EnvVars() []string { return []string{"THREATBOOK_KEY"} }
func (ThreatBook) APIDoc() string    { return "https://x.threatbook.com/v5/myApi" }

func (ThreatBook) IPReputation(ctx context.Context, client *http.Client, ip string) (map[string]any, error) {
	if err := require("threatbook", ThreatBook{}.EnvVars(), ThreatBook{}.APIDoc()); err != nil {
		return nil, err
	}
	data, err := postJSON(ctx, "threatbook", client, "https://api.threatbook.cn/v3/scene/ip_reputation",
		map[string]any{"apikey": envKey("THREATBOOK_KEY"), "resource": ip}, nil)
	if err != nil {
		return nil, err
	}
	if jint(data, "response_code") != 0 {
		return nil, &EngineError{"threatbook", jstr(data, "verbose_msg")}
	}
	rep := sub(data, "data", ip)
	loc := sub(rep, "basic", "location")
	location := map[string]any{}
	for _, k := range []string{"country", "province", "city"} {
		if v := loc[k]; v != nil {
			location[k] = v
		}
	}
	return map[string]any{
		"engine": "threatbook", "ip": ip,
		"severity": rep["severity"], "judgments": rep["judgments"],
		"tags_classes": rep["tags_classes"], "location": location,
		"carrier":    sub(rep, "basic")["carrier"],
		"confidence": rep["confidence_level"], "update_time": rep["update_time"],
	}, nil
}

// --- VirusTotal (intel only) ---

type VirusTotal struct{}

func (VirusTotal) Name() string      { return "virustotal" }
func (VirusTotal) EnvVars() []string { return []string{"VT_KEY"} }
func (VirusTotal) APIDoc() string    { return "https://www.virustotal.com/gui/user/<user>/apikey" }

func (VirusTotal) Report(ctx context.Context, client *http.Client, target string, isIP bool) (map[string]any, error) {
	if err := require("virustotal", VirusTotal{}.EnvVars(), VirusTotal{}.APIDoc()); err != nil {
		return nil, err
	}
	kind := "domains"
	if isIP {
		kind = "ip_addresses"
	}
	data, err := getJSON(ctx, "virustotal", client,
		"https://www.virustotal.com/api/v3/"+kind+"/"+target, nil,
		map[string]string{"x-apikey": envKey("VT_KEY")})
	if err != nil {
		return nil, err
	}
	attrs := sub(data, "data", "attributes")
	return map[string]any{
		"engine": "virustotal", "target": target,
		"last_analysis_stats": attrs["last_analysis_stats"],
		"reputation":          attrs["reputation"],
		"country":             attrs["country"],
		"as_owner":            attrs["as_owner"],
		"network":             attrs["network"],
		"tags":                attrs["tags"],
		"crowdsourced_tags":   attrs["crowdsourced_context"],
	}, nil
}

var SearchEngines = []SearchEngine{
	Fofa{}, Hunter{}, Quake{}, Shodan{}, Censys{}, ZoomEye{}, Zone0{}, DayDayMap{},
}

// IntelEngines keeps declaration order for engine_status output.
var IntelEngines = []Engine{ThreatBook{}, VirusTotal{}}
