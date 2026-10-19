package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 天眼查微信小程序 UA（小程序 API 免登录的关键）
const tycUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/539 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 MicroMessenger/6.8.0(0x16080000) NetType/WIFI MiniProgramEnv/Mac MacWechat/WMPF MacWechat/3.8"

// 爱企查桌面 UA
const aqcUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"

type CompanyBrief struct {
	Source      string   `json:"source"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	LegalPerson string   `json:"legal_person,omitempty"`
	RegStatus   string   `json:"reg_status,omitempty"`
	RegCapital  string   `json:"reg_capital,omitempty"`
	Estiblish   string   `json:"estiblish_time,omitempty"`
	Emails      []string `json:"emails,omitempty"`
	Phones      []string `json:"phones,omitempty"`
	Root        bool     `json:"root,omitempty"`
}

type equityChild struct {
	ID        string
	Name      string
	Percent   float64
	RegStatus string
	HasNode   bool
}

type icpHit struct {
	domain string
	icpNo  string
}

var emTagRe = regexp.MustCompile(`</?em>`)

func stripEm(s string) string { return emTagRe.ReplaceAllString(s, "") }

// parsePercent: "90%"→90, "3.564292%"→3.564292, ""→0, "-"→0
func parsePercent(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	if s == "" || s == "-" {
		return 0
	}
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

// jid 把 JSON 里的 id（数字或字符串）无损转成字符串（float64 直接 Sprint 会变科学计数法）
func jid(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	case string:
		return n
	}
	return ""
}

func normDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if i := strings.IndexByte(d, '/'); i >= 0 {
		d = d[:i]
	}
	return strings.TrimSuffix(d, ".")
}

func jstrList(m map[string]any, key string) []string {
	out := []string{}
	for _, v := range arr(m, key) {
		if s := jstrAny(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func tycSearch(ctx context.Context, client *http.Client, keyword string, limit int) ([]CompanyBrief, error) {
	body, _ := json.Marshal(map[string]any{
		"sortType": 0, "pageSize": clamp(limit, 1, 50), "pageNum": 1,
		"word": keyword, "allowModifyQuery": 1,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api9.tianyancha.com/cloud-tempest/app/searchCompany", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", tycUA)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Version", "TYC-XCX-WEB")
	req.Header.Set("Referer", "https://tianyancha.com/")
	m, err := doHTTP("tyc", client, req)
	if err != nil {
		return nil, err
	}
	if _, ok := m["state"]; !ok {
		return nil, &EngineError{"tyc", "unexpected response shape（可能触发风控/验证码）"}
	}
	data, ok := m["data"].(map[string]any)
	if !ok {
		return nil, nil // 无结果时 data 是字符串 "无数据"
	}
	out := []CompanyBrief{}
	for _, it := range arr(data, "companyList") {
		c, ok := it.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, CompanyBrief{
			Source:      "tyc",
			ID:          jid(c["id"]),
			Name:        stripEm(jstr(c, "name")),
			LegalPerson: stripEm(jstr(c, "legalPersonName")),
			RegStatus:   jstr(c, "regStatus"),
			RegCapital:  jstr(c, "regCapital"),
			Estiblish:   jstr(c, "estiblishTime"),
			Emails:      jstrList(c, "emailList"),
			Phones:      jstrList(c, "phoneList"),
		})
	}
	return out, nil
}

func tycEquity(ctx context.Context, client *http.Client, id string) ([]equityChild, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api9.tianyancha.com/cloud-equity-provider/v4/equity/indexnode.json?id="+url.QueryEscape(id), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", tycUA)
	m, err := doHTTP("tyc", client, req)
	if err != nil {
		return nil, err
	}
	if _, ok := m["state"]; !ok {
		return nil, &EngineError{"tyc", "unexpected response shape（可能触发风控/验证码）"}
	}
	// 注意：state 常为 "warn"/"mustlogin" 但 data 完整，只读 data
	out := []equityChild{}
	for _, it := range arr(sub(m, "data"), "investorList") {
		c, ok := it.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, equityChild{
			ID:        jid(c["id"]),
			Name:      stripEm(jstr(c, "name")),
			Percent:   parsePercent(jstr(c, "percent")),
			RegStatus: jstr(c, "regStatus"),
			HasNode:   c["hasNode"] == true,
		})
	}
	return out, nil
}

func tycICP(ctx context.Context, client *http.Client, id string) ([]icpHit, error) {
	u := "https://capi.tianyancha.com/cloud-intellectual-property/intellectualProperty/icpRecordList?id=" +
		url.QueryEscape(id) + "&pageNum=1&pageSize=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", tycUA)
	req.Header.Set("Version", "TYC-XCX-WX")
	req.Header.Set("Referer", "https://servicewechat.com/")
	m, err := doHTTP("tyc", client, req)
	if err != nil {
		return nil, err
	}
	if _, ok := m["state"]; !ok {
		return nil, &EngineError{"tyc", "unexpected response shape（可能触发风控/验证码）"}
	}
	hits := []icpHit{}
	for _, it := range arr(sub(m, "data"), "item") {
		c, ok := it.(map[string]any)
		if !ok {
			continue
		}
		no := jstr(c, "liscense")
		if ym := normDomain(jstr(c, "ym")); ym != "" {
			hits = append(hits, icpHit{ym, no})
		}
		for _, w := range jstrList(c, "webSite") {
			if d := normDomain(w); d != "" {
				hits = append(hits, icpHit{d, no})
			}
		}
	}
	return hits, nil
}

// aqc* 一律不发送 Cookie：PassiveRecon 硬编码的 BAIDUID 已被百度拉黑，
// 携带旧 cookie 必触发 302 验证码；裸请求实测放行（2026-10-19 验证）。

func aqcSearch(ctx context.Context, client *http.Client, keyword string, limit int) ([]CompanyBrief, error) {
	u := "https://www.aiqicha.com/wechat/searchListAjax?q=" + url.QueryEscape(keyword) + "&t=0&p=1&s=30&o=0&f=null"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", aqcUA)
	req.Header.Set("smart-refer", "/pages/s/index?q=&t=0&fr=query")
	req.Header.Set("Referer", "https://servicewechat.com")
	m, err := doHTTP("aqc", client, req)
	if err != nil {
		return nil, err
	}
	if _, ok := m["status"]; !ok {
		return nil, &EngineError{"aqc", "unexpected response shape（可能触发百度风控/验证码）"}
	}
	out := []CompanyBrief{}
	for i, it := range arr(sub(m, "data"), "resultList") {
		if i >= limit {
			break
		}
		c, ok := it.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, CompanyBrief{
			Source:      "aqc",
			ID:          jstr(c, "pid"),
			Name:        stripEm(jstr(c, "entName")),
			LegalPerson: stripEm(jstr(c, "legalPerson")),
			RegCapital:  jstr(c, "regCap"),
			Estiblish:   jstr(c, "validityFrom"),
		})
	}
	return out, nil
}

func aqcEquity(ctx context.Context, client *http.Client, pid string) ([]equityChild, error) {
	u := "https://www.aiqicha.com/stockchart/stockchartAjax?pid=" + url.QueryEscape(pid) + "&drill=2"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", aqcUA)
	req.Header.Set("Referer", "https://www.aiqicha.com/company_detail_"+pid)
	m, err := doHTTP("aqc", client, req)
	if err != nil {
		return nil, err
	}
	if _, ok := m["status"]; !ok {
		return nil, &EngineError{"aqc", "unexpected response shape（可能触发百度风控/验证码）"}
	}
	out := []equityChild{}
	for _, it := range arr(sub(m, "data", "investRecordData"), "list") {
		c, ok := it.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, equityChild{
			ID:        jstr(c, "pid"),
			Name:      stripEm(jstr(c, "entName")),
			Percent:   parsePercent(jstr(c, "regRate")),
			RegStatus: jstr(c, "regStatus"),
			HasNode:   true, // 该接口无 hasNode 提示，递归由 depth/maxCompanies 约束
		})
	}
	return out, nil
}

func aqcICP(ctx context.Context, client *http.Client, pid string) ([]icpHit, error) {
	u := "https://www.aiqicha.com/cs/icpInfoAjax?pid=" + url.QueryEscape(pid) + "&p=1&size=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", aqcUA)
	req.Header.Set("Referer", "https://www.aiqicha.com/company_detail_"+pid)
	m, err := doHTTP("aqc", client, req)
	if err != nil {
		return nil, err
	}
	if _, ok := m["status"]; !ok {
		return nil, &EngineError{"aqc", "unexpected response shape（可能触发百度风控/验证码）"}
	}
	hits := []icpHit{}
	for _, it := range arr(sub(m, "data"), "list") { // total=0 时 list 为 null，arr() 返回 nil
		c, ok := it.(map[string]any)
		if !ok {
			continue
		}
		no := jstr(c, "icpNo")
		for _, d := range jstrList(c, "domain") {
			if nd := normDomain(d); nd != "" {
				hits = append(hits, icpHit{nd, no})
			}
		}
		for _, h := range jstrList(c, "homeSite") {
			if nd := normDomain(h); nd != "" {
				hits = append(hits, icpHit{nd, no})
			}
		}
	}
	return hits, nil
}

var requestPace = 250 * time.Millisecond // 同源请求间隔，测试置 0

func pace() {
	if requestPace > 0 {
		time.Sleep(requestPace)
	}
}

type EquityNode struct {
	Source  string  `json:"source"`
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Percent float64 `json:"percent"`
	Depth   int     `json:"depth"`
	Path    string  `json:"path"`
}

type DomainRecord struct {
	Domain  string   `json:"domain"`
	Company string   `json:"company"`
	ICPNo   string   `json:"icp_no,omitempty"`
	Sources []string `json:"sources"`
}

type CompanyReconResult struct {
	Keyword    string         `json:"keyword"`
	Companies  []CompanyBrief `json:"companies"`
	EquityTree []EquityNode   `json:"equity_tree"`
	Domains    []DomainRecord `json:"domains"`
	Errors     []string       `json:"errors"`
}

type sourceAdapter struct {
	name   string
	search func(context.Context, *http.Client, string, int) ([]CompanyBrief, error)
	equity func(context.Context, *http.Client, string) ([]equityChild, error)
	icp    func(context.Context, *http.Client, string) ([]icpHit, error)
	h11    bool // 强制 HTTP/1.1（aqc 的 WAF 断 Go HTTP/2 握手）
}

func tycAdapter() sourceAdapter {
	return sourceAdapter{name: "tyc", search: tycSearch, equity: tycEquity, icp: tycICP}
}

func aqcAdapter() sourceAdapter {
	return sourceAdapter{name: "aqc", search: aqcSearch, equity: aqcEquity, icp: aqcICP, h11: true}
}

type walkOut struct {
	companies []CompanyBrief
	tree      []EquityNode
	domains   []DomainRecord
	errs      []string
}

// walkSource：搜索 → 取首条命中为根 → BFS 穿透（visited 防环，minPercent/注销 过滤，
// maxCompanies 硬上限），每个遍历到的公司查一次 ICP 域名。
func walkSource(ctx context.Context, client *http.Client, ad sourceAdapter, keyword string,
	depth, maxCompanies int, minPercent float64, searchLimit int) walkOut {

	out := walkOut{}
	hits, err := ad.search(ctx, client, keyword, searchLimit)
	if err != nil {
		out.errs = append(out.errs, err.Error())
		return out
	}
	if len(hits) == 0 {
		return out
	}
	hits[0].Root = true
	out.companies = hits
	root := hits[0]

	type item struct {
		id, name, path string
		depth          int
	}
	visited := map[string]bool{root.ID: true}
	inTree := map[string]bool{}
	queue := []item{{root.ID, root.Name, root.Name, 1}}
	walked := 0
	for len(queue) > 0 && walked < maxCompanies {
		it := queue[0]
		queue = queue[1:]
		walked++
		pace()
		icpHits, err := ad.icp(ctx, client, it.id)
		if err != nil {
			out.errs = append(out.errs, err.Error())
		} else {
			for _, h := range icpHits {
				out.domains = append(out.domains, DomainRecord{
					Domain: h.domain, Company: it.name, ICPNo: h.icpNo, Sources: []string{ad.name},
				})
			}
		}
		if it.depth >= depth {
			continue
		}
		pace()
		children, err := ad.equity(ctx, client, it.id)
		if err != nil {
			out.errs = append(out.errs, err.Error())
			continue
		}
		for _, ch := range children {
			if ch.RegStatus == "注销" || ch.Percent < minPercent || inTree[ch.ID] {
				continue
			}
			inTree[ch.ID] = true
			p := strconv.FormatFloat(ch.Percent, 'f', -1, 64) + "%"
			nodePath := it.path + " -" + p + "-> " + ch.Name
			out.tree = append(out.tree, EquityNode{
				Source: ad.name, ID: ch.ID, Name: ch.Name,
				Percent: ch.Percent, Depth: it.depth + 1, Path: nodePath,
			})
			if !visited[ch.ID] && ch.HasNode && walked+len(queue) < maxCompanies {
				visited[ch.ID] = true
				queue = append(queue, item{ch.ID, ch.Name, nodePath, it.depth + 1})
			}
		}
	}
	return out
}

// CompanyRecon 双源并发遍历，域名按 domain 合并、sources 归集。
func CompanyRecon(ctx context.Context, keyword string, sources []string, depth int,
	minPercent float64, maxCompanies, searchLimit int) CompanyReconResult {

	depth = clamp(depth, 1, 5)
	maxCompanies = clamp(maxCompanies, 1, 100)
	searchLimit = clamp(searchLimit, 1, 20)
	if minPercent < 0 {
		minPercent = 0
	}
	if minPercent > 100 {
		minPercent = 100
	}
	if len(sources) == 0 {
		sources = []string{"tyc", "aqc"}
	}
	empty := CompanyReconResult{
		Keyword: keyword, Companies: []CompanyBrief{},
		EquityTree: []EquityNode{}, Domains: []DomainRecord{}, Errors: []string{},
	}
	ads := []sourceAdapter{}
	bad := []string{}
	for _, s := range sources {
		switch s {
		case "tyc":
			ads = append(ads, tycAdapter())
		case "aqc":
			ads = append(ads, aqcAdapter())
		default:
			bad = append(bad, s)
		}
	}
	if len(bad) > 0 {
		empty.Errors = append(empty.Errors, fmt.Sprintf("unknown source(s): %v; available: [tyc aqc]", bad))
		return empty
	}

	outs := make([]walkOut, len(ads))
	var wg sync.WaitGroup
	for i, ad := range ads {
		wg.Add(1)
		go func(i int, ad sourceAdapter) {
			defer wg.Done()
			client := httpClientFor(ad.name)
			if ad.h11 {
				client = http11ClientFor(ad.name)
			}
			outs[i] = walkSource(ctx, client, ad, keyword, depth, maxCompanies, minPercent, searchLimit)
		}(i, ad)
	}
	wg.Wait()

	res := empty
	domainIdx := map[string]int{}
	for _, o := range outs {
		res.Companies = append(res.Companies, o.companies...)
		res.EquityTree = append(res.EquityTree, o.tree...)
		res.Errors = append(res.Errors, o.errs...)
		for _, d := range o.domains {
			if i, ok := domainIdx[d.Domain]; ok {
				ex := &res.Domains[i]
				seen := false
				for _, s := range ex.Sources {
					if s == d.Sources[0] {
						seen = true
						break
					}
				}
				if !seen {
					ex.Sources = append(ex.Sources, d.Sources[0])
				}
				continue
			}
			domainIdx[d.Domain] = len(res.Domains)
			res.Domains = append(res.Domains, d)
		}
	}
	return res
}
