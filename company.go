package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
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
