package main

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// NVD CVE API 2.0: https://nvd.nist.gov/developers/vulnerabilities
// No key required; NVD_API_KEY raises the rate limit.

var cveIDPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

type CVEEntry struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Score       float64  `json:"score,omitempty"`
	Published   string   `json:"published,omitempty"`
	References  []string `json:"references,omitempty"`
}

type CVEResult struct {
	Query   string     `json:"query"`
	Total   int        `json:"total"`
	Results []CVEEntry `json:"results"`
}

func CVESearch(ctx context.Context, client *http.Client, query string, limit int) (CVEResult, error) {
	const name = "nvd"
	query = strings.TrimSpace(query)
	params := map[string]string{
		"resultsPerPage": strconv.Itoa(clamp(limit, 1, 100)),
	}
	if cveIDPattern.MatchString(query) {
		params["cveId"] = strings.ToUpper(query)
	} else {
		params["keywordSearch"] = query
	}
	headers := map[string]string{}
	if k := envKey("NVD_API_KEY"); k != "" {
		headers["apiKey"] = k
	}
	data, err := getJSON(ctx, name, client,
		"https://services.nvd.nist.gov/rest/json/cves/2.0", params, headers)
	if err != nil {
		return CVEResult{}, err
	}
	out := CVEResult{Query: query, Total: jint(data, "totalResults"), Results: []CVEEntry{}}
	for _, v := range arr(data, "vulnerabilities") {
		wrap, ok := v.(map[string]any)
		if !ok {
			continue
		}
		cve := sub(wrap, "cve")
		e := CVEEntry{ID: jstr(cve, "id"), Published: jstr(cve, "published")}
		// English description
		for _, d := range arr(cve, "descriptions") {
			if dm, ok := d.(map[string]any); ok && jstr(dm, "lang") == "en" {
				e.Description = jstr(dm, "value")
				break
			}
		}
		// Prefer CVSS v3.1, fall back to v3.0 then v2.
		metrics := sub(cve, "metrics")
		for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if ms := arr(metrics, key); len(ms) > 0 {
				if mm, ok := ms[0].(map[string]any); ok {
					cvss := sub(mm, "cvssData")
					e.Score = jfloat(cvss, "baseScore")
					e.Severity = first(jstr(mm, "baseSeverity"), jstr(cvss, "baseSeverity"))
				}
				break
			}
		}
		for _, r := range arr(cve, "references") {
			if rm, ok := r.(map[string]any); ok {
				if u := jstr(rm, "url"); u != "" {
					e.References = append(e.References, u)
				}
			}
			if len(e.References) >= 5 {
				break
			}
		}
		out.Results = append(out.Results, e)
	}
	return out, nil
}

func jfloat(m map[string]any, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}
