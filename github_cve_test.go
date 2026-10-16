package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitHubSearchCodeRequiresToken(t *testing.T) {
	_, err := GitHubSearch(context.Background(), http.DefaultClient, `"x.com" apikey`, "code", 5)
	if err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("want GITHUB_TOKEN error, got %v", err)
	}
}

func TestGitHubSearchRejectsBadType(t *testing.T) {
	_, err := GitHubSearch(context.Background(), http.DefaultClient, "x", "users", 5)
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("want unknown type error, got %v", err)
	}
}

func TestGitHubSearchParsesItems(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "gt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gt" {
			t.Error("missing bearer token")
		}
		fmt.Fprint(w, `{"total_count":1,"incomplete_results":false,"items":[
			{"path":"config.py","html_url":"https://github.com/a/b/blob/main/config.py",
			 "repository":{"full_name":"a/b"}}]}`)
	}))
	defer srv.Close()
	res, err := GitHubSearch(context.Background(), rewriteHostClient(srv), "q", "code", 5)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || len(res.Items) != 1 {
		t.Fatalf("want 1 item, got %+v", res)
	}
	if res.Items[0]["repo"] != "a/b" || res.Items[0]["path"] != "config.py" {
		t.Fatalf("item parse wrong: %+v", res.Items[0])
	}
}

func TestCVESearchByIDUsesCveIDParam(t *testing.T) {
	var gotID, gotKeyword string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = r.URL.Query().Get("cveId")
		gotKeyword = r.URL.Query().Get("keywordSearch")
		fmt.Fprint(w, `{"totalResults":1,"vulnerabilities":[{"cve":{
			"id":"CVE-2021-44228","published":"2021-12-10T10:15:09.143",
			"descriptions":[{"lang":"en","value":"Log4j RCE"},{"lang":"zh","value":"x"}],
			"metrics":{"cvssMetricV31":[{"baseSeverity":"CRITICAL",
				"cvssData":{"baseScore":10.0}}]},
			"references":[{"url":"https://nvd.nist.gov/1"},{"url":"https://nvd.nist.gov/2"}]}}]}`)
	}))
	defer srv.Close()

	res, err := CVESearch(context.Background(), rewriteHostClient(srv), "cve-2021-44228", 5)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != "CVE-2021-44228" || gotKeyword != "" {
		t.Fatalf("routing wrong: cveId=%q keyword=%q", gotID, gotKeyword)
	}
	e := res.Results[0]
	if e.Description != "Log4j RCE" || e.Severity != "CRITICAL" || e.Score != 10.0 {
		t.Fatalf("entry parse wrong: %+v", e)
	}
	if len(e.References) != 2 {
		t.Fatalf("references: %+v", e.References)
	}
}

func TestCVESearchKeywordPath(t *testing.T) {
	var gotKeyword string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKeyword = r.URL.Query().Get("keywordSearch")
		fmt.Fprint(w, `{"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer srv.Close()
	if _, err := CVESearch(context.Background(), rewriteHostClient(srv), "log4j", 5); err != nil {
		t.Fatal(err)
	}
	if gotKeyword != "log4j" {
		t.Fatalf("keyword path wrong: %q", gotKeyword)
	}
}
