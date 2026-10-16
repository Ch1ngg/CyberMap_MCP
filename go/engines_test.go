package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- merge ---

func TestMergeAssetsDedupsAndMergesSources(t *testing.T) {
	in := []Asset{
		{IP: "1.1.1.1", Port: 80, Host: "a.com", Protocol: "http", Title: "T", Sources: []string{"fofa"}},
		{IP: "1.1.1.1", Port: 80, Host: "a.com", Protocol: "http", Sources: []string{"quake"}},
		{IP: "2.2.2.2", Port: 443, Sources: []string{"shodan"}},
	}
	out := MergeAssets(in)
	if len(out) != 2 {
		t.Fatalf("want 2 merged, got %d", len(out))
	}
	if fmt.Sprint(out[0].Sources) != "[fofa quake]" || out[0].Title != "T" {
		t.Fatalf("merge wrong: %+v", out[0])
	}
}

func TestMergeAssetsKeepsIdentityLess(t *testing.T) {
	out := MergeAssets([]Asset{{Title: "x"}, {Title: "x"}})
	if len(out) != 2 {
		t.Fatalf("identity-less assets must not dedup, got %d", len(out))
	}
}

// --- hunter page_size ---

func TestHunterRoundsUpPageSizeAndSlices(t *testing.T) {
	t.Setenv("HUNTER_KEY", "hk")
	var gotPageSize string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPageSize = r.URL.Query().Get("page_size")
		rows := []string{}
		for i := range 10 {
			rows = append(rows, fmt.Sprintf(`{"ip":"10.0.0.%d","port":80}`, i))
		}
		fmt.Fprintf(w, `{"code":200,"data":{"arr":[%s]}}`, strings.Join(rows, ","))
	}))
	defer srv.Close()

	// Point the adapter at the test server by monkeying the URL via client
	// transport rewrite.
	client := rewriteHostClient(srv)
	assets, err := Hunter{}.Search(context.Background(), client, "x", 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	if gotPageSize != "10" {
		t.Fatalf("page_size: want 10, got %q", gotPageSize)
	}
	if len(assets) != 5 {
		t.Fatalf("want 5 sliced assets, got %d", len(assets))
	}
}

func TestHunterNon200CodeRaises(t *testing.T) {
	t.Setenv("HUNTER_KEY", "hk")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":401,"message":"积分不足"}`)
	}))
	defer srv.Close()
	_, err := Hunter{}.Search(context.Background(), rewriteHostClient(srv), "x", 20, 1)
	if err == nil || !strings.Contains(err.Error(), "积分不足") {
		t.Fatalf("want 积分不足 error, got %v", err)
	}
}

// --- shodan ---

func TestShodanNumericIPAndClamp(t *testing.T) {
	t.Setenv("SHODAN_KEY", "sk")
	matches := []string{}
	for i := range 4 {
		// numeric ip (new format), no ip_str
		matches = append(matches, fmt.Sprintf(`{"ip":16909060,"port":%d,"transport":"tcp"}`, 8000+i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"matches":[%s]}`, strings.Join(matches, ","))
	}))
	defer srv.Close()
	assets, err := Shodan{}.Search(context.Background(), rewriteHostClient(srv), "x", 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 3 {
		t.Fatalf("limit clamp: want 3, got %d", len(assets))
	}
	if assets[0].IP != "1.2.3.4" {
		t.Fatalf("numeric ip decode: want 1.2.3.4, got %q", assets[0].IP)
	}
}

// --- query routing ---

func TestNormalizeQueriesDictRouting(t *testing.T) {
	q, err := normalizeQueries(map[string]any{"fofa": `app="x"`, "shodan": "product:x"},
		[]SearchEngine{Fofa{}, Shodan{}, Hunter{}})
	if err != nil {
		t.Fatal(err)
	}
	if q["fofa"] != `app="x"` || q["shodan"] != "product:x" {
		t.Fatalf("routing wrong: %v", q)
	}
	if _, ok := q["hunter"]; ok {
		t.Fatal("hunter must be skipped when absent from dict")
	}
}

func TestNormalizeQueriesRejectsUnknownAndEmpty(t *testing.T) {
	if _, err := normalizeQueries(map[string]any{"nope": "x"}, SearchEngines); err == nil {
		t.Fatal("want unknown-engine error")
	}
	if _, err := normalizeQueries(map[string]any{"fofa": "x"}, []SearchEngine{Quake{}}); err == nil {
		t.Fatal("want no-entry error")
	}
	if _, err := normalizeQueries(42, SearchEngines); err == nil {
		t.Fatal("want type error for non-string non-object query")
	}
}

// rewriteHostClient points every request at srv (test-only transport rewrite).
func rewriteHostClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: rewriteTransport{srv.URL}}
}

type rewriteTransport struct{ base string }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(rt.base, "http://")
	return http.DefaultTransport.RoundTrip(req)
}
