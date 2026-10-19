package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// pathFixture routes canned JSON bodies by request path.
func pathFixture(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestStripEm(t *testing.T) {
	if got := stripEm("深圳市<em>腾讯</em>网域"); got != "深圳市腾讯网域" {
		t.Fatalf("stripEm = %q", got)
	}
}

func TestParsePercent(t *testing.T) {
	cases := map[string]float64{"90%": 90, "3.564292%": 3.564292, "": 0, "-": 0, " 100% ": 100}
	for in, want := range cases {
		if got := parsePercent(in); got != want {
			t.Fatalf("parsePercent(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTycSearchParsesCompanies(t *testing.T) {
	srv := pathFixture(t, map[string]string{
		"/cloud-tempest/app/searchCompany": `{"state":"ok","data":{"companyList":[
			{"id":485687893,"name":"深圳市<em>腾讯</em>网域计算机网络有限公司","legalPersonName":"何迪亮",
			 "regStatus":"存续","regCapital":"2401000万人民币","estiblishTime":"1997-04-28 00:00:00.0",
			 "emailList":["a@tencent.com"],"phoneList":["0755-86013388"]}]}}`,
	})
	defer srv.Close()
	out, err := tycSearch(context.Background(), rewriteHostClient(srv), "腾讯", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 company, got %d", len(out))
	}
	c := out[0]
	if c.ID != "485687893" { // float64 不得变成科学计数法
		t.Fatalf("id mangled: %q", c.ID)
	}
	if c.Name != "深圳市腾讯网域计算机网络有限公司" {
		t.Fatalf("em not stripped: %q", c.Name)
	}
	if len(c.Emails) != 1 || len(c.Phones) != 1 || c.LegalPerson != "何迪亮" {
		t.Fatalf("fields missing: %+v", c)
	}
}

func TestTycSearchNoDataString(t *testing.T) {
	srv := pathFixture(t, map[string]string{
		"/cloud-tempest/app/searchCompany": `{"state":"ok","data":"无数据"}`,
	})
	defer srv.Close()
	out, err := tycSearch(context.Background(), rewriteHostClient(srv), "不存在", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("want 0, got %d", len(out))
	}
}

func TestTycEquityToleratesMustloginWarn(t *testing.T) {
	srv := pathFixture(t, map[string]string{
		"/cloud-equity-provider/v4/equity/indexnode.json": `{"state":"warn","special":"mustlogin","data":{"investorList":[
			{"name":"北京赢销通科技有限公司","id":6459547117,"percent":"90%","hasNode":true},
			{"name":"已注销公司","id":999,"percent":"100%","regStatus":"注销","hasNode":false}]}}`,
	})
	defer srv.Close()
	out, err := tycEquity(context.Background(), rewriteHostClient(srv), "21463580")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2, got %d", len(out))
	}
	if out[0].ID != "6459547117" || out[0].Percent != 90 || !out[0].HasNode {
		t.Fatalf("bad child: %+v", out[0])
	}
	if out[1].RegStatus != "注销" {
		t.Fatalf("regStatus lost: %+v", out[1])
	}
}

func TestTycICPExtractsDomains(t *testing.T) {
	srv := pathFixture(t, map[string]string{
		"/cloud-intellectual-property/intellectualProperty/icpRecordList": `{"state":"ok","data":{"itemTotal":1,"item":[
			{"ym":"21kunpeng.com","liscense":"辽ICP备11004471号-2","webSite":["www.21kunpeng.com"]}]}}`,
	})
	defer srv.Close()
	hits, err := tycICP(context.Background(), rewriteHostClient(srv), "2329122847")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || hits[0].domain != "21kunpeng.com" || hits[0].icpNo != "辽ICP备11004471号-2" {
		t.Fatalf("bad hits: %+v", hits)
	}
}

func TestTycSearchDetectsRiskControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>captcha</html>"))
	}))
	defer srv.Close()
	_, err := tycSearch(context.Background(), rewriteHostClient(srv), "腾讯", 10)
	if err == nil {
		t.Fatal("want risk-control error, got nil")
	}
}
