package main

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Proxy resolution, highest priority first:
//  1. -proxy flag
//  2. CYBERMAP_PROXY env var (project-scoped; never collides with other tools)
//  3. HTTP_PROXY/HTTPS_PROXY env vars (Go default, fallback only)
//
// CYBERMAP_PROXY_ENGINES is a comma-separated allowlist: when set, only the
// listed engines use the explicit proxy and the rest connect directly
// (e.g. "shodan,censys,virustotal" proxies only the overseas platforms).
var (
	directClient *http.Client
	proxyClient  *http.Client
	proxyEngines map[string]bool
)

func newTransport(proxy func(*http.Request) (*url.URL, error)) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = proxy
	t.ResponseHeaderTimeout = 60 * time.Second
	return t
}

func initProxy(flagValue string) {
	proxyURL := flagValue
	if proxyURL == "" {
		proxyURL = envKey("CYBERMAP_PROXY")
	}
	if v := envKey("CYBERMAP_PROXY_ENGINES"); v != "" {
		proxyEngines = map[string]bool{}
		for _, name := range strings.Split(v, ",") {
			if n := strings.TrimSpace(name); n != "" {
				proxyEngines[n] = true
			}
		}
	}

	direct := http.ProxyFromEnvironment
	if proxyURL != "" {
		// Explicit proxy configured: non-proxied engines must bypass any
		// ambient env proxy, otherwise routing by engine is meaningless.
		direct = nil
		u, err := url.Parse(proxyURL)
		if err != nil {
			log.Fatal("invalid proxy URL: ", err)
		}
		proxyClient = &http.Client{Timeout: 90 * time.Second, Transport: newTransport(http.ProxyURL(u))}
	}
	directClient = &http.Client{Timeout: 90 * time.Second, Transport: newTransport(direct)}
}

// httpClientFor picks the proxied or direct client for an engine.
func httpClientFor(engine string) *http.Client {
	if proxyClient != nil && (len(proxyEngines) == 0 || proxyEngines[engine]) {
		return proxyClient
	}
	return directClient
}
