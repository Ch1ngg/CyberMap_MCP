package main

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
)

// MapSearchResult mirrors the Python tool's JSON output.
type MapSearchResult struct {
	Query      any      `json:"query"`
	TotalRaw   int      `json:"total_raw,omitempty"`
	TotalDedup int      `json:"total_dedup,omitempty"`
	Assets     []Asset  `json:"assets"`
	Errors     []string `json:"errors"`
	Hint       any      `json:"hint,omitempty"`
}

func engineByName(name string) SearchEngine {
	for _, e := range SearchEngines {
		if e.Name() == name {
			return e
		}
	}
	return nil
}

func allEngines() []Engine {
	out := make([]Engine, 0, len(SearchEngines)+len(IntelEngines))
	for _, e := range SearchEngines {
		out = append(out, e)
	}
	return append(out, IntelEngines...)
}

func selectEngines(names []string) ([]SearchEngine, error) {
	if len(names) == 0 {
		return SearchEngines, nil
	}
	bad := []string{}
	out := []SearchEngine{}
	for _, n := range names {
		e := engineByName(n)
		if e == nil {
			bad = append(bad, n)
		} else {
			out = append(out, e)
		}
	}
	if len(bad) > 0 {
		known := []string{}
		for _, e := range SearchEngines {
			known = append(known, e.Name())
		}
		sort.Strings(known)
		return nil, fmt.Errorf("unknown engine(s): %v; available: %v", bad, known)
	}
	return out, nil
}

// normalizeQueries turns query (string or map[string]string) into a
// per-engine routing table.
func normalizeQueries(query any, selected []SearchEngine) (map[string]string, error) {
	if m, ok := query.(map[string]any); ok {
		known := map[string]bool{}
		for _, e := range SearchEngines {
			known[e.Name()] = true
		}
		bad := []string{}
		for k := range m {
			if !known[k] {
				bad = append(bad, k)
			}
		}
		if len(bad) > 0 {
			sort.Strings(bad)
			names := []string{}
			for _, e := range SearchEngines {
				names = append(names, e.Name())
			}
			sort.Strings(names)
			return nil, fmt.Errorf("unknown engine(s) in query: %v; available: %v", bad, names)
		}
		queries := map[string]string{}
		for _, e := range selected {
			if v, ok := m[e.Name()]; ok {
				queries[e.Name()] = fmt.Sprint(v)
			}
		}
		if len(queries) == 0 {
			return nil, fmt.Errorf("query dict has no entry for any selected engine")
		}
		return queries, nil
	}
	s, ok := query.(string)
	if !ok {
		return nil, fmt.Errorf("query must be a string or an object mapping engine name to query string")
	}
	queries := map[string]string{}
	for _, e := range selected {
		queries[e.Name()] = s
	}
	return queries, nil
}

func MapSearch(ctx context.Context, query any, engines []string, limit, page int) (MapSearchResult, error) {
	selected, err := selectEngines(engines)
	if err != nil {
		return MapSearchResult{}, err
	}
	queries, err := normalizeQueries(query, selected)
	if err != nil {
		return MapSearchResult{}, err
	}
	runnable := []SearchEngine{}
	for _, e := range selected {
		if _, ok := queries[e.Name()]; ok && configured(e.EnvVars()) {
			runnable = append(runnable, e)
		}
	}
	if len(runnable) == 0 {
		missing := []map[string]any{}
		for _, e := range selected {
			if _, ok := queries[e.Name()]; ok {
				missing = append(missing, map[string]any{
					"engine": e.Name(), "env": e.EnvVars(), "doc": e.APIDoc(),
				})
			}
		}
		return MapSearchResult{
			Query:  query,
			Assets: []Asset{},
			Errors: []string{},
			Hint: map[string]any{
				"message":   "no engine key configured",
				"configure": missing,
			},
		}, nil
	}

	type outcome struct {
		assets []Asset
		err    string
	}
	results := make([]outcome, len(runnable))
	var wg sync.WaitGroup
	for i, e := range runnable {
		wg.Add(1)
		go func(i int, e SearchEngine) {
			defer wg.Done()
			assets, err := e.Search(ctx, httpClientFor(e.Name()), queries[e.Name()], limit, page)
			if err != nil {
				results[i].err = err.Error()
			} else {
				results[i].assets = assets
			}
		}(i, e)
	}
	wg.Wait()

	all := []Asset{}
	errs := []string{}
	for _, r := range results {
		all = append(all, r.assets...)
		if r.err != "" {
			errs = append(errs, r.err)
		}
	}
	merged := MergeAssets(all)
	return MapSearchResult{
		Query:      query,
		TotalRaw:   len(all),
		TotalDedup: len(merged),
		Assets:     merged,
		Errors:     errs,
	}, nil
}

type HostIntelResult struct {
	Target string         `json:"target"`
	Intel  map[string]any `json:"intel"`
	Errors []string       `json:"errors"`
}

func HostIntel(ctx context.Context, target string) HostIntelResult {
	_, ipErr := netip.ParseAddr(target)
	isIP := ipErr == nil

	out := HostIntelResult{Target: target, Intel: map[string]any{}, Errors: []string{}}
	tb := ThreatBook{}
	vt := VirusTotal{}

	if isIP {
		if configured(tb.EnvVars()) {
			rep, err := tb.IPReputation(ctx, httpClientFor(tb.Name()), target)
			if err != nil {
				out.Errors = append(out.Errors, err.Error())
			} else {
				out.Intel[tb.Name()] = rep
			}
		}
	}
	if configured(vt.EnvVars()) {
		rep, err := vt.Report(ctx, httpClientFor(vt.Name()), target, isIP)
		if err != nil {
			out.Errors = append(out.Errors, err.Error())
		} else {
			out.Intel[vt.Name()] = rep
		}
	}
	if len(out.Intel) == 0 && len(out.Errors) == 0 {
		out.Errors = append(out.Errors, "no intel engine configured: set THREATBOOK_KEY and/or VT_KEY")
	}
	return out
}

func EngineStatus() []map[string]any {
	searchSet := map[string]bool{}
	for _, e := range SearchEngines {
		searchSet[e.Name()] = true
	}
	rows := []map[string]any{}
	for _, e := range allEngines() {
		mode := "intel"
		if searchSet[e.Name()] {
			mode = "search"
		}
		rows = append(rows, map[string]any{
			"engine":     e.Name(),
			"mode":       mode,
			"configured": configured(e.EnvVars()),
			"env_vars":   e.EnvVars(),
			"api_doc":    e.APIDoc(),
		})
	}
	return rows
}
