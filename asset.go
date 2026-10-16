package main

// Asset is the unified asset record across engines.
// Empty fields are omitted from JSON, mirroring the Python `as_dict`.
type Asset struct {
	IP       string   `json:"ip,omitempty"`
	Port     int      `json:"port,omitempty"`
	Host     string   `json:"host,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	URL      string   `json:"url,omitempty"`
	Title    string   `json:"title,omitempty"`
	Service  string   `json:"service,omitempty"`
	Product  string   `json:"product,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Org      string   `json:"org,omitempty"`
	Country  string   `json:"country,omitempty"`
	City     string   `json:"city,omitempty"`
	Sources  []string `json:"sources,omitempty"`
}

type dedupKey struct {
	ip       string
	port     int
	host     string
	protocol string
}

// key returns nil when the asset carries no identity fields at all.
func (a Asset) key() *dedupKey {
	if a.IP == "" && a.Host == "" && a.Domain == "" {
		return nil
	}
	host := a.Host
	if host == "" {
		host = a.Domain
	}
	return &dedupKey{a.IP, a.Port, host, a.Protocol}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// MergeAssets dedups by (ip, port, host/domain, protocol), merging sources
// and filling empty fields from later duplicates.
func MergeAssets(assets []Asset) []Asset {
	merged := map[dedupKey]*Asset{}
	order := []dedupKey{}
	tail := []Asset{}
	for _, a := range assets {
		k := a.key()
		if k == nil {
			tail = append(tail, a)
			continue
		}
		if m, ok := merged[*k]; ok {
			for _, s := range a.Sources {
				if !contains(m.Sources, s) {
					m.Sources = append(m.Sources, s)
				}
			}
			mergeEmpty(m, a)
		} else {
			cp := a
			merged[*k] = &cp
			order = append(order, *k)
		}
	}
	out := make([]Asset, 0, len(order)+len(tail))
	for _, k := range order {
		out = append(out, *merged[k])
	}
	return append(out, tail...)
}

func mergeEmpty(m *Asset, a Asset) {
	if m.IP == "" {
		m.IP = a.IP
	}
	if m.Port == 0 {
		m.Port = a.Port
	}
	if m.Host == "" {
		m.Host = a.Host
	}
	if m.Domain == "" {
		m.Domain = a.Domain
	}
	if m.URL == "" {
		m.URL = a.URL
	}
	if m.Title == "" {
		m.Title = a.Title
	}
	if m.Service == "" {
		m.Service = a.Service
	}
	if m.Product == "" {
		m.Product = a.Product
	}
	if m.Protocol == "" {
		m.Protocol = a.Protocol
	}
	if m.Org == "" {
		m.Org = a.Org
	}
	if m.Country == "" {
		m.Country = a.Country
	}
	if m.City == "" {
		m.City = a.City
	}
}

// EngineError is an auth/config/API failure; message is model-readable.
type EngineError struct {
	Engine  string
	Message string
}

func (e *EngineError) Error() string { return "[" + e.Engine + "] " + e.Message }
