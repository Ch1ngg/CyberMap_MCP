package main

import (
	"context"
	"fmt"
	"net/http"
)

// GitHub Search API: https://docs.github.com/en/rest/search
// code search requires GITHUB_TOKEN; repositories/issues work without but
// with a much lower rate limit.

type GitHubResult struct {
	Type     string           `json:"type"`
	Total    int              `json:"total"`
	Items    []map[string]any `json:"items"`
	Warnings []string         `json:"warnings,omitempty"`
}

func GitHubSearch(ctx context.Context, client *http.Client, query, searchType string, limit int) (GitHubResult, error) {
	const name = "github"
	if searchType == "" {
		searchType = "code"
	}
	switch searchType {
	case "code", "repositories", "issues":
	default:
		return GitHubResult{}, &EngineError{name,
			fmt.Sprintf("unknown type %q: want code | repositories | issues", searchType)}
	}
	token := envKey("GITHUB_TOKEN")
	if token == "" && searchType == "code" {
		return GitHubResult{}, &EngineError{name,
			"code search requires GITHUB_TOKEN (repositories/issues search works without)"}
	}
	data, err := getJSON(ctx, name, client,
		"https://api.github.com/search/"+searchType,
		map[string]string{"q": query, "per_page": fmt.Sprint(clamp(limit, 1, 100))},
		githubHeaders(token))
	if err != nil {
		return GitHubResult{}, err
	}
	out := GitHubResult{Type: searchType, Total: jint(data, "total_count"), Items: []map[string]any{}}
	if v, ok := data["incomplete_results"].(bool); ok && v {
		out.Warnings = append(out.Warnings, "incomplete_results: GitHub timed out; narrow the query")
	}
	for _, it := range arr(data, "items") {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		out.Items = append(out.Items, githubItem(searchType, m))
	}
	return out, nil
}

func githubHeaders(token string) map[string]string {
	h := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	return h
}

func githubItem(searchType string, m map[string]any) map[string]any {
	switch searchType {
	case "code":
		return map[string]any{
			"repo": jstr(sub(m, "repository"), "full_name"),
			"path": jstr(m, "path"),
			"url":  jstr(m, "html_url"),
		}
	case "repositories":
		return map[string]any{
			"repo":        jstr(m, "full_name"),
			"description": jstr(m, "description"),
			"url":         jstr(m, "html_url"),
			"stars":       jint(m, "stargazers_count"),
			"language":    jstr(m, "language"),
			"updated_at":  jstr(m, "updated_at"),
		}
	default: // issues
		return map[string]any{
			"title": jstr(m, "title"),
			"url":   jstr(m, "html_url"),
			"state": jstr(m, "state"),
			"repo":  jstr(m, "repository_url"),
		}
	}
}
