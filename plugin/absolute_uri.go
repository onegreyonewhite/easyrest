package plugin

import "strings"

// BuildAbsoluteUri joins the public scheme, host, and prefix stored on a
// plugin context with a path and query.
func BuildAbsoluteUri(ctx map[string]any, pathAndQuery string) string {
	request, _ := ctx["request"].(map[string]any)
	scheme, _ := request["scheme"].(string)
	if scheme == "" {
		scheme = "http"
	}
	host, _ := request["host"].(string)
	prefix, _ := request["prefix"].(string)
	path, query, _ := strings.Cut(pathAndQuery, "?")
	return scheme + "://" + host + joinPublicPath(prefix, path) + publicQuery(query)
}

func joinPublicPath(prefix, path string) string {
	prefix = strings.Trim(prefix, "/")
	path = strings.TrimLeft(path, "/")
	switch {
	case prefix == "" && path == "":
		return "/"
	case prefix == "":
		return "/" + path
	case path == "":
		return "/" + prefix
	default:
		return "/" + prefix + "/" + path
	}
}

func publicQuery(query string) string {
	if query == "" {
		return ""
	}
	return "?" + query
}
