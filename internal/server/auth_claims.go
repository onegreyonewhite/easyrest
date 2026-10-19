package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	cachepkg "github.com/patrickmn/go-cache"
)

var authPluginOrder atomic.Pointer[[]string]

// authCredential is where one loaded auth plugin reads its secret.
type authCredential struct {
	Key      string
	IsCookie bool
}

var authCredentials atomic.Pointer[map[string]authCredential]

// claimsCacheEntry stores claims and user_id for a token
// Used for caching in Authenticate
// Claims is jwt.MapClaims, UserID is string
// TTL is managed by go-cache

type claimsCacheEntry struct {
	Claims jwt.MapClaims
	UserID string
}

// claimsCache is a package-level cache for token claims and user_id
var claimsCache *cachepkg.Cache

func setAuthPluginOrder(plugins map[string]easyrest.AuthPlugin) {
	order := authPluginTrialOrder(plugins)
	authPluginOrder.Store(&order)
}

func authPluginOrderSnapshot() []string {
	if orderPtr := authPluginOrder.Load(); orderPtr != nil {
		return *orderPtr
	}
	plugins := AuthPlugins.Load()
	if plugins == nil {
		return nil
	}
	return authPluginTrialOrder(*plugins)
}

func ResetClaimsCache() {
	if claimsCache != nil {
		claimsCache.Flush()
	}
}

// DecodeTokenWithoutValidation decodes a JWT token without validating its signature.
var base64NoPadDecoder = base64.URLEncoding.WithPadding(base64.NoPadding)

func DecodeTokenWithoutValidation(tokenStr string) (jwt.MapClaims, error) {
	first := strings.IndexByte(tokenStr, '.')
	if first < 0 {
		return nil, errors.New("invalid token format")
	}
	second := strings.IndexByte(tokenStr[first+1:], '.')
	if second < 0 {
		return nil, errors.New("invalid token format")
	}
	payload := tokenStr[first+1 : first+1+second]

	decoded, err := base64NoPadDecoder.DecodeString(payload)
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	err = json.Unmarshal(decoded, &claims)
	return jwt.MapClaims(claims), err
}

// authPluginTrialOrder returns plugin names in a deterministic order: local/cheap
// auth first, then network-bound plugins, then any others alphabetically.
func authPluginTrialOrder(plugins map[string]easyrest.AuthPlugin) []string {
	priority := []string{"jwt", "jwtsession", "basic", "apikey", "dbsession", "oidc", "awssigv4"}
	seen := make(map[string]struct{}, len(plugins))
	order := make([]string, 0, len(plugins))
	for _, name := range priority {
		if _, ok := plugins[name]; ok {
			order = append(order, name)
			seen[name] = struct{}{}
		}
	}
	rest := make([]string, 0, len(plugins))
	for name := range plugins {
		if _, ok := seen[name]; !ok {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	return append(order, rest...)
}

func credentialFrom(info easyrest.AuthInfo) authCredential {
	key := info.Key
	if key == "" {
		key = "Authorization"
	}
	return authCredential{Key: key, IsCookie: info.IsCookie}
}

func authCredentialValue(r *http.Request, src authCredential) string {
	key := src.Key
	if key == "" {
		key = "Authorization"
	}
	if !src.IsCookie {
		return r.Header.Get(key)
	}
	cookie, err := r.Cookie(key)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func authCacheKey(r *http.Request) string {
	sources := authCredentials.Load()
	if sources == nil || len(*sources) == 0 {
		return r.Header.Get("Authorization")
	}
	names := make([]string, 0, len(*sources))
	for name := range *sources {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		value := authCredentialValue(r, (*sources)[name])
		if value == "" {
			continue
		}
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, "\n")
}

func authHeadersForPlugins(r *http.Request) (map[string]string, map[string]any) {
	headers, pluginHeaders := buildRequestHeaderMaps(r.Header)
	sources := authCredentials.Load()
	if sources == nil {
		return headers, pluginHeaders
	}
	for _, src := range *sources {
		if !src.IsCookie {
			continue
		}
		value := authCredentialValue(r, src)
		if value == "" {
			continue
		}
		key := src.Key
		if key == "" {
			key = "Authorization"
		}
		headers[strings.ToLower(key)] = value
	}
	return headers, pluginHeaders
}

// CheckScope verifies if the claims contain the required scope.
func CheckScope(claims jwt.MapClaims, required string) bool {
	scopeVal, ok := claims["scope"]
	if !ok {
		return false
	}
	scopesStr, ok := scopeVal.(string)
	if !ok {
		return false
	}
	for s := range strings.FieldsSeq(scopesStr) {
		if s == required {
			return true
		}
		if (strings.HasSuffix(required, "read") && s == "read") ||
			(strings.HasSuffix(required, "write") && s == "write") {
			return true
		}
	}
	return false
}

// extractUserIDFromClaims extracts the user ID from JWT claims.
func extractUserIDFromClaims(claims jwt.MapClaims, searchPath string) string {
	if val, ok := claims[searchPath]; ok {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// getTokenClaims retrieves token claims from the request context.
func getTokenClaims(r *http.Request) jwt.MapClaims {
	if claims, ok := r.Context().Value(TokenClaimsKey).(jwt.MapClaims); ok {
		return claims
	}
	return nil
}

func tableScope(table, suffix string) string {
	var b strings.Builder
	b.Grow(len(table) + len(suffix))
	b.WriteString(table)
	b.WriteString(suffix)
	return b.String()
}
