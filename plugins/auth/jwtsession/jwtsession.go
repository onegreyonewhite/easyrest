// Package jwtsession authenticates a request from a signed JWT cookie.
// The host copies the cookie into the headers map. This plugin does not set cookies.
package jwtsession

import (
	"fmt"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
)

// Plugin reads claims from a JWT stored in a cookie.
type Plugin struct {
	host   easyrest.HostRPC
	secret string
	cookie string
}

var _ easyrest.AuthPlugin = (*Plugin)(nil)

// New returns a JWT session auth plugin.
func New() *Plugin { return &Plugin{} }

// Init stores the JWT secret and a cookie apiKey schema. It does not parse tokens.
func (p *Plugin) Init(settings map[string]any, host easyrest.HostRPC) (easyrest.AuthInfo, error) {
	p.host = host
	if settings != nil {
		p.secret, _ = settings["jwt_secret"].(string)
	}
	p.cookie = sessionSetting(settings, "cookie", "session")
	info := easyrest.NewAuthInfo(map[string]any{
		"type": "apiKey",
		"name": p.cookie,
		"in":   "cookie",
	})
	info.Key = p.cookie
	info.IsCookie = true
	return info, nil
}

func sessionSetting(settings map[string]any, key, fallback string) string {
	if settings == nil {
		return fallback
	}
	value, _ := settings[key].(string)
	if value == "" {
		return fallback
	}
	return value
}

// Authenticate reads the cookie value the host placed in headers and parses it as a JWT.
func (p *Plugin) Authenticate(headers map[string]string, _, _, _ string) (map[string]any, error) {
	value := headers[strings.ToLower(p.cookie)]
	if value == "" {
		value = headers[p.cookie]
	}
	if value == "" {
		return nil, fmt.Errorf("auth jwtsession: missing %s cookie", p.cookie)
	}
	token, err := jwt.TokenFromCredential(value, "Bearer")
	if err != nil {
		return nil, fmt.Errorf("auth jwtsession: %w", err)
	}
	claims, err := jwt.ParseToken(token, p.secret)
	if err != nil {
		return nil, fmt.Errorf("auth jwtsession: %w", err)
	}
	return claims, nil
}
