// Package dbsession authenticates a request from a session row.
// The host copies the cookie into the headers map. This plugin does not set cookies.
package dbsession

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin loads claims from a session table through HostRPC.
type Plugin struct {
	mu        sync.Mutex
	conn      *hostConn
	host      easyrest.HostRPC
	db        string
	table     string
	idCol     string
	claimsCol string
	expCol    string
	cookie    string
}

// hostConn dials the internal RPC server once. Init replaces it.
type hostConn struct {
	once    sync.Once
	mu      sync.Mutex
	client  *easyrest.Host
	err     error
	retired bool
}

var errHostReset = errors.New("host connection was reset")

var _ easyrest.AuthPlugin = (*Plugin)(nil)

// New returns a database session auth plugin.
func New() *Plugin { return &Plugin{} }

// Init stores the table settings and a cookie apiKey schema. It does not dial.
// A later Init drops the cached client. The next Authenticate dials the HostRPC from that Init.
func (p *Plugin) Init(settings map[string]any, host easyrest.HostRPC) (easyrest.AuthInfo, error) {
	if err := p.initSettings(settings); err != nil {
		return easyrest.AuthInfo{}, err
	}
	if err := p.resetHost(host); err != nil {
		return easyrest.AuthInfo{}, err
	}
	info := easyrest.NewAuthInfo(map[string]any{
		"type": "apiKey",
		"name": p.cookie,
		"in":   "cookie",
	})
	info.Key = p.cookie
	info.IsCookie = true
	return info, nil
}

func (p *Plugin) initSettings(settings map[string]any) error {
	if settings == nil {
		return fmt.Errorf("auth dbsession: plugin and table are required together")
	}
	db, _ := settings["plugin"].(string)
	table, _ := settings["table"].(string)
	if db == "" || table == "" {
		return fmt.Errorf("auth dbsession: plugin and table are required together")
	}
	p.db = db
	p.table = table
	p.idCol = sessionSetting(settings, "id", "id")
	p.claimsCol = sessionSetting(settings, "claims", "claims")
	p.expCol = sessionSetting(settings, "exp", "exp")
	p.cookie = sessionSetting(settings, "cookie", "session")
	return nil
}

func sessionSetting(settings map[string]any, key, fallback string) string {
	value, _ := settings[key].(string)
	if value == "" {
		return fallback
	}
	return value
}

// Authenticate reads the cookie value the host placed in headers and loads that session row.
func (p *Plugin) Authenticate(headers map[string]string, _, _, _ string) (map[string]any, error) {
	value := headers[strings.ToLower(p.cookie)]
	if value == "" {
		value = headers[p.cookie]
	}
	if value == "" {
		return nil, fmt.Errorf("auth dbsession: missing %s cookie", p.cookie)
	}
	client, err := p.hostClient()
	if err != nil {
		return nil, err
	}
	row, err := p.fetchSession(client, value)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("auth dbsession: session not found")
	}
	if err := rejectExpired(row[p.expCol]); err != nil {
		return nil, err
	}
	return claimsObject(row[p.claimsCol])
}

// claimsObject accepts a JSON object, or the same object stored as text.
func claimsObject(raw any) (map[string]any, error) {
	switch v := raw.(type) {
	case map[string]any:
		return v, nil
	case string:
		return unmarshalClaims([]byte(v))
	case []byte:
		return unmarshalClaims(v)
	default:
		return nil, fmt.Errorf("auth dbsession: claims are missing")
	}
}

func unmarshalClaims(raw []byte) (map[string]any, error) {
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil || claims == nil {
		return nil, fmt.Errorf("auth dbsession: claims are missing")
	}
	return claims, nil
}

func (p *Plugin) resetHost(cfg easyrest.HostRPC) error {
	p.mu.Lock()
	old := p.conn
	p.host = cfg
	p.conn = &hostConn{}
	p.mu.Unlock()
	if old == nil {
		return nil
	}
	if err := old.retire(); err != nil {
		return fmt.Errorf("auth dbsession: %w", err)
	}
	return nil
}

func (p *Plugin) hostClient() (*easyrest.Host, error) {
	p.mu.Lock()
	conn := p.conn
	cfg := p.host
	if conn == nil {
		conn = &hostConn{}
		p.conn = conn
	}
	p.mu.Unlock()
	client, err := conn.dial(cfg)
	if err != nil {
		return nil, fmt.Errorf("auth dbsession: %w", err)
	}
	return client, nil
}

func (c *hostConn) dial(cfg easyrest.HostRPC) (*easyrest.Host, error) {
	c.once.Do(func() {
		client, err := easyrest.DialHost(cfg)
		c.mu.Lock()
		retired := c.retired
		if !retired {
			c.client = client
			c.err = err
		}
		c.mu.Unlock()
		if !retired {
			return
		}
		err = retireDial(client, err)
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	if c.retired || c.client == nil {
		return nil, errHostReset
	}
	return c.client, nil
}

func (c *hostConn) retire() error {
	c.mu.Lock()
	c.retired = true
	client := c.client
	c.client = nil
	c.mu.Unlock()
	if client == nil {
		return nil
	}
	return client.Close()
}

func retireDial(client *easyrest.Host, err error) error {
	if client == nil {
		if err == nil {
			return errHostReset
		}
		return err
	}
	return errors.Join(err, client.Close(), errHostReset)
}

func (p *Plugin) fetchSession(client *easyrest.Host, id string) (map[string]any, error) {
	query := url.Values{}
	query.Set("where.eq."+p.idCol, id)
	query.Set("select", p.claimsCol+","+p.expCol)
	result, err := client.TableGet(easyrest.HostCall{
		DB:    p.db,
		Name:  p.table,
		Query: query.Encode(),
	})
	if err != nil {
		return nil, fmt.Errorf("auth dbsession: %w", err)
	}
	if result.Status < 200 || result.Status > 299 {
		return nil, fmt.Errorf("auth dbsession: get status %d", result.Status)
	}
	if len(result.Body) == 0 {
		return nil, nil
	}
	var rows []map[string]any
	if err := json.Unmarshal(result.Body, &rows); err != nil {
		return nil, fmt.Errorf("auth dbsession: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

func rejectExpired(raw any) error {
	value, _ := raw.(string)
	if value == "" {
		return fmt.Errorf("auth dbsession: exp is missing")
	}
	exp, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fmt.Errorf("auth dbsession: %w", err)
	}
	if exp.Before(time.Now()) {
		return fmt.Errorf("auth dbsession: session expired")
	}
	return nil
}
