// Package dbglob stores object bytes.
// Inline mode returns a data URL. Table mode stores standard base64 in the data column.
package dbglob

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin stores object bytes. Without a table it returns a data URL.
// With plugin and table it stores a row through HostRPC.
type Plugin struct {
	host    easyrest.HostRPC
	name    string
	db      string
	table   string
	pathCol string
	dataCol string
	metaCol string
}

var _ easyrest.StoragePlugin = (*Plugin)(nil)

// New returns a dbglob storage plugin.
func New() *Plugin { return &Plugin{} }

// Init reports inline mode and no media root.
func (p *Plugin) Init(settings map[string]any, host easyrest.HostRPC) (easyrest.StorageInfo, error) {
	p.host = host
	root, inline, err := p.initSettings(settings)
	if err != nil {
		return easyrest.StorageInfo{}, err
	}
	return easyrest.NewStorageInfo(root, inline), nil
}

func (p *Plugin) initSettings(settings map[string]any) (string, bool, error) {
	if settings == nil {
		return "", true, nil
	}
	if name, ok := settings["name"].(string); ok {
		p.name = name
	}
	db, _ := settings["plugin"].(string)
	table, _ := settings["table"].(string)
	if db == "" && table == "" {
		return "", true, nil
	}
	if db == "" || table == "" {
		return "", false, fmt.Errorf("storage dbglob: plugin and table are required together")
	}
	p.db = db
	p.table = table
	p.pathCol = dbglobSetting(settings, "path", "path")
	p.dataCol = dbglobSetting(settings, "data", "data")
	p.metaCol = dbglobSetting(settings, "metadata", "metadata")
	return ".", false, nil
}

func dbglobSetting(settings map[string]any, key, fallback string) string {
	value, _ := settings[key].(string)
	if value == "" {
		return fallback
	}
	return value
}

// Put stores body. Inline mode returns a data URL. Table mode returns the path.
func (p *Plugin) Put(relPath string, body []byte, ctx map[string]any) (string, map[string]any, error) {
	if p.table == "" {
		mediaType, _ := easyrest.CtxString(ctx, easyrest.CtxStorageMIME)
		return easyrest.FormatDataURL(mediaType, body), ctx, nil
	}
	rel, err := easyrest.CleanStorageRel(relPath)
	if err != nil {
		return "", ctx, fmt.Errorf("storage dbglob: %w", err)
	}
	client, err := easyrest.DialHost(p.host)
	if err != nil {
		return "", ctx, fmt.Errorf("storage dbglob: %w", err)
	}
	defer client.Close()
	existing, err := p.fetchRow(client, rel, p.metaCol)
	if err != nil {
		return "", ctx, err
	}
	payload := map[string]any{
		p.pathCol: rel,
		p.dataCol: base64.StdEncoding.EncodeToString(body),
		p.metaCol: p.objectMeta(body, existing),
	}
	if existing != nil {
		if err := p.updateRow(client, rel, payload); err != nil {
			return "", ctx, err
		}
		return rel, ctx, nil
	}
	if err := p.createRow(client, payload); err != nil {
		return "", ctx, err
	}
	return rel, ctx, nil
}

func (p *Plugin) fetchRow(client *easyrest.Host, rel, column string) (map[string]any, error) {
	query := url.Values{}
	query.Set("where.eq."+p.pathCol, rel)
	if column != "" {
		query.Set("select", column)
	}
	result, err := client.TableGet(easyrest.HostCall{
		DB:    p.db,
		Name:  p.table,
		Query: query.Encode(),
	})
	if err != nil {
		return nil, fmt.Errorf("storage dbglob: %w", err)
	}
	if result.Status < 200 || result.Status > 299 {
		return nil, fmt.Errorf("storage dbglob: get status %d", result.Status)
	}
	var rows []map[string]any
	if len(result.Body) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(result.Body, &rows); err != nil {
		return nil, fmt.Errorf("storage dbglob: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

func (p *Plugin) createRow(client *easyrest.Host, payload map[string]any) error {
	raw, err := json.Marshal([]map[string]any{payload})
	if err != nil {
		return fmt.Errorf("storage dbglob: %w", err)
	}
	result, err := client.TableCreate(easyrest.HostCall{
		DB:     p.db,
		Name:   p.table,
		Header: map[string]string{"Content-Type": "application/json"},
		Body:   raw,
	})
	if err != nil {
		return fmt.Errorf("storage dbglob: %w", err)
	}
	if result.Status < 200 || result.Status > 299 {
		return fmt.Errorf("storage dbglob: create status %d", result.Status)
	}
	return nil
}

func (p *Plugin) updateRow(client *easyrest.Host, rel string, payload map[string]any) error {
	raw, err := json.Marshal(map[string]any{
		p.dataCol: payload[p.dataCol],
		p.metaCol: payload[p.metaCol],
	})
	if err != nil {
		return fmt.Errorf("storage dbglob: %w", err)
	}
	query := url.Values{}
	query.Set("where.eq."+p.pathCol, rel)
	result, err := client.TableUpdate(easyrest.HostCall{
		DB:     p.db,
		Name:   p.table,
		Query:  query.Encode(),
		Header: map[string]string{"Content-Type": "application/json"},
		Body:   raw,
	})
	if err != nil {
		return fmt.Errorf("storage dbglob: %w", err)
	}
	if result.Status < 200 || result.Status > 299 {
		return fmt.Errorf("storage dbglob: update status %d", result.Status)
	}
	return nil
}

func (p *Plugin) objectMeta(body []byte, existing map[string]any) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	created := now
	if existing != nil {
		if prev, ok := existing[p.metaCol].(map[string]any); ok {
			if value, ok := prev["created"].(string); ok && value != "" {
				created = value
			}
		}
	}
	return map[string]any{
		"size":     len(body),
		"mime":     http.DetectContentType(body),
		"created":  created,
		"mod_time": now,
	}
}

// GetUrl returns the stored text in inline mode and a media URL in table mode.
func (p *Plugin) GetUrl(paths []string, ctx map[string]any) ([]easyrest.StorageURL, error) {
	out := make([]easyrest.StorageURL, 0, len(paths))
	for _, stored := range paths {
		url := stored
		if p.table != "" {
			url = easyrest.StorageFileURL(ctx, p.name, stored)
		}
		out = append(out, easyrest.StorageURL{URL: url})
	}
	return out, nil
}

// GetMetadata reports size and MIME type. Table mode reads only the metadata column.
func (p *Plugin) GetMetadata(stored string, ctx map[string]any) (easyrest.StorageMeta, error) {
	if p.table == "" {
		body, mime, _, err := p.GetBin(stored, ctx)
		if err != nil {
			return easyrest.StorageMeta{}, err
		}
		return easyrest.StorageMeta{Size: int64(len(body)), Mime: mime}, nil
	}
	client, err := easyrest.DialHost(p.host)
	if err != nil {
		return easyrest.StorageMeta{}, fmt.Errorf("storage dbglob: %w", err)
	}
	defer client.Close()
	row, err := p.fetchRow(client, stored, p.metaCol)
	if err != nil {
		return easyrest.StorageMeta{}, err
	}
	if row == nil {
		return easyrest.StorageMeta{}, fmt.Errorf("storage dbglob: %s not found", stored)
	}
	meta, _ := row[p.metaCol].(map[string]any)
	return metaFromMap(meta)
}

// GetBin returns file bytes. Table mode reads only the data column.
func (p *Plugin) GetBin(stored string, ctx map[string]any) ([]byte, string, map[string]any, error) {
	if p.table == "" {
		mediaType, body, err := easyrest.ParseDataURL(stored)
		if err != nil {
			return nil, "", ctx, fmt.Errorf("storage dbglob: %w", err)
		}
		if mediaType == "" {
			mediaType = http.DetectContentType(body)
		}
		return body, mediaType, ctx, nil
	}
	client, err := easyrest.DialHost(p.host)
	if err != nil {
		return nil, "", ctx, fmt.Errorf("storage dbglob: %w", err)
	}
	defer client.Close()
	row, err := p.fetchRow(client, stored, p.dataCol)
	if err != nil {
		return nil, "", ctx, err
	}
	if row == nil {
		return nil, "", ctx, fmt.Errorf("storage dbglob: %s not found", stored)
	}
	encoded, _ := row[p.dataCol].(string)
	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", ctx, fmt.Errorf("storage dbglob: %w", err)
	}
	return body, http.DetectContentType(body), ctx, nil
}

func metaFromMap(meta map[string]any) (easyrest.StorageMeta, error) {
	if meta == nil {
		return easyrest.StorageMeta{}, fmt.Errorf("storage dbglob: metadata is missing")
	}
	var out easyrest.StorageMeta
	switch size := meta["size"].(type) {
	case float64:
		out.Size = int64(size)
	case int:
		out.Size = int64(size)
	case int64:
		out.Size = size
	}
	out.Mime, _ = meta["mime"].(string)
	if created, ok := meta["created"].(string); ok && created != "" {
		parsed, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return easyrest.StorageMeta{}, fmt.Errorf("storage dbglob: %w", err)
		}
		out.Created = parsed
	}
	if mod, ok := meta["mod_time"].(string); ok && mod != "" {
		parsed, err := time.Parse(time.RFC3339Nano, mod)
		if err != nil {
			return easyrest.StorageMeta{}, fmt.Errorf("storage dbglob: %w", err)
		}
		out.ModTime = parsed
	}
	return out, nil
}

// List reports that dbglob has no directories.
func (*Plugin) List(string, map[string]any) ([]easyrest.StorageEntry, error) {
	return nil, fmt.Errorf("storage dbglob: no directory listing")
}

// Delete removes the row in table mode. Inline mode has nothing to remove.
func (p *Plugin) Delete(relPath string, _ map[string]any) error {
	if p.table == "" {
		return fmt.Errorf("storage dbglob: delete is not supported")
	}
	rel, err := easyrest.CleanStorageRel(relPath)
	if err != nil {
		return fmt.Errorf("storage dbglob: %w", err)
	}
	client, err := easyrest.DialHost(p.host)
	if err != nil {
		return fmt.Errorf("storage dbglob: %w", err)
	}
	defer client.Close()
	query := url.Values{}
	query.Set("where.eq."+p.pathCol, rel)
	result, err := client.TableDelete(easyrest.HostCall{
		DB:    p.db,
		Name:  p.table,
		Query: query.Encode(),
	})
	if err != nil {
		return fmt.Errorf("storage dbglob: %w", err)
	}
	if result.Status < 200 || result.Status > 299 {
		return fmt.Errorf("storage dbglob: delete status %d", result.Status)
	}
	return nil
}
