package memory

import (
	"fmt"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type object struct {
	body    []byte
	mime    string
	created time.Time
	mod     time.Time
}

// Plugin stores file bytes in memory.
type Plugin struct {
	host   easyrest.HostRPC
	mu     sync.RWMutex
	name   string
	inline bool
	files  map[string]object
}

var _ easyrest.StoragePlugin = (*Plugin)(nil)

// New returns an empty memory storage plugin.
func New() *Plugin {
	return &Plugin{files: map[string]object{}}
}

// Init records the plugin name and reports a virtual root so the host mounts a route.
func (p *Plugin) Init(settings map[string]any, host easyrest.HostRPC) (easyrest.StorageInfo, error) {
	p.host = host
	root, inline, err := p.initSettings(settings)
	if err != nil {
		return easyrest.StorageInfo{}, err
	}
	return easyrest.NewStorageInfo(root, inline), nil
}

func (p *Plugin) initSettings(settings map[string]any) (string, bool, error) {
	if settings != nil {
		if name, ok := settings["name"].(string); ok {
			p.name = name
		}
		p.inline, _ = settings["inline"].(bool)
	}
	p.mu.Lock()
	if p.files == nil {
		p.files = map[string]object{}
	}
	p.mu.Unlock()
	return ".", p.inline, nil
}

// Put stores body at the storage-relative path. Created stays at the first write.
func (p *Plugin) Put(relPath string, body []byte, ctx map[string]any) (string, map[string]any, error) {
	rel, err := easyrest.CleanStorageRel(relPath)
	if err != nil {
		return "", ctx, err
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	prev, ok := p.files[rel]
	created := now
	if ok {
		created = prev.created
	}
	copied := append([]byte(nil), body...)
	p.files[rel] = object{
		body:    copied,
		mime:    contentType(rel, copied),
		created: created,
		mod:     now,
	}
	if p.inline {
		return easyrest.FormatDataURL(inlineMediaType(rel, copied, ctx), copied), ctx, nil
	}
	return rel, ctx, nil
}

// GetUrl returns the absolute public URL and MIME type of each file, in order.
func (p *Plugin) GetUrl(paths []string, ctx map[string]any) ([]easyrest.StorageURL, error) {
	out := make([]easyrest.StorageURL, 0, len(paths))
	for _, relPath := range paths {
		meta, err := p.GetMetadata(relPath, ctx)
		if err != nil {
			return nil, err
		}
		rel, err := easyrest.CleanStorageRel(relPath)
		if err != nil {
			return nil, err
		}
		out = append(out, easyrest.StorageURL{
			URL:  easyrest.StorageFileURL(ctx, p.name, rel),
			Mime: meta.Mime,
		})
	}
	return out, nil
}

// GetMetadata returns size, MIME type, and timestamps for a file.
func (p *Plugin) GetMetadata(relPath string, ctx map[string]any) (easyrest.StorageMeta, error) {
	rel, err := easyrest.CleanStorageRel(relPath)
	if err != nil {
		return easyrest.StorageMeta{}, err
	}
	p.mu.RLock()
	obj, ok := p.files[rel]
	p.mu.RUnlock()
	if !ok {
		if p.isDir(rel) {
			return easyrest.StorageMeta{}, fmt.Errorf("storage memory: %s is a directory", rel)
		}
		return easyrest.StorageMeta{}, fmt.Errorf("storage memory: %s not found", rel)
	}
	return easyrest.StorageMeta{
		Size:    int64(len(obj.body)),
		Mime:    obj.mime,
		ModTime: obj.mod,
		Created: obj.created,
	}, nil
}

// GetBin returns a copy of the stored bytes.
func (p *Plugin) GetBin(relPath string, ctx map[string]any) ([]byte, string, map[string]any, error) {
	rel, err := easyrest.CleanStorageRel(relPath)
	if err != nil {
		return nil, "", ctx, err
	}
	p.mu.RLock()
	obj, ok := p.files[rel]
	p.mu.RUnlock()
	if !ok {
		if p.isDir(rel) {
			return nil, "", ctx, fmt.Errorf("storage memory: %s is a directory", rel)
		}
		return nil, "", ctx, fmt.Errorf("storage memory: %s not found", rel)
	}
	return append([]byte(nil), obj.body...), obj.mime, ctx, nil
}

// List returns the immediate children of a directory.
func (p *Plugin) List(relPath string, ctx map[string]any) ([]easyrest.StorageEntry, error) {
	prefix, err := p.dirPrefix(relPath)
	if err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	seen := map[string]easyrest.StorageEntry{}
	order := []string{}
	for key, obj := range p.files {
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := key
		if prefix != "" {
			rest = strings.TrimPrefix(key, prefix)
		}
		name, _, _ := strings.Cut(rest, "/")
		if _, ok := seen[name]; ok {
			continue
		}
		child := name
		if rel := strings.TrimSuffix(prefix, "/"); rel != "" {
			child = rel + "/" + name
		}
		item := easyrest.StorageEntry{Name: name, Type: easyrest.StorageTypeDir}
		if !strings.Contains(rest, "/") {
			item.Type = easyrest.StorageTypeFile
			item.Path = child
			item.Mime = obj.mime
		}
		seen[name] = item
		order = append(order, name)
	}
	out := make([]easyrest.StorageEntry, 0, len(order))
	for _, name := range order {
		out = append(out, seen[name])
	}
	return out, nil
}

// Delete removes a file, or a directory and every object under it.
func (p *Plugin) Delete(relPath string, ctx map[string]any) error {
	rel, err := easyrest.CleanStorageRel(relPath)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.files[rel]; ok {
		delete(p.files, rel)
		return nil
	}
	prefix := rel + "/"
	found := false
	for key := range p.files {
		if strings.HasPrefix(key, prefix) {
			delete(p.files, key)
			found = true
		}
	}
	if !found {
		return fmt.Errorf("storage memory: %s not found", rel)
	}
	return nil
}

func (p *Plugin) dirPrefix(relPath string) (string, error) {
	if relPath == "" || relPath == "." {
		return "", nil
	}
	rel, err := easyrest.CleanStorageRel(relPath)
	if err != nil {
		return "", err
	}
	p.mu.RLock()
	_, isFile := p.files[rel]
	p.mu.RUnlock()
	if isFile {
		return "", fmt.Errorf("storage memory: %s is a file", rel)
	}
	if !p.isDir(rel) {
		return "", fmt.Errorf("storage memory: %s not found", rel)
	}
	return rel + "/", nil
}

func (p *Plugin) isDir(rel string) bool {
	prefix := rel + "/"
	p.mu.RLock()
	defer p.mu.RUnlock()
	for key := range p.files {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func inlineMediaType(rel string, body []byte, ctx map[string]any) string {
	if mediaType, ok := easyrest.CtxString(ctx, easyrest.CtxStorageMIME); ok && mediaType != "" {
		return mediaType
	}
	return contentType(rel, body)
}

func contentType(rel string, body []byte) string {
	if mt := mime.TypeByExtension(path.Ext(rel)); mt != "" {
		return mt
	}
	return http.DetectContentType(body)
}
