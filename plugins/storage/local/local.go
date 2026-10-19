package local

import (
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin stores files under a directory on disk.
type Plugin struct {
	host   easyrest.HostRPC
	name   string
	dir    string
	inline bool
}

var _ easyrest.StoragePlugin = (*Plugin)(nil)

// New returns a local storage plugin.
func New() *Plugin { return &Plugin{} }

// Init creates the storage directory when it is missing.
// It returns an error when the path is not a writable directory.
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
		return "", false, fmt.Errorf("storage local: dir is required")
	}
	if name, ok := settings["name"].(string); ok {
		p.name = name
	}
	p.inline, _ = settings["inline"].(bool)
	dir, _ := settings["dir"].(string)
	if dir == "" {
		return "", false, fmt.Errorf("storage local: dir is required")
	}
	info, err := os.Stat(dir)
	if err == nil && !info.IsDir() {
		return "", false, fmt.Errorf("storage local: %s is not a directory", dir)
	}
	if err != nil && !os.IsNotExist(err) {
		return "", false, fmt.Errorf("storage local: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", false, fmt.Errorf("storage local: %w", err)
	}
	probe := filepath.Join(dir, ".easyrest-write-probe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		return "", false, fmt.Errorf("storage local: directory is not writable: %w", err)
	}
	if err := os.Remove(probe); err != nil {
		return "", false, fmt.Errorf("storage local: %w", err)
	}
	p.dir = dir
	return dir, p.inline, nil
}

// Put writes body at the storage-relative path and returns that path.
func (p *Plugin) Put(relPath string, body []byte, ctx map[string]any) (string, map[string]any, error) {
	full, rel, err := p.fullPath(relPath)
	if err != nil {
		return "", ctx, err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", ctx, fmt.Errorf("storage local: %w", err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		return "", ctx, fmt.Errorf("storage local: %w", err)
	}
	if p.inline {
		return base64.StdEncoding.EncodeToString(body), ctx, nil
	}
	return rel, ctx, nil
}

// GetBin reads the file at the storage-relative path.
func (p *Plugin) GetBin(relPath string, ctx map[string]any) ([]byte, string, map[string]any, error) {
	full, rel, err := p.fullPath(relPath)
	if err != nil {
		return nil, "", ctx, err
	}
	info, err := os.Stat(full)
	if err != nil {
		return nil, "", ctx, fmt.Errorf("storage local: %w", err)
	}
	if info.IsDir() {
		return nil, "", ctx, fmt.Errorf("storage local: %s is a directory", rel)
	}
	body, err := os.ReadFile(full)
	if err != nil {
		return nil, "", ctx, fmt.Errorf("storage local: %w", err)
	}
	return body, contentType(rel, body), ctx, nil
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
	full, rel, err := p.fullPath(relPath)
	if err != nil {
		return easyrest.StorageMeta{}, err
	}
	info, err := os.Stat(full)
	if err != nil {
		return easyrest.StorageMeta{}, fmt.Errorf("storage local: %w", err)
	}
	if info.IsDir() {
		return easyrest.StorageMeta{}, fmt.Errorf("storage local: %s is a directory", rel)
	}
	var head []byte
	if mime.TypeByExtension(path.Ext(rel)) == "" {
		f, err := os.Open(full)
		if err != nil {
			return easyrest.StorageMeta{}, fmt.Errorf("storage local: %w", err)
		}
		head = make([]byte, 512)
		n, _ := f.Read(head)
		f.Close()
		head = head[:n]
	}
	mod := info.ModTime()
	return easyrest.StorageMeta{
		Size:    info.Size(),
		Mime:    contentType(rel, head),
		ModTime: mod,
		Created: mod,
	}, nil
}

// List returns the immediate children of a directory.
// A file path returns an error. Directory entries leave Path empty.
func (p *Plugin) List(relPath string, ctx map[string]any) ([]easyrest.StorageEntry, error) {
	full, rel, err := p.dirPath(relPath)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, fmt.Errorf("storage local: %w", err)
	}
	out := make([]easyrest.StorageEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		child := name
		if rel != "" {
			child = rel + "/" + name
		}
		item := easyrest.StorageEntry{Name: name, Type: easyrest.StorageTypeDir}
		if !entry.IsDir() {
			item.Type = easyrest.StorageTypeFile
			item.Path = child
			item.Mime = mime.TypeByExtension(path.Ext(name))
		}
		out = append(out, item)
	}
	return out, nil
}

// Delete removes a file or a directory and its contents.
func (p *Plugin) Delete(relPath string, ctx map[string]any) error {
	full, _, err := p.fullPath(relPath)
	if err != nil {
		return err
	}
	info, err := os.Stat(full)
	if err != nil {
		return fmt.Errorf("storage local: %w", err)
	}
	if info.IsDir() {
		if err := os.RemoveAll(full); err != nil {
			return fmt.Errorf("storage local: %w", err)
		}
		return nil
	}
	if err := os.Remove(full); err != nil {
		return fmt.Errorf("storage local: %w", err)
	}
	return nil
}

func (p *Plugin) dirPath(relPath string) (full, rel string, err error) {
	if relPath == "" || relPath == "." {
		info, statErr := os.Stat(p.dir)
		if statErr != nil {
			return "", "", fmt.Errorf("storage local: %w", statErr)
		}
		if !info.IsDir() {
			return "", "", fmt.Errorf("storage local: %s is a file", p.dir)
		}
		return p.dir, "", nil
	}
	full, rel, err = p.fullPath(relPath)
	if err != nil {
		return "", "", err
	}
	info, statErr := os.Stat(full)
	if statErr != nil {
		return "", "", fmt.Errorf("storage local: %w", statErr)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("storage local: %s is a file", rel)
	}
	return full, rel, nil
}

func (p *Plugin) fullPath(relPath string) (full, rel string, err error) {
	rel, err = easyrest.CleanStorageRel(relPath)
	if err != nil {
		return "", "", err
	}
	full = filepath.Join(p.dir, filepath.FromSlash(rel))
	root := filepath.Clean(p.dir)
	if full != root && !strings.HasPrefix(full, root+string(os.PathSeparator)) {
		return "", "", fmt.Errorf("storage local: path escapes root")
	}
	return full, rel, nil
}

func contentType(rel string, body []byte) string {
	if mt := mime.TypeByExtension(path.Ext(rel)); mt != "" {
		return mt
	}
	return http.DetectContentType(body)
}
