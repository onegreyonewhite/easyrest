// Package static serves files from a directory, then from embedded Swagger UI assets.
// Put and Delete always fail.
package static

import (
	"fmt"
	"io"
	"io/fs"
	"mime"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin is a read-only storage plugin.
type Plugin struct {
	host easyrest.HostRPC
	name string
	dir  string
}

var _ easyrest.StoragePlugin = (*Plugin)(nil)

// New returns a static storage plugin.
func New() *Plugin { return &Plugin{} }

// Init records the directory. An empty path uses {workdir}/static.
// A missing directory is not an error; reads then use the embedded files.
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
		if dir, ok := settings["path"].(string); ok {
			p.dir = dir
		}
	}
	if p.dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", false, fmt.Errorf("storage static: %w", err)
		}
		p.dir = filepath.Join(wd, "static")
	}
	return p.dir, false, nil
}

// Put rejects every write.
func (p *Plugin) Put(string, []byte, map[string]any) (string, map[string]any, error) {
	return "", nil, fmt.Errorf("storage static: read-only")
}

// Delete rejects every delete.
func (p *Plugin) Delete(string, map[string]any) error {
	return fmt.Errorf("storage static: read-only")
}

// GetUrl returns the public URL of each file that can be read.
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

// GetMetadata reports the directory file when it exists, otherwise the embedded file.
func (p *Plugin) GetMetadata(relPath string, ctx map[string]any) (easyrest.StorageMeta, error) {
	rel, err := easyrest.CleanStorageRel(relPath)
	if err != nil {
		return easyrest.StorageMeta{}, err
	}
	if _, info, ok := p.diskFile(rel); ok {
		return easyrest.StorageMeta{
			Size:    info.Size(),
			Mime:    contentType(rel),
			ModTime: info.ModTime(),
			Created: info.ModTime(),
		}, nil
	}
	info, err := fs.Stat(embedded, path.Join("assets", rel))
	if err != nil || info.IsDir() {
		return easyrest.StorageMeta{}, fmt.Errorf("storage static: %s not found", rel)
	}
	mod := info.ModTime()
	if mod.IsZero() {
		mod = time.Unix(0, 0)
	}
	return easyrest.StorageMeta{
		Size:    info.Size(),
		Mime:    contentType(rel),
		ModTime: mod,
		Created: mod,
	}, nil
}

// GetBin reads the directory file when it exists, otherwise the embedded file.
func (p *Plugin) GetBin(relPath string, ctx map[string]any) ([]byte, string, map[string]any, error) {
	rel, err := easyrest.CleanStorageRel(relPath)
	if err != nil {
		return nil, "", ctx, err
	}
	if full, _, ok := p.diskFile(rel); ok {
		body, err := os.ReadFile(full)
		if err != nil {
			return nil, "", ctx, fmt.Errorf("storage static: %w", err)
		}
		return body, contentType(rel), ctx, nil
	}
	f, err := embedded.Open(path.Join("assets", rel))
	if err != nil {
		return nil, "", ctx, fmt.Errorf("storage static: %s not found", rel)
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, "", ctx, fmt.Errorf("storage static: %w", err)
	}
	return body, contentType(rel), ctx, nil
}

// List returns the immediate children of a directory.
// A name that exists on disk replaces the embedded file of the same name.
func (p *Plugin) List(relPath string, ctx map[string]any) ([]easyrest.StorageEntry, error) {
	rel := ""
	if relPath != "" && relPath != "." {
		var err error
		rel, err = easyrest.CleanStorageRel(relPath)
		if err != nil {
			return nil, err
		}
	}
	seen := map[string]easyrest.StorageEntry{}
	if err := p.listEmbed(rel, seen); err != nil {
		return nil, err
	}
	p.listDisk(rel, seen)
	out := make([]easyrest.StorageEntry, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	return out, nil
}

func (p *Plugin) listEmbed(rel string, seen map[string]easyrest.StorageEntry) error {
	dir := "assets"
	if rel != "" {
		dir = path.Join(dir, rel)
	}
	entries, err := fs.ReadDir(embedded, dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return nil
	}
	for _, entry := range entries {
		name := entry.Name()
		item := easyrest.StorageEntry{Name: name, Type: easyrest.StorageTypeDir}
		if !entry.IsDir() {
			item.Type = easyrest.StorageTypeFile
			item.Mime = contentType(name)
			item.Path = path.Join(rel, name)
		}
		seen[name] = item
	}
	return nil
}

func (p *Plugin) listDisk(rel string, seen map[string]easyrest.StorageEntry) {
	full := p.dir
	if rel != "" {
		full = filepath.Join(p.dir, filepath.FromSlash(rel))
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		item := easyrest.StorageEntry{Name: name, Type: easyrest.StorageTypeDir}
		if !entry.IsDir() {
			item.Type = easyrest.StorageTypeFile
			item.Mime = contentType(name)
			item.Path = path.Join(rel, name)
		}
		seen[name] = item
	}
}

func (p *Plugin) diskFile(rel string) (string, os.FileInfo, bool) {
	if p.dir == "" {
		return "", nil, false
	}
	full := filepath.Join(p.dir, filepath.FromSlash(rel))
	back, err := filepath.Rel(p.dir, full)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", nil, false
	}
	info, err := os.Stat(full)
	if err != nil || !info.Mode().IsRegular() {
		return "", nil, false
	}
	return full, info, true
}

func contentType(rel string) string {
	if t := mime.TypeByExtension(path.Ext(rel)); t != "" {
		return t
	}
	return "application/octet-stream"
}
