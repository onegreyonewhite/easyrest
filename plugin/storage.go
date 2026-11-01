package plugin

import (
	"fmt"
	"path"
	"strings"
	"time"
)

const (
	// StorageTypeFile is a List entry that names a file.
	StorageTypeFile = "file"
	// StorageTypeDir is a List entry that names a directory.
	StorageTypeDir = "dir"
	// CtxStorageMIME is the media type of a file passed to StoragePlugin.Put.
	// Inline Put uses it in the returned data URL when it is a non-empty string.
	CtxStorageMIME = "storage.mime"
)

// StorageMeta is the metadata a storage plugin reports for one object.
type StorageMeta struct {
	Size    int64
	Mime    string
	ModTime time.Time
	Created time.Time
}

// StorageEntry is one name in a directory listing.
// Path is the storage-relative path of a file. Directories leave Path empty.
type StorageEntry struct {
	Name string
	Type string
	Mime string
	Path string
}

// StorageURL is the public URL and MIME type of one stored object.
type StorageURL struct {
	URL  string
	Mime string
}

// StoragePlugin stores and serves objects.
// Init returns the storage root and whether values are stored inline.
// A non-empty root tells the host to mount GET /media/{name}/* when inline
// is false. The root string itself is not part of the URL.
// inline true means Put's return value is the database cell and the response.
// That value is a data URL. CtxStorageMIME, when set, supplies its media type.
// The host does not call GetUrl and does not mount /media for that plugin.
// Put and GetBin exchange file bytes so an external plugin can carry them over RPC.
// A nil ctx map from Put or GetBin means the caller keeps its existing context.
type StoragePlugin interface {
	Init(settings map[string]any, host HostRPC) (StorageInfo, error)
	Put(path string, body []byte, ctx map[string]any) (rel string, ctxOut map[string]any, err error)
	GetUrl(paths []string, ctx map[string]any) ([]StorageURL, error)
	GetMetadata(path string, ctx map[string]any) (StorageMeta, error)
	GetBin(path string, ctx map[string]any) (body []byte, mime string, ctxOut map[string]any, err error)
	List(path string, ctx map[string]any) ([]StorageEntry, error)
	Delete(path string, ctx map[string]any) error
}

// StorageFileURL builds the public URL of an object under /media/{plugin}/.
func StorageFileURL(ctx map[string]any, pluginName, relPath string) string {
	return BuildAbsoluteUri(ctx, storagePublicPath(pluginName, relPath))
}

func storagePublicPath(pluginName, relPath string) string {
	name := strings.Trim(pluginName, "/")
	rel := strings.Trim(strings.ReplaceAll(relPath, "\\", "/"), "/")
	switch {
	case name == "" && rel == "":
		return "/media"
	case rel == "":
		return "/media/" + name
	default:
		return "/media/" + name + "/" + rel
	}
}

// CleanStorageRel returns a storage-relative path that stays inside the root.
func CleanStorageRel(relPath string) (string, error) {
	if relPath == "" || strings.Contains(relPath, `\`) || strings.HasPrefix(relPath, "/") {
		return "", fmt.Errorf("storage: invalid path %q", relPath)
	}
	cleaned := path.Clean(relPath)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("storage: invalid path %q", relPath)
	}
	return cleaned, nil
}
