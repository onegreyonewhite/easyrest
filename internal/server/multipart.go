package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"path"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type multipartFile struct {
	Name     string
	Filename string
	Body     []byte
}

type storageStatusError struct {
	status int
	err    error
}

func (e *storageStatusError) Error() string { return e.err.Error() }

func (e *storageStatusError) Unwrap() error { return e.err }

func storageBadRequest(err error) error {
	return &storageStatusError{status: http.StatusBadRequest, err: err}
}

func storageFailure(err error) error {
	return &storageStatusError{status: http.StatusInternalServerError, err: err}
}

func storageStatus(err error) int {
	var status *storageStatusError
	if ok := asStorageStatus(err, &status); ok {
		return status.status
	}
	return http.StatusBadRequest
}

func asStorageStatus(err error, target **storageStatusError) bool {
	for err != nil {
		if status, ok := err.(*storageStatusError); ok {
			*target = status
			return true
		}
		unwrap, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrap.Unwrap()
	}
	return false
}

func restStorageName(action, endpoint, app, fallback string) string {
	switch {
	case action != "":
		return action
	case endpoint != "":
		return endpoint
	case app != "":
		return app
	case fallback != "":
		return fallback
	default:
		return "local"
	}
}

func storagePluginByName(name string) (storagePluginRef, bool) {
	loaded := storagePlugins.Load()
	if loaded == nil {
		return storagePluginRef{}, false
	}
	ref, ok := (*loaded)[name]
	if !ok || ref.Plugin == nil {
		return storagePluginRef{}, false
	}
	return ref, true
}

func storageInline(name string) bool {
	ref, ok := storagePluginByName(name)
	return ok && ref.Inline
}

func isMultipart(contentType string) bool {
	switch mediaType(contentType) {
	case "multipart/form-data", "multipart/mixed":
		return true
	default:
		return false
	}
}

func readMultipart(r *http.Request, allowed []contentPluginRef) (any, []multipartFile, error) {
	if err := r.Context().Err(); err != nil {
		return nil, nil, err
	}
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, nil, storageBadRequest(fmt.Errorf("multipart: %w", err))
	}
	var (
		doc     []byte
		docType string
		sawDoc  bool
		files   = []multipartFile{}
	)
	for {
		if err := r.Context().Err(); err != nil {
			return nil, nil, err
		}
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, storageBadRequest(fmt.Errorf("multipart: %w", err))
		}
		body, err := io.ReadAll(part)
		part.Close()
		if err != nil {
			return nil, nil, storageBadRequest(err)
		}
		disposition := part.Header.Get("Content-Disposition")
		_, params, err := mime.ParseMediaType(disposition)
		if err != nil {
			return nil, nil, storageBadRequest(fmt.Errorf("multipart: %w", err))
		}
		if params["filename"] == "" {
			if sawDoc {
				return nil, nil, storageBadRequest(fmt.Errorf("multipart: expected one document part"))
			}
			sawDoc = true
			doc = body
			docType = mediaType(part.Header.Get("Content-Type"))
			continue
		}
		name := params["name"]
		if name == "" {
			return nil, nil, storageBadRequest(fmt.Errorf("multipart: file part is missing a name"))
		}
		files = append(files, multipartFile{Name: name, Filename: params["filename"], Body: body})
	}
	if !sawDoc {
		return nil, nil, storageBadRequest(fmt.Errorf("multipart: document part is missing"))
	}
	parsed, err := parseDocumentPart(doc, docType, allowed)
	if err != nil {
		return nil, nil, err
	}
	return parsed, files, nil
}

func parseDocumentPart(body []byte, contentType string, allowed []contentPluginRef) (any, error) {
	if contentType == "" {
		contentType = easyrest.MediaTypeJSON
	}
	plug, ok := findParser(allowed, func(p contentPluginRef) bool {
		return strings.EqualFold(p.ParserMedia, contentType)
	})
	if !ok {
		return nil, storageBadRequest(fmt.Errorf("unsupported Content-Type: %s", contentType))
	}
	parsed, _, err := plug.Plugin.Parse(body, map[string]any{easyrest.CtxExpectArray: false})
	if err != nil {
		return nil, storageBadRequest(err)
	}
	value, err := coerceParsed(parsed, false)
	if err != nil {
		return nil, storageBadRequest(err)
	}
	return value, nil
}

func storeObjectFields(ctx context.Context, row map[string]any, files []multipartFile, kinds map[string]storageValueKind, ref storagePluginRef, table string, reqCtx map[string]any) error {
	if len(kinds) == 0 {
		return nil
	}
	if ref.Plugin == nil {
		return storageFailure(fmt.Errorf("storage plugin %q is not loaded", ref.Name))
	}
	grouped := map[string][]multipartFile{}
	for _, file := range files {
		kind, ok := kinds[file.Name]
		if !ok || (kind != storageValueBinary && kind != storageValueBinaryList) {
			return storageBadRequest(fmt.Errorf("unknown file field %s", file.Name))
		}
		grouped[file.Name] = append(grouped[file.Name], file)
	}
	for name, kind := range kinds {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch kind {
		case storageValueBinary:
			if err := storeBinaryField(ctx, row, name, grouped[name], false, ref, table, reqCtx); err != nil {
				return err
			}
		case storageValueBinaryList:
			if err := storeBinaryField(ctx, row, name, grouped[name], true, ref, table, reqCtx); err != nil {
				return err
			}
		case storageValueBase64:
			if err := storeBase64Field(ctx, row, name, false, ref, table, reqCtx); err != nil {
				return err
			}
		case storageValueBase64List:
			if err := storeBase64Field(ctx, row, name, true, ref, table, reqCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

func storeBinaryField(ctx context.Context, row map[string]any, name string, files []multipartFile, list bool, ref storagePluginRef, table string, reqCtx map[string]any) error {
	if raw, ok := row[name]; ok && raw != nil {
		return storageBadRequest(fmt.Errorf("field %s must be sent as a file", name))
	}
	delete(row, name)
	if len(files) == 0 {
		return nil
	}
	if !list && len(files) > 1 {
		return storageBadRequest(fmt.Errorf("field %s accepts one file", name))
	}
	stored := make([]string, 0, len(files))
	for _, file := range files {
		value, err := putStored(ctx, ref, table, name, file.Filename, file.Body, reqCtx)
		if err != nil {
			return err
		}
		stored = append(stored, value)
	}
	if list {
		cell, err := storageListCell(stored)
		if err != nil {
			return storageFailure(err)
		}
		row[name] = cell
		return nil
	}
	row[name] = stored[0]
	return nil
}

func storeBase64Field(ctx context.Context, row map[string]any, name string, list bool, ref storagePluginRef, table string, reqCtx map[string]any) error {
	raw, ok := row[name]
	if !ok || raw == nil {
		return nil
	}
	if list {
		items, err := base64List(raw)
		if err != nil {
			return storageBadRequest(fmt.Errorf("field %s: %w", name, err))
		}
		if len(items) == 0 {
			delete(row, name)
			return nil
		}
		stored := make([]string, 0, len(items))
		for _, item := range items {
			body, err := decodeFieldBase64(item)
			if err != nil {
				return storageBadRequest(fmt.Errorf("field %s: %w", name, err))
			}
			value, err := putStored(ctx, ref, table, name, "object", body, reqCtx)
			if err != nil {
				return err
			}
			stored = append(stored, value)
		}
		cell, err := storageListCell(stored)
		if err != nil {
			return storageFailure(err)
		}
		row[name] = cell
		return nil
	}
	text, ok := raw.(string)
	if !ok {
		return storageBadRequest(fmt.Errorf("field %s must be a string", name))
	}
	if text == "" {
		delete(row, name)
		return nil
	}
	body, err := decodeFieldBase64(text)
	if err != nil {
		return storageBadRequest(fmt.Errorf("field %s: %w", name, err))
	}
	value, err := putStored(ctx, ref, table, name, "object", body, reqCtx)
	if err != nil {
		return err
	}
	row[name] = value
	return nil
}

func decodeFieldBase64(text string) ([]byte, error) {
	body, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("invalid base64")
	}
	return body, nil
}

func base64List(raw any) ([]string, error) {
	switch items := raw.(type) {
	case []string:
		return items, nil
	case []any:
		out := make([]string, len(items))
		for i, item := range items {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("must be an array of strings")
			}
			out[i] = text
		}
		return out, nil
	default:
		return nil, fmt.Errorf("must be an array of strings")
	}
}

func putStored(ctx context.Context, ref storagePluginRef, table, field, filename string, body []byte, reqCtx map[string]any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	relPath := "object"
	if !ref.Inline {
		var err error
		relPath, err = newStoragePath(table, field, filename)
		if err != nil {
			return "", storageBadRequest(err)
		}
	}
	stored, _, err := ref.Plugin.Put(relPath, body, reqCtx)
	if err != nil {
		return "", storageFailure(err)
	}
	if ref.Inline {
		return stored, nil
	}
	cleaned, err := easyrest.CleanStorageRel(stored)
	if err != nil {
		return "", storageBadRequest(err)
	}
	return cleaned, nil
}

func newStoragePath(table, field, filename string) (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	rel := table + "/" + field + "/" + hex.EncodeToString(buf[:]) + "/" + storageFileBase(filename)
	return easyrest.CleanStorageRel(rel)
}

func storageFileBase(name string) string {
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '_' || r == '-':
			return r
		default:
			return '_'
		}
	}, name)
	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return "object"
	}
	return cleaned
}

func storageListCell(values []string) (string, error) {
	raw, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func expandStoredObject(r *http.Request, obj map[string]any, kinds map[string]storageValueKind, ref storagePluginRef) error {
	if len(kinds) == 0 {
		return nil
	}
	reqCtx := map[string]any{}
	if r != nil {
		reqCtx["request"] = requestPublic(r)
	}
	for name, kind := range kinds {
		raw, ok := obj[name]
		if !ok || raw == nil {
			continue
		}
		if ref.Inline {
			if storageKindList(kind) {
				paths, err := storedPathList(raw)
				if err != nil {
					return err
				}
				obj[name] = paths
			}
			continue
		}
		if ref.Plugin == nil {
			return fmt.Errorf("storage plugin %q is not loaded", ref.Name)
		}
		paths, err := storedPathList(raw)
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			continue
		}
		urls, err := ref.Plugin.GetUrl(paths, reqCtx)
		if err != nil {
			return err
		}
		if len(urls) != len(paths) {
			return fmt.Errorf("storage url missing")
		}
		if storageKindList(kind) {
			out := make([]string, len(urls))
			for i, item := range urls {
				out[i] = item.URL
			}
			obj[name] = out
			continue
		}
		obj[name] = urls[0].URL
	}
	return nil
}

func storedPathList(raw any) ([]string, error) {
	switch value := raw.(type) {
	case string:
		if value == "" {
			return []string{}, nil
		}
		if strings.HasPrefix(value, "[") {
			var paths []string
			if err := json.Unmarshal([]byte(value), &paths); err != nil {
				return nil, fmt.Errorf("stored file list: %w", err)
			}
			return paths, nil
		}
		return []string{value}, nil
	case []string:
		return value, nil
	case []any:
		out := make([]string, len(value))
		for i, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("stored file list has %T", item)
			}
			out[i] = text
		}
		return out, nil
	default:
		return nil, fmt.Errorf("stored file value has %T", raw)
	}
}

func cloneRow(row map[string]any) map[string]any {
	out := make(map[string]any, len(row))
	maps.Copy(out, row)
	return out
}
