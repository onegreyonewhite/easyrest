package s3storage

import (
	"encoding/xml"
	"fmt"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeObj struct {
	body  []byte
	ctype string
	mod   time.Time
}

type fakeS3 struct {
	mu      sync.Mutex
	buckets map[string]map[string]fakeObj
	unknown []string
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucket := parts[0]
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.buckets == nil {
		f.buckets = map[string]map[string]fakeObj{}
	}
	switch {
	case r.Method == http.MethodHead && key == "":
		if _, ok := f.buckets[bucket]; !ok {
			http.Error(w, "missing", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPut && key == "":
		if _, ok := f.buckets[bucket]; !ok {
			f.buckets[bucket] = map[string]fakeObj{}
		}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPut && key != "":
		body, _ := io.ReadAll(r.Body)
		objs := f.buckets[bucket]
		if objs == nil {
			http.Error(w, "missing bucket", http.StatusNotFound)
			return
		}
		ctype := r.Header.Get("Content-Type")
		objs[key] = fakeObj{body: body, ctype: ctype, mod: time.Now().UTC().Truncate(time.Second)}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodHead && key != "":
		f.writeObject(w, r, bucket, key, false)
	case r.Method == http.MethodGet && key != "" && r.URL.Query().Get("list-type") == "":
		f.writeObject(w, r, bucket, key, true)
	case r.Method == http.MethodDelete && key != "":
		objs := f.buckets[bucket]
		if objs == nil {
			http.Error(w, "missing", http.StatusNotFound)
			return
		}
		delete(objs, key)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && key == "" && r.URL.Query().Get("list-type") == "2":
		f.writeList(w, r, bucket)
	default:
		line := r.Method + " " + r.URL.RequestURI()
		f.unknown = append(f.unknown, line)
		http.Error(w, "unexpected "+line, http.StatusInternalServerError)
	}
}

func (f *fakeS3) writeObject(w http.ResponseWriter, r *http.Request, bucket, key string, withBody bool) {
	objs := f.buckets[bucket]
	obj, ok := objs[key]
	if !ok {
		http.Error(w, "missing", http.StatusNotFound)
		return
	}
	payload := obj.body
	status := http.StatusOK
	if withBody {
		if rng := r.Header.Get("Range"); rng != "" {
			var from int
			if _, err := fmt.Sscanf(rng, "bytes=%d-", &from); err != nil || from < 0 {
				http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
				return
			}
			if from >= len(obj.body) {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(obj.body)))
				http.Error(w, "range", http.StatusRequestedRangeNotSatisfiable)
				return
			}
			payload = obj.body[from:]
			status = http.StatusPartialContent
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, len(obj.body)-1, len(obj.body)))
		}
	}
	w.Header().Set("Content-Type", obj.ctype)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	w.Header().Set("Last-Modified", obj.mod.Format(http.TimeFormat))
	if withBody {
		w.WriteHeader(status)
		_, _ = w.Write(payload)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3) writeList(w http.ResponseWriter, r *http.Request, bucket string) {
	objs := f.buckets[bucket]
	if objs == nil {
		http.Error(w, "missing", http.StatusNotFound)
		return
	}
	prefix := r.URL.Query().Get("prefix")
	delim := r.URL.Query().Get("delimiter")
	type content struct {
		XMLName xml.Name `xml:"Contents"`
		Key     string   `xml:"Key"`
		Size    int      `xml:"Size"`
	}
	type common struct {
		XMLName xml.Name `xml:"CommonPrefixes"`
		Prefix  string   `xml:"Prefix"`
	}
	type result struct {
		XMLName        xml.Name `xml:"ListBucketResult"`
		Contents       []content
		CommonPrefixes []common
	}
	out := result{}
	seen := map[string]bool{}
	for key, obj := range objs {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := strings.TrimPrefix(key, prefix)
		if delim != "" {
			if i := strings.Index(rest, delim); i >= 0 {
				cp := prefix + rest[:i+len(delim)]
				if !seen[cp] {
					seen[cp] = true
					out.CommonPrefixes = append(out.CommonPrefixes, common{Prefix: cp})
				}
				continue
			}
		}
		out.Contents = append(out.Contents, content{Key: key, Size: len(obj.body)})
	}
	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	_ = enc.Encode(out)
}

func (f *fakeS3) object(bucket, key string) (fakeObj, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.buckets[bucket][key]
	return obj, ok
}

func startFake(t *testing.T) (*fakeS3, *httptest.Server) {
	t.Helper()
	fake := &fakeS3{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return fake, srv
}

func settings(endpoint string, extra map[string]any) map[string]any {
	out := map[string]any{
		"endpoint":   endpoint,
		"region":     "us-east-1",
		"bucket":     "media",
		"access_key": "minio",
		"secret_key": "minio-secret",
		"path_style": true,
	}
	maps.Copy(out, extra)
	return out
}

func TestInitCreatesBucket(t *testing.T) {
	_, srv := startFake(t)
	plug := New()
	info, err := plug.Init(settings(srv.URL, map[string]any{"prefix": "photos"}), easyrest.HostRPC{})
	root, inline := info.Root, info.Inline
	if err != nil {
		t.Fatal(err)
	}
	if inline {
		t.Fatal("expected stored paths")
	}
	if root != "media/photos" {
		t.Fatalf("root %q", root)
	}
	again := New()
	if _, err := again.Init(settings(srv.URL, map[string]any{"prefix": "photos"}), easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}

	if _, err := New().Init(settings(srv.URL, map[string]any{"bucket": ""}), easyrest.HostRPC{}); err == nil {
		t.Fatal("expected missing bucket")
	}
	if _, err := New().Init(map[string]any{"bucket": "media"}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected missing keys")
	}
}

func TestPutStreamGetStream(t *testing.T) {
	fake, srv := startFake(t)
	plug := New()
	if _, err := plug.Init(settings(srv.URL, nil), easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	rel, _, err := plug.PutStream("note.txt", strings.NewReader("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rel != "note.txt" {
		t.Fatalf("rel %q", rel)
	}
	obj, ok := fake.object("media", "note.txt")
	if !ok || string(obj.body) != "hello" {
		t.Fatalf("object %#v ok %v", obj, ok)
	}
	if got := readS3Stream(t, plug, 0); got != "hello" {
		t.Fatalf("body %q", got)
	}
	if got := readS3Stream(t, plug, 4); got != "o" {
		t.Fatalf("suffix %q", got)
	}
}

func readS3Stream(t *testing.T, plug *Plugin, offset int64) string {
	t.Helper()
	rc, _, _, err := plug.GetStream("note.txt", offset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestPutGetPrefix(t *testing.T) {
	fake, srv := startFake(t)
	photos := New()
	if _, err := photos.Init(settings(srv.URL, map[string]any{"prefix": "photos"}), easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	docs := New()
	if _, err := docs.Init(settings(srv.URL, map[string]any{"prefix": "docs"}), easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	got, _, err := photos.Put("a/b.txt", []byte("hi"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "a/b.txt" {
		t.Fatalf("stored %q", got)
	}
	obj, ok := fake.object("media", "photos/a/b.txt")
	if !ok || string(obj.body) != "hi" {
		t.Fatalf("object %#v ok %v", obj, ok)
	}
	body, _, _, err := photos.GetBin("a/b.txt", nil)
	if err != nil || string(body) != "hi" {
		t.Fatalf("body %q err %v", body, err)
	}
	if _, _, _, err := docs.GetBin("a/b.txt", nil); err == nil {
		t.Fatal("docs prefix should not see photos")
	}
	if _, _, err := photos.Put("../x", []byte("no"), nil); err == nil {
		t.Fatal("expected escape rejection")
	}
	if _, ok := fake.object("media", "x"); ok {
		t.Fatal("escape reached the bucket")
	}
}

func TestGetUrl(t *testing.T) {
	_, srv := startFake(t)
	plug := New()
	if _, err := plug.Init(settings(srv.URL, map[string]any{"prefix": "photos"}), easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plug.Put("a/b.txt", []byte("hi"), nil); err != nil {
		t.Fatal(err)
	}
	got, err := plug.GetUrl([]string{"a/b.txt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := srv.URL + "/media/photos/a/b.txt"
	if len(got) != 1 || got[0].URL != want || got[0].Mime != "text/plain; charset=utf-8" {
		t.Fatalf("%#v", got)
	}

	cdn := New()
	if _, err := cdn.Init(settings(srv.URL, map[string]any{
		"prefix":      "photos",
		"public_base": "https://cdn.example.com",
	}), easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	got, err = cdn.GetUrl([]string{"a/b.txt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].URL != "https://cdn.example.com/photos/a/b.txt" {
		t.Fatalf("%#v", got)
	}
}

func TestInlineStoresAndReturnsBase64(t *testing.T) {
	fake, srv := startFake(t)
	plug := New()
	info, err := plug.Init(settings(srv.URL, map[string]any{"inline": true}), easyrest.HostRPC{})
	_, inline := info.Root, info.Inline
	if err != nil || !inline {
		t.Fatalf("inline %v err %v", inline, err)
	}
	got, _, err := plug.Put("a.txt", []byte("hi"), nil)
	want := easyrest.FormatDataURL("text/plain; charset=utf-8", []byte("hi"))
	if err != nil || got != want {
		t.Fatalf("stored %q err %v", got, err)
	}
	typed, _, err := plug.Put("b.bin", []byte{0x00, 0x01}, map[string]any{easyrest.CtxStorageMIME: "image/png"})
	if err != nil || typed != easyrest.FormatDataURL("image/png", []byte{0x00, 0x01}) {
		t.Fatalf("typed %q err %v", typed, err)
	}
	body, _, _, err := plug.GetBin("a.txt", nil)
	if err != nil || string(body) != "hi" {
		t.Fatalf("body %q err %v", body, err)
	}
	if _, ok := fake.object("media", "a.txt"); !ok {
		t.Fatal("inline put did not store the object")
	}
}

func TestListDeleteMetadata(t *testing.T) {
	fake, srv := startFake(t)
	plug := New()
	if _, err := plug.Init(settings(srv.URL, map[string]any{"prefix": "photos"}), easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plug.Put("sub/a.txt", []byte("hi"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plug.Put("sub/nested/b.txt", []byte("yo"), nil); err != nil {
		t.Fatal(err)
	}
	entries, err := plug.List("sub", nil)
	if err != nil {
		t.Fatal(err)
	}
	var file, dir bool
	for _, entry := range entries {
		if entry.Type == "file" && entry.Name == "a.txt" && entry.Path == "sub/a.txt" {
			file = true
		}
		if entry.Type == "dir" && entry.Name == "nested" && entry.Path == "" {
			dir = true
		}
	}
	if !file || !dir {
		t.Fatalf("%#v", entries)
	}
	if _, err := plug.List("sub/a.txt", nil); err == nil {
		t.Fatal("listing a file should fail")
	}
	meta, err := plug.GetMetadata("sub/a.txt", nil)
	if err != nil || meta.Size != 2 || meta.Mime != "text/plain; charset=utf-8" {
		t.Fatalf("%#v %v", meta, err)
	}
	if err := plug.Delete("sub", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.object("media", "photos/sub/a.txt"); ok {
		t.Fatal("file survived directory delete")
	}
	if _, ok := fake.object("media", "photos/sub/nested/b.txt"); ok {
		t.Fatal("nested file survived directory delete")
	}
}
