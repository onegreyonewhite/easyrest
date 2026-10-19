package server

import (
	"fmt"
	"io"
	"net/http"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// lazyStorageBody reports size from metadata without reading bytes.
// ServeContent checks conditional headers before the first Read.
type lazyStorageBody struct {
	plug   easyrest.StoragePlugin
	rel    string
	ctx    map[string]any
	size   int64
	req    *http.Request
	body   []byte
	off    int64
	loaded bool
}

func (b *lazyStorageBody) Seek(offset int64, whence int) (int64, error) {
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = b.off + offset
	case io.SeekEnd:
		next = b.size + offset
	default:
		return 0, fmt.Errorf("invalid whence %d", whence)
	}
	if next < 0 {
		return 0, fmt.Errorf("negative seek")
	}
	b.off = next
	return next, nil
}

func (b *lazyStorageBody) Read(p []byte) (int, error) {
	if err := b.req.Context().Err(); err != nil {
		return 0, err
	}
	if !b.loaded {
		body, _, _, err := b.plug.GetBin(b.rel, b.ctx)
		if err != nil {
			return 0, err
		}
		b.body = body
		b.loaded = true
	}
	if b.off >= int64(len(b.body)) {
		return 0, io.EOF
	}
	n := copy(p, b.body[b.off:])
	b.off += int64(n)
	return n, nil
}
