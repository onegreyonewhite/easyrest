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
	stream io.ReadCloser
	off    int64
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
	if b.stream != nil {
		if seeker, ok := b.stream.(io.Seeker); ok {
			pos, err := seeker.Seek(offset, whence)
			if err != nil {
				return 0, err
			}
			b.off = pos
			return pos, nil
		}
		err := b.stream.Close()
		b.stream = nil
		if err != nil {
			return 0, err
		}
	}
	b.off = next
	return next, nil
}

func (b *lazyStorageBody) Read(p []byte) (int, error) {
	if err := b.req.Context().Err(); err != nil {
		return 0, err
	}
	if b.stream == nil {
		rc, _, _, err := b.plug.GetStream(b.rel, b.off, b.ctx)
		if err != nil {
			return 0, err
		}
		b.stream = rc
	}
	n, err := b.stream.Read(p)
	b.off += int64(n)
	if err == io.EOF {
		closeErr := b.stream.Close()
		b.stream = nil
		if closeErr != nil {
			return n, closeErr
		}
	}
	return n, err
}

func (b *lazyStorageBody) Close() error {
	if b.stream == nil {
		return nil
	}
	err := b.stream.Close()
	b.stream = nil
	return err
}
