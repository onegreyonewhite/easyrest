package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/onegreyonewhite/easyrest/internal/config"
)

func TestNewHTTPServer(t *testing.T) {
	base := func(tls bool) config.Config {
		return config.Config{
			Port:       "8080",
			TLSEnabled: tls,
			Server: config.ServerConfig{
				ReadTimeout:                       2 * time.Second,
				WriteTimeout:                      3 * time.Second,
				IdleTimeout:                       4 * time.Second,
				ReadHeaderTimeout:                   time.Second,
				MaxHeaderBytes:                    2_000_000,
				HTTP2MaxConcurrentStreams:         100,
				HTTP2MaxReadFrameSize:             16384,
				HTTP2MaxUploadBufferPerConnection: 65536,
				HTTP2MaxUploadBufferPerStream:     32768,
				HTTP2ReadIdleTimeout:              5 * time.Second,
				HTTP2PingTimeout:                  2 * time.Second,
				HTTP2PermitProhibitedCipherSuites: true,
			},
		}
	}

	t.Run("plain", func(t *testing.T) {
		conf := base(false)
		srv := newHTTPServer(&conf, http.NotFoundHandler())
		if srv.Addr != ":8080" {
			t.Errorf("Addr: %q", srv.Addr)
		}
		if srv.ReadTimeout != 2*time.Second || srv.WriteTimeout != 3*time.Second || srv.IdleTimeout != 4*time.Second {
			t.Errorf("timeouts: read=%v write=%v idle=%v", srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
		}
		if srv.ReadHeaderTimeout != time.Second || srv.MaxHeaderBytes != 2_000_000 {
			t.Errorf("headers: read_header=%v max_bytes=%d", srv.ReadHeaderTimeout, srv.MaxHeaderBytes)
		}
		if srv.Protocols == nil {
			t.Fatal("Protocols")
		}
		if !srv.Protocols.HTTP1() || !srv.Protocols.UnencryptedHTTP2() {
			t.Errorf("Protocols: %v", srv.Protocols)
		}
		if srv.HTTP2 == nil {
			t.Fatal("HTTP2")
		}
		h2 := srv.HTTP2
		if h2.MaxConcurrentStreams != 100 || h2.MaxReadFrameSize != 16384 {
			t.Errorf("HTTP2 streams/frame: %d %d", h2.MaxConcurrentStreams, h2.MaxReadFrameSize)
		}
		if h2.MaxReceiveBufferPerConnection != 65536 || h2.MaxReceiveBufferPerStream != 32768 {
			t.Errorf("HTTP2 buffers: %d %d", h2.MaxReceiveBufferPerConnection, h2.MaxReceiveBufferPerStream)
		}
		if h2.SendPingTimeout != 5*time.Second || h2.PingTimeout != 2*time.Second {
			t.Errorf("HTTP2 ping: send=%v ping=%v", h2.SendPingTimeout, h2.PingTimeout)
		}
		if !h2.PermitProhibitedCipherSuites {
			t.Error("PermitProhibitedCipherSuites")
		}
	})

	t.Run("tls", func(t *testing.T) {
		conf := base(true)
		srv := newHTTPServer(&conf, http.NotFoundHandler())
		if srv.Protocols != nil {
			t.Errorf("Protocols should be nil for TLS, got %#v", srv.Protocols)
		}
		if srv.HTTP2 == nil || srv.HTTP2.MaxConcurrentStreams != 100 {
			t.Errorf("HTTP2: %#v", srv.HTTP2)
		}
	})
}