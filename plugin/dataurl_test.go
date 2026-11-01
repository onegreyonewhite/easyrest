package plugin

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func TestParseDataURL(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G'}
	pngB64 := base64.StdEncoding.EncodeToString(png)
	tests := []struct {
		name      string
		raw       string
		mediaType string
		body      []byte
		wantErr   bool
	}{
		{
			name:      "base64 with media type",
			raw:       "data:image/png;base64," + pngB64,
			mediaType: "image/png",
			body:      png,
		},
		{
			name:      "base64 token is case insensitive",
			raw:       "DATA:image/png; BASE64," + pngB64,
			mediaType: "image/png",
			body:      png,
		},
		{
			name:      "charset stays with the media type",
			raw:       "data:text/plain;charset=utf-8;base64," + base64.StdEncoding.EncodeToString([]byte("hi")),
			mediaType: "text/plain; charset=utf-8",
			body:      []byte("hi"),
		},
		{
			name: "omitted media type with base64",
			raw:  "data:;base64," + pngB64,
			body: png,
		},
		{
			name: "percent encoded with omitted media type",
			raw:  "data:,hello%20world",
			body: []byte("hello world"),
		},
		{
			name:      "percent encoded keeps plus",
			raw:       "data:text/plain,a+b",
			mediaType: "text/plain",
			body:      []byte("a+b"),
		},
		{
			name:    "plain base64",
			raw:     pngB64,
			wantErr: true,
		},
		{
			name:    "missing comma",
			raw:     "data:image/png;base64",
			wantErr: true,
		},
		{
			name:    "bad base64",
			raw:     "data:image/png;base64,@@@",
			wantErr: true,
		},
		{
			name:    "whitespace in base64",
			raw:     "data:image/png;base64," + pngB64[:4] + " " + pngB64[4:],
			wantErr: true,
		},
		{
			name:    "bad percent encoding",
			raw:     "data:,%ZZ",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mediaType, body, err := ParseDataURL(tt.raw)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidDataURL) {
					t.Fatalf("ParseDataURL(%q) err = %v", tt.raw, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDataURL(%q) err = %v", tt.raw, err)
			}
			if mediaType != tt.mediaType {
				t.Fatalf("media type %q, want %q", mediaType, tt.mediaType)
			}
			if !bytes.Equal(body, tt.body) {
				t.Fatalf("body %q, want %q", body, tt.body)
			}
		})
	}
}

func TestFormatDataURL(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G'}
	got := FormatDataURL("image/png", png)
	want := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	if got != want {
		t.Fatalf("FormatDataURL() = %q, want %q", got, want)
	}
	mediaType, body, err := ParseDataURL(got)
	if err != nil || mediaType != "image/png" || !bytes.Equal(body, png) {
		t.Fatalf("round trip type %q body %q err %v", mediaType, body, err)
	}

	detected := FormatDataURL("", []byte("hi"))
	wantDetected := "data:text/plain; charset=utf-8;base64," + base64.StdEncoding.EncodeToString([]byte("hi"))
	if detected != wantDetected {
		t.Fatalf("detected = %q, want %q", detected, wantDetected)
	}

	fallback := FormatDataURL("not a type", png)
	wantFallback := "data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString(png)
	if fallback != wantFallback {
		t.Fatalf("fallback = %q, want %q", fallback, wantFallback)
	}
}
