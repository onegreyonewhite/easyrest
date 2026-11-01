package plugin

import (
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// ErrInvalidDataURL is returned when a string is not a data URL.
var ErrInvalidDataURL = errors.New("invalid data url")

// ParseDataURL splits a data URL into a media type and bytes.
// An omitted media type is returned as an empty string.
// A base64 payload must use standard encoding with padding and no whitespace.
func ParseDataURL(raw string) (string, []byte, error) {
	if len(raw) < len("data:") || !strings.EqualFold(raw[:len("data:")], "data:") {
		return "", nil, ErrInvalidDataURL
	}
	rest := raw[len("data:"):]
	comma := strings.IndexByte(rest, ',')
	if comma < 0 {
		return "", nil, ErrInvalidDataURL
	}
	meta, payload := rest[:comma], rest[comma+1:]
	base64Mode := false
	if stripped, ok := cutBase64Token(meta); ok {
		base64Mode = true
		meta = stripped
	}
	mediaType, err := dataURLMediaType(strings.TrimSpace(meta))
	if err != nil {
		return "", nil, err
	}
	body, err := decodeDataURLPayload(payload, base64Mode)
	if err != nil {
		return "", nil, err
	}
	return mediaType, body, nil
}

// FormatDataURL builds a data URL with a standard base64 payload.
// An empty mediaType is replaced with the detected content type.
// A media type that cannot be parsed becomes application/octet-stream.
func FormatDataURL(mediaType string, body []byte) string {
	formatted := canonicalMediaType(mediaType, body)
	return "data:" + formatted + ";base64," + base64.StdEncoding.EncodeToString(body)
}

func dataURLMediaType(meta string) (string, error) {
	if meta == "" {
		return "", nil
	}
	parsed, params, err := mime.ParseMediaType(meta)
	if err != nil {
		return "", ErrInvalidDataURL
	}
	formatted := mime.FormatMediaType(parsed, params)
	if formatted == "" {
		return "", ErrInvalidDataURL
	}
	return formatted, nil
}

func decodeDataURLPayload(payload string, base64Mode bool) ([]byte, error) {
	if base64Mode {
		if strings.ContainsAny(payload, " \t\r\n") {
			return nil, ErrInvalidDataURL
		}
		body, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, ErrInvalidDataURL
		}
		return body, nil
	}
	decoded, err := url.PathUnescape(payload)
	if err != nil {
		return nil, ErrInvalidDataURL
	}
	return []byte(decoded), nil
}

func canonicalMediaType(mediaType string, body []byte) string {
	mediaType = strings.TrimSpace(mediaType)
	if mediaType == "" {
		mediaType = http.DetectContentType(body)
	}
	parsed, params, err := mime.ParseMediaType(mediaType)
	if err != nil || parsed == "" {
		return "application/octet-stream"
	}
	formatted := mime.FormatMediaType(parsed, params)
	if formatted == "" {
		return "application/octet-stream"
	}
	return formatted
}

func cutBase64Token(meta string) (string, bool) {
	trimmed := strings.TrimSpace(meta)
	const token = "base64"
	if len(trimmed) < len(token) || !strings.EqualFold(trimmed[len(trimmed)-len(token):], token) {
		return meta, false
	}
	head := strings.TrimSpace(trimmed[:len(trimmed)-len(token)])
	if !strings.HasSuffix(head, ";") {
		return meta, false
	}
	return strings.TrimSpace(head[:len(head)-1]), true
}
