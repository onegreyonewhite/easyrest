package plugin

import "testing"

func TestBuildAbsoluteUri(t *testing.T) {
	ctx := map[string]any{
		"request": map[string]any{
			"scheme": "https",
			"host":   "example.com:8433",
			"prefix": "/someapp",
		},
	}
	got := BuildAbsoluteUri(ctx, "/restapi/v1/users/?limit=10&offset=30")
	want := "https://example.com:8433/someapp/restapi/v1/users/?limit=10&offset=30"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	cases := []struct {
		name    string
		request map[string]any
		path    string
		want    string
	}{
		{
			name:    "empty prefix",
			request: map[string]any{"scheme": "https", "host": "example.com", "prefix": ""},
			path:    "/restapi/v1/users/?limit=10&offset=30",
			want:    "https://example.com/restapi/v1/users/?limit=10&offset=30",
		},
		{
			name:    "prefix without leading slash",
			request: map[string]any{"scheme": "https", "host": "example.com", "prefix": "someapp"},
			path:    "/restapi/v1/users/?limit=10&offset=30",
			want:    "https://example.com/someapp/restapi/v1/users/?limit=10&offset=30",
		},
		{
			name:    "path without leading slash",
			request: map[string]any{"scheme": "https", "host": "example.com", "prefix": "/someapp"},
			path:    "restapi/v1/users/?limit=10&offset=30",
			want:    "https://example.com/someapp/restapi/v1/users/?limit=10&offset=30",
		},
		{
			name:    "missing scheme",
			request: map[string]any{"host": "example.com"},
			path:    "/restapi/v1/users/?limit=10&offset=30",
			want:    "http://example.com/restapi/v1/users/?limit=10&offset=30",
		},
		{
			name:    "trailing prefix slash",
			request: map[string]any{"scheme": "https", "host": "example.com", "prefix": "/someapp/"},
			path:    "/restapi/v1/users/",
			want:    "https://example.com/someapp/restapi/v1/users/",
		},
		{
			name:    "empty query",
			request: map[string]any{"scheme": "https", "host": "example.com", "prefix": "/someapp"},
			path:    "/restapi/v1/users/?",
			want:    "https://example.com/someapp/restapi/v1/users/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildAbsoluteUri(map[string]any{"request": tc.request}, tc.path)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
