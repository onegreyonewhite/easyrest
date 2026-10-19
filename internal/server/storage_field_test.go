package server

import "testing"

func TestStorageValueKindOf(t *testing.T) {
	cases := []struct {
		name string
		prop any
		want storageValueKind
	}{
		{
			name: "string binary",
			prop: map[string]any{"type": "string", "format": "binary"},
			want: storageValueBinary,
		},
		{
			name: "array of binary",
			prop: map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string", "format": "binary"},
			},
			want: storageValueBinaryList,
		},
		{
			name: "string base64",
			prop: map[string]any{"type": "string", "format": "base64"},
			want: storageValueBase64,
		},
		{
			name: "array of base64",
			prop: map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string", "format": "base64"},
			},
			want: storageValueBase64List,
		},
		{
			name: "string without format",
			prop: map[string]any{"type": "string"},
			want: storageValueNone,
		},
		{
			name: "sqlite byte blob",
			prop: map[string]any{"type": "string", "format": "byte"},
			want: storageValueNone,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := storageValueKindOf(tc.prop); got != tc.want {
				t.Fatalf("kind %d, want %d", got, tc.want)
			}
		})
	}
}
