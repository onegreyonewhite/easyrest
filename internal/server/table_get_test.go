package server

import "testing"

func TestPreferPageSize(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ctx  map[string]any
		want int
	}{
		{name: "nil ctx"},
		{name: "missing prefer", ctx: map[string]any{}},
		{name: "missing key", ctx: map[string]any{"prefer": map[string]any{}}},
		{name: "valid", ctx: map[string]any{"prefer": map[string]any{"page_size": "50"}}, want: 50},
		{name: "zero", ctx: map[string]any{"prefer": map[string]any{"page_size": "0"}}},
		{name: "negative", ctx: map[string]any{"prefer": map[string]any{"page_size": "-1"}}},
		{name: "non integer", ctx: map[string]any{"prefer": map[string]any{"page_size": "abc"}}},
		{name: "non string", ctx: map[string]any{"prefer": map[string]any{"page_size": 20}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := preferPageSize(tc.ctx); got != tc.want {
				t.Fatalf("preferPageSize = %d, want %d", got, tc.want)
			}
		})
	}
}
