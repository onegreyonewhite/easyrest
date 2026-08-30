package plugin

import (
	"math"
	"testing"
	"time"
)

func TestCtxString(t *testing.T) {
	if _, ok := CtxString(nil, "k"); ok {
		t.Fatal("nil ctx")
	}
	if _, ok := CtxString(map[string]any{"k": 1}, "k"); ok {
		t.Fatal("non-string")
	}
	got, ok := CtxString(map[string]any{"k": "v"}, "k")
	if !ok || got != "v" {
		t.Fatalf("got %q %v", got, ok)
	}
}

func TestAsIntAndIntFromCtx(t *testing.T) {
	cases := []struct {
		in   any
		want int
		ok   bool
	}{
		{int(3), 3, true},
		{int8(3), 3, true},
		{int16(3), 3, true},
		{int32(3), 3, true},
		{int64(3), 3, true},
		{uint(3), 3, true},
		{uint8(3), 3, true},
		{uint16(3), 3, true},
		{uint32(3), 3, true},
		{uint64(3), 3, true},
		{float32(3.2), 3, true},
		{float64(3.9), 3, true},
		{"3", 0, false},
		{uint64(math.MaxUint64), 0, false},
	}
	for _, tc := range cases {
		got, ok := AsInt(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("AsInt(%T)=%d,%v want %d,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := IntFromCtx(nil, "n"); ok {
		t.Fatal("nil ctx")
	}
	got, ok := IntFromCtx(map[string]any{"n": int64(9)}, "n")
	if !ok || got != 9 {
		t.Fatalf("IntFromCtx: %d %v", got, ok)
	}
}

func TestBuildSelectQueryAndFormatSQLTime(t *testing.T) {
	q, args, err := BuildSelectQuery("users", nil, map[string]any{"id": map[string]any{"=": 1}}, []string{"name"}, []string{"id"}, 10, 5, SelectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if q != "SELECT * FROM users WHERE id = ? GROUP BY id ORDER BY name LIMIT 10 OFFSET 5" {
		t.Fatalf("query: %s", q)
	}
	if len(args) != 1 || args[0] != 1 {
		t.Fatalf("args: %#v", args)
	}
	q, _, err = BuildSelectQuery("t", []string{"a"}, nil, nil, nil, 0, 3, SelectOptions{OffsetNeedsLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	if q != "SELECT a FROM t LIMIT -1 OFFSET 3" {
		t.Fatalf("sqlite offset: %s", q)
	}
	day := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	if FormatSQLTime(day) != "2024-01-02" {
		t.Fatalf("date: %s", FormatSQLTime(day))
	}
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if FormatSQLTime(ts) != "2024-01-02 03:04:05" {
		t.Fatalf("datetime: %s", FormatSQLTime(ts))
	}
}

func TestScalarToContextString(t *testing.T) {
	if scalarToContextString("x") != "x" {
		t.Fatal("string")
	}
	if scalarToContextString(int(7)) != "7" {
		t.Fatal("int")
	}
	if scalarToContextString(int32(7)) != "7" {
		t.Fatal("int32")
	}
	if scalarToContextString(int64(7)) != "7" {
		t.Fatal("int64")
	}
	if scalarToContextString(3.5) != "3.5" {
		t.Fatal("float")
	}
	if scalarToContextString(true) != "true" {
		t.Fatal("bool")
	}
	if scalarToContextString(struct{ X int }{1}) == "" {
		t.Fatal("default")
	}
}
