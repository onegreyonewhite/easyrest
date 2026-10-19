package plugin

import "testing"

func TestCountPreferenceAndMaxRows(t *testing.T) {
	cases := []struct {
		name string
		ctx  map[string]any
		mode string
		max  int
	}{
		{name: "nil"},
		{name: "exact", ctx: map[string]any{"prefer": map[string]any{"count": "exact"}}, mode: "exact"},
		{name: "planned", ctx: map[string]any{"prefer": map[string]any{"count": "planned"}}, mode: "planned"},
		{name: "estimated", ctx: map[string]any{"prefer": map[string]any{"count": "estimated"}}, mode: "estimated"},
		{name: "unknown", ctx: map[string]any{"prefer": map[string]any{"count": "nope"}}},
		{name: "non string", ctx: map[string]any{"prefer": map[string]any{"count": 1}}},
		{name: "max rows", ctx: map[string]any{"db_max_rows": 50}, max: 50},
		{name: "zero max", ctx: map[string]any{"db_max_rows": 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CountPreference(tc.ctx); got != tc.mode {
				t.Fatalf("CountPreference = %q, want %q", got, tc.mode)
			}
			wantMax := tc.max
			if wantMax == 0 {
				wantMax = 10000
			}
			if got := CountMaxRows(tc.ctx); got != wantMax {
				t.Fatalf("CountMaxRows = %d, want %d", got, wantMax)
			}
		})
	}
}

func TestCountSQLKeepsFilterAndDropsPage(t *testing.T) {
	inner, args, err := BuildSelectQuery("users", []string{"id"}, map[string]any{"city": "Berlin"}, nil, []string{"city"}, 0, 0, SelectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if inner != "SELECT id FROM users WHERE city = ? GROUP BY city" {
		t.Fatalf("unbounded select: %s", inner)
	}
	if len(args) != 1 || args[0] != "Berlin" {
		t.Fatalf("args: %#v", args)
	}
	got := CountSQL(inner)
	want := "SELECT count(*) FROM (" + inner + ") AS er_count"
	if got != want {
		t.Fatalf("CountSQL = %s", got)
	}
}

func TestCountFromEstimate(t *testing.T) {
	exactCalls := 0
	exact := func() (int64, error) {
		exactCalls++
		return 8, nil
	}
	total, ok, err := CountFromEstimate("exact", 0, false, 10000, exact)
	if err != nil || !ok || total != 8 || exactCalls != 1 {
		t.Fatalf("exact: total=%d ok=%v err=%v calls=%d", total, ok, err, exactCalls)
	}

	exactCalls = 0
	total, ok, err = CountFromEstimate("planned", 10, true, 10000, exact)
	if err != nil || !ok || total != 10 || exactCalls != 0 {
		t.Fatalf("planned: total=%d ok=%v calls=%d", total, ok, exactCalls)
	}

	exactCalls = 0
	total, ok, err = CountFromEstimate("estimated", 10, true, 10000, exact)
	if err != nil || !ok || total != 8 || exactCalls != 1 {
		t.Fatalf("estimated below: total=%d ok=%v calls=%d", total, ok, exactCalls)
	}

	exactCalls = 0
	total, ok, err = CountFromEstimate("estimated", 10000, true, 10000, exact)
	if err != nil || !ok || total != 10000 || exactCalls != 0 {
		t.Fatalf("estimated at max: total=%d ok=%v calls=%d", total, ok, exactCalls)
	}

	exactCalls = 0
	total, ok, err = CountFromEstimate("estimated", 0, false, 10000, exact)
	if err != nil || ok || exactCalls != 0 {
		t.Fatalf("estimated without plan: ok=%v calls=%d", ok, exactCalls)
	}
}

func TestRoundCount(t *testing.T) {
	if got := RoundCount(10.4); got != 10 {
		t.Fatalf("10.4 -> %d", got)
	}
	if got := RoundCount(10.5); got != 11 {
		t.Fatalf("10.5 -> %d", got)
	}
	if got := RoundCount(-3); got != 0 {
		t.Fatalf("negative -> %d", got)
	}
}

func TestWithTotalKeepsContext(t *testing.T) {
	ctx := map[string]any{"timezone": "UTC"}
	got := WithTotal(ctx, 12)
	if got["total"] != int64(12) || got["timezone"] != "UTC" {
		t.Fatalf("with total: %#v", got)
	}
	ctx["timezone"] = "GMT"
	if got["timezone"] != "GMT" {
		t.Fatal("WithTotal must return the same map")
	}
	fresh := WithTotal(nil, 3)
	if fresh["total"] != int64(3) || len(fresh) != 1 {
		t.Fatalf("nil ctx: %#v", fresh)
	}
}
