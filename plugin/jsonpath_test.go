package plugin

import (
	"strings"
	"testing"
)

func TestJSONWherePostgres(t *testing.T) {
	t.Parallel()

	clause, args, err := BuildWhereClauseSorted(map[string]any{
		`json_data->>'blood_type'`: map[string]any{"=": "A-"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if clause != ` WHERE (json_data->>'blood_type') = ?` || len(args) != 1 || args[0] != "A-" {
		t.Fatalf("text %q %#v", clause, args)
	}

	clause, args, err = BuildWhereClauseSorted(map[string]any{
		`json_data->'age'`: map[string]any{">": "20"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if clause != ` WHERE (json_data->'age') > ?::jsonb` || args[0] != "20" {
		t.Fatalf("json %q %#v", clause, args)
	}

	clause, _, err = BuildWhereClauseSorted(map[string]any{
		`NOT json_data->>'blood_type'`: map[string]any{"=": "A-"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if clause != ` WHERE NOT ((json_data->>'blood_type') = ?)` {
		t.Fatalf("not %q", clause)
	}

	_, _, err = BuildWhereClauseSorted(map[string]any{
		`json_data->'age'`: map[string]any{"LIKE": "2%"},
	})
	if err == nil || !strings.Contains(err.Error(), "->>") {
		t.Fatalf("like: %v", err)
	}
}

func TestJSONWhereMySQL(t *testing.T) {
	t.Parallel()

	clause, args, err := BuildWhereClauseSortedFor(map[string]any{
		`json_data->'phones'->0->>'number'`: map[string]any{"=": "917"},
		`json_data->'age'`:                  map[string]any{">": "20"},
	}, DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clause, `(json_data->>'$.phones[0].number') = ?`) {
		t.Fatalf("path %q", clause)
	}
	if !strings.Contains(clause, `(json_data->'$.age') > CAST(? AS JSON)`) || args[0] != "20" && args[1] != "20" {
		t.Fatalf("cast %q %#v", clause, args)
	}

	got, err := RewriteJSONSelectFields([]string{
		`json_data->'phones'->0->>'number' AS "number"`,
		`languages->0 AS primary_language`,
		"id",
	}, DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "json_data->>'$.phones[0].number' AS `number`" {
		t.Fatalf("select %q", got[0])
	}
	if got[1] != "languages->'$[0]' AS primary_language" || got[2] != "id" {
		t.Fatalf("select %#v", got)
	}

	clause, _, err = BuildWhereClauseSortedFor(map[string]any{
		`LOWER(json_data->>'name')`: map[string]any{"LIKE": "a%"},
	}, DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	if clause != ` WHERE LOWER((json_data->>'$.name')) LIKE ?` {
		t.Fatalf("ilike %q", clause)
	}
}

func TestJSONWhereSQLite(t *testing.T) {
	t.Parallel()

	clause, args, err := BuildWhereClauseSortedFor(map[string]any{
		`json_data->'age'`: map[string]any{"=": "25"},
	}, DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	if clause != ` WHERE (json_data->'age') = json(?)` || args[0] != "25" {
		t.Fatalf("eq %q %#v", clause, args)
	}

	clause, args, err = BuildWhereClauseSortedFor(map[string]any{
		`json_data->'age'`: map[string]any{">": "20"},
	}, DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	if clause != ` WHERE CAST((json_data->>'age') AS REAL) > CAST(? AS REAL)` || args[0] != "20" {
		t.Fatalf("gt %q %#v", clause, args)
	}

	clause, args, err = BuildWhereClauseSortedFor(map[string]any{
		`json_data->'name'`: map[string]any{">": `"B"`},
	}, DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	if clause != ` WHERE (json_data->>'name') > ?` || args[0] != "B" {
		t.Fatalf("string gt %q %#v", clause, args)
	}

	_, _, err = BuildWhereClauseSortedFor(map[string]any{
		`json_data->'ok'`: map[string]any{">": "true"},
	}, DialectSQLite)
	if err == nil || !strings.Contains(err.Error(), "sqlite") {
		t.Fatalf("bool gt: %v", err)
	}

	clause, _, err = BuildWhereClauseSortedFor(map[string]any{
		`json_data->>'name' COLLATE NOCASE`: map[string]any{"LIKE": "a%"},
	}, DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	if clause != ` WHERE (json_data->>'name') COLLATE NOCASE LIKE ?` {
		t.Fatalf("nocase %q", clause)
	}
}

func TestNormalizeJSONArrowRows(t *testing.T) {
	t.Parallel()

	rows := []map[string]any{{
		"phones": `[{"number":"917"}]`,
		"age":    "25",
		"text":   int64(25),
		"kept":   "A-",
	}}
	NormalizeJSONArrowRows(rows, []string{
		`json_data->'phones' AS "phones"`,
		`json_data->'age' AS "age"`,
		`json_data->>'age' AS "text"`,
		`json_data->>'blood_type' AS "kept"`,
	})
	phones, ok := rows[0]["phones"].([]any)
	if !ok || len(phones) != 1 {
		t.Fatalf("phones %#v", rows[0]["phones"])
	}
	if rows[0]["age"] != float64(25) {
		t.Fatalf("age %#v (%T)", rows[0]["age"], rows[0]["age"])
	}
	if rows[0]["text"] != "25" || rows[0]["kept"] != "A-" {
		t.Fatalf("text %#v", rows[0])
	}
}
