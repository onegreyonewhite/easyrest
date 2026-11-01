package sqlite

import (
	"testing"
)

func TestTableGetJSONArrows(t *testing.T) {
	plugin := &sqlitePlugin{}
	if err := plugin.InitConnection("sqlite://:memory:"); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}
	t.Cleanup(func() { plugin.db.Close() })
	if _, err := plugin.db.Exec(`CREATE TABLE people (id INTEGER, json_data TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.db.Exec(`INSERT INTO people (id, json_data) VALUES
		(1, '{"blood_type":"A-","age":25,"phones":[{"number":"917-929-5745"}]}'),
		(2, '{"blood_type":"O+","age":9,"phones":[{"number":"512-446-4988"}]}'),
		(3, '{"blood_type":"A-","age":20,"phones":[]}')`); err != nil {
		t.Fatal(err)
	}

	fields := []string{
		"id",
		`json_data->>'blood_type' AS "blood_type"`,
		`json_data->'phones' AS "phones"`,
	}
	rows, _, err := plugin.TableGet("u", "people", fields, map[string]any{
		`json_data->>'blood_type'`: map[string]any{"=": "A-"},
	}, []string{"id"}, nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["blood_type"] != "A-" || rows[1]["blood_type"] != "A-" {
		t.Fatalf("text filter %#v", rows)
	}
	phones, ok := rows[0]["phones"].([]any)
	if !ok || len(phones) != 1 {
		t.Fatalf("phones %#v (%T)", rows[0]["phones"], rows[0]["phones"])
	}

	rows, _, err = plugin.TableGet("u", "people", []string{
		"id",
		`json_data->'phones'->0->>'number' AS "number"`,
	}, nil, []string{"id"}, nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0]["number"] != "917-929-5745" || rows[1]["number"] != "512-446-4988" {
		t.Fatalf("nested %#v", rows)
	}

	rows, _, err = plugin.TableGet("u", "people", []string{
		"id",
		`json_data->'age' AS "age"`,
		`json_data->>'age' AS "age_text"`,
	}, map[string]any{
		`json_data->'age'`: map[string]any{">": "20"},
	}, []string{"id"}, nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("gt.20 returned %d rows: %#v", len(rows), rows)
	}
	if rows[0]["age"] != float64(25) {
		t.Fatalf("age %#v (%T)", rows[0]["age"], rows[0]["age"])
	}
	if rows[0]["age_text"] != "25" {
		t.Fatalf("age text %#v (%T)", rows[0]["age_text"], rows[0]["age_text"])
	}
}
