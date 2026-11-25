package sqlite

import (
	"context"
	"testing"
)

func TestSQLiteRawQuery(t *testing.T) {
	plug := NewSqlitePlugin()
	if err := plug.InitConnection("sqlite://:memory:"); err != nil {
		t.Fatalf("InitConnection: %v", err)
	}
	defer plug.Close()

	ctx := context.Background()
	if _, err := plug.RawQuery(ctx, "DROP TABLE IF EXISTS raw_items"); err != nil {
		t.Fatalf("DROP: %v", err)
	}
	if _, err := plug.RawQuery(ctx, "CREATE TABLE raw_items (id INTEGER PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}
	if rows, err := plug.RawQuery(ctx, "INSERT INTO raw_items (name) VALUES ('ada')"); err != nil {
		t.Fatalf("INSERT: %v", err)
	} else if len(rows) != 0 {
		t.Fatalf("INSERT rows len = %d, want 0", len(rows))
	}
	rows, err := plug.RawQuery(ctx, "SELECT id, name FROM raw_items")
	if err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if len(rows) != 1 || rows[0]["name"] != "ada" {
		t.Fatalf("SELECT result: %#v", rows)
	}
}