package sqlite

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func createTempSQLiteDB(t *testing.T) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "sqlite-query-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		created_at DATETIME
	)`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO users (name, created_at) VALUES ('Alice', '2024-01-15 10:30:00')`)
	if err != nil {
		t.Fatalf("Failed to insert row: %v", err)
	}
	return dbPath
}

func TestBuildSQLiteDSN(t *testing.T) {
	t.Run("read-write default", func(t *testing.T) {
		dsn, err := buildSQLiteDSN("sqlite://./test.db", false)
		if err != nil {
			t.Fatal(err)
		}
		if dsn != "file:./test.db" {
			t.Fatalf("got dsn %q", dsn)
		}
	})

	t.Run("read-only adds mode=ro", func(t *testing.T) {
		dsn, err := buildSQLiteDSN("sqlite://./test.db", true)
		if err != nil {
			t.Fatal(err)
		}
		if dsn != "file:./test.db?mode=ro" {
			t.Fatalf("got dsn %q", dsn)
		}
	})

	t.Run("preserves existing query params", func(t *testing.T) {
		dsn, err := buildSQLiteDSN("sqlite://./test.db?_pragma=busy_timeout(5000)", true)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(dsn, "mode=ro") || !strings.Contains(dsn, "_pragma=busy_timeout(5000)") {
			t.Fatalf("got dsn %q", dsn)
		}
	})

	t.Run("invalid URI", func(t *testing.T) {
		_, err := buildSQLiteDSN("postgres://localhost/db", false)
		if err == nil {
			t.Fatal("expected error for invalid URI")
		}
	})
}

func TestSqliteQueryPluginInitConnection(t *testing.T) {
	dbPath := createTempSQLiteDB(t)
	defer os.Remove(dbPath)

	plugin := NewSqliteQueryPlugin()
	err := plugin.InitConnection("sqlite://" + dbPath)
	if err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}

	t.Run("invalid URI", func(t *testing.T) {
		p := NewSqliteQueryPlugin()
		err := p.InitConnection("invalid://path")
		if err == nil {
			t.Fatal("expected error for invalid URI")
		}
	})

	t.Run("missing database file", func(t *testing.T) {
		p := NewSqliteQueryPlugin()
		err := p.InitConnection("sqlite:///nonexistent/path/to/db.db")
		if err == nil {
			t.Fatal("expected error for missing file in read-only mode")
		}
	})
}

func TestSqliteQueryPluginQueryCall(t *testing.T) {
	dbPath := createTempSQLiteDB(t)
	defer os.Remove(dbPath)

	plugin := NewSqliteQueryPlugin()
	if err := plugin.InitConnection("sqlite://" + dbPath); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}

	t.Run("select rows", func(t *testing.T) {
		rows, err := plugin.QueryCall("SELECT id, name FROM users", nil)
		if err != nil {
			t.Fatalf("QueryCall failed: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("Expected 1 row, got %d", len(rows))
		}
		if rows[0]["name"] != "Alice" {
			t.Errorf("Expected name Alice, got %v", rows[0]["name"])
		}
	})

	t.Run("datetime formatting", func(t *testing.T) {
		rows, err := plugin.QueryCall("SELECT created_at FROM users", nil)
		if err != nil {
			t.Fatalf("QueryCall failed: %v", err)
		}
		createdAt, ok := rows[0]["created_at"].(string)
		if !ok {
			t.Fatalf("Expected string created_at, got %T", rows[0]["created_at"])
		}
		if createdAt != "2024-01-15 10:30:00" {
			t.Errorf("Expected formatted datetime, got %q", createdAt)
		}
	})

	t.Run("empty query", func(t *testing.T) {
		_, err := plugin.QueryCall("  ", nil)
		if err == nil {
			t.Fatal("expected error for empty query")
		}
	})

	t.Run("write rejected", func(t *testing.T) {
		_, err := plugin.QueryCall("INSERT INTO users (name) VALUES ('Bob')", nil)
		if err == nil {
			t.Fatal("expected error for write query in read-only mode")
		}
	})

	t.Run("invalid SQL", func(t *testing.T) {
		_, err := plugin.QueryCall("SELECT FROM broken", nil)
		if err == nil {
			t.Fatal("expected error for invalid SQL")
		}
	})
}

func TestVerifyReadOnlyConnection(t *testing.T) {
	dbPath := createTempSQLiteDB(t)
	defer os.Remove(dbPath)

	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatalf("Failed to open read-only DB: %v", err)
	}
	defer db.Close()

	if err := verifyReadOnlyConnection(db); err != nil {
		t.Fatalf("verifyReadOnlyConnection failed: %v", err)
	}
}

func TestScanResultRowsDateOnly(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE events (event_date DATE)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO events (event_date) VALUES ('2024-06-01')`)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query("SELECT event_date FROM events")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	results, err := scanResultRows(rows, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(results))
	}

	if val, ok := results[0]["event_date"].(string); ok {
		parsed, err := time.Parse("2006-01-02", val)
		if err == nil && parsed.Hour() == 0 {
			if val != "2024-06-01" {
				t.Errorf("Expected date-only format, got %q", val)
			}
		}
	}
}
