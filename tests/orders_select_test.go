package tests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	_ "modernc.org/sqlite"
	"github.com/onegreyonewhite/easyrest/internal/server"
)

// setupOrdersTestDB creates a temporary SQLite database with an orders table.
func setupOrdersTestDB(t *testing.T) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "orders_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temporary DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()
	createStmt := `CREATE TABLE orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		items INTEGER,
		order_date DATE,
		amount REAL
	);`
	_, err = db.Exec(createStmt)
	if err != nil {
		t.Fatalf("Failed to create orders table: %v", err)
	}
	return dbPath
}

// insertOrder inserts a record into the orders table.
func insertOrder(t *testing.T, dbPath string, items int, orderDate string, amount float64) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()
	res, err := db.Exec(`INSERT INTO orders (items, order_date, amount) VALUES (?, ?, ?)`, items, orderDate, amount)
	if err != nil {
		t.Fatalf("Failed to insert order: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get last insert id: %v", err)
	}
	return int(id)
}

// generateTestToken creates a JWT token for testing.
func generateTestToken(t *testing.T, secret string, scope string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": scope,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return tokenStr
}

// TestOrdersSelectSum verifies that the query "/api/test/orders/?select=amount.sum()"
// returns one record with field "sum" equal to the total of all amount values.
func TestOrdersSelectSum(t *testing.T) {
	dbPath := setupOrdersTestDB(t)
	defer os.Remove(dbPath)
	// Insert sample orders with amounts: 10.5, 20.0, 30.0 (total = 60.5)
	insertOrder(t, dbPath, 1, "2023-03-01", 10.5)
	insertOrder(t, dbPath, 2, "2023-03-01", 20.0)
	insertOrder(t, dbPath, 3, "2023-03-02", 30.0)

	// Set environment variables required for server operation.
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	os.Setenv("ER_CHECK_SCOPE", "0") // disable scope checking for tests
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

	tokenStr := generateTestToken(t, secret, "read")

	router := server.SetupRouter()
	// Perform the GET request.
	req, err := http.NewRequest("GET", "/api/test/orders/?select=amount.sum()", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result))
	}
	row := result[0]
	// The select processing assigns the alias "sum" for a count-less function.
	sumVal, ok := row["sum"].(float64)
	if !ok {
		t.Fatalf("Expected field 'sum' as float64, got: %v in %s", row["sum"], row)
	}
	expected := 10.5 + 20.0 + 30.0
	if sumVal != expected {
		t.Errorf("Expected sum %v, got %v", expected, sumVal)
	}
}

// TestOrdersSelectGroupBy verifies that the query
// "/api/test/orders/?select=total:amount.sum(),amount.avg(),order_date"
// returns one record per order_date group with proper aggregated values.
func TestOrdersSelectGroupBy(t *testing.T) {
	dbPath := setupOrdersTestDB(t)
	defer os.Remove(dbPath)
	// Insert sample orders:
	// For order_date "2023-03-01": two orders with amounts 10 and 20 (total = 30, avg = 15)
	// For order_date "2023-03-02": three orders with amounts 5, 15 and 25 (total = 45, avg = 15)
	insertOrder(t, dbPath, 1, "2023-03-01", 10)
	insertOrder(t, dbPath, 2, "2023-03-01", 20)
	insertOrder(t, dbPath, 1, "2023-03-02", 5)
	insertOrder(t, dbPath, 2, "2023-03-02", 15)
	insertOrder(t, dbPath, 3, "2023-03-02", 25)

	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	os.Setenv("ER_CHECK_SCOPE", "0")
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

	tokenStr := generateTestToken(t, secret, "read")

	router := server.SetupRouter()
	// Perform the GET request.
	req, err := http.NewRequest("GET", "/api/test/orders/?select=total:amount.sum(),amount.avg(),order_date", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	// We expect two groups: one for "2023-03-01" and one for "2023-03-02".
	if len(result) != 2 {
		t.Fatalf("Expected 2 rows, got %d", len(result))
	}
	// Verify each group.
	for _, row := range result {
		dateStr, ok := row["order_date"].(string)
		if !ok {
			t.Fatalf("Expected order_date as string, got: %v", row["order_date"])
		}
		switch dateStr {
		case "2023-03-01":
			total, ok1 := row["total"].(float64)
			avg, ok2 := row["avg"].(float64)
			if !ok1 || !ok2 {
				t.Fatalf("Expected total and avg as float64 for date %s", dateStr)
			}
			if total != 30 || avg != 15 {
				t.Errorf("For date %s, expected total=30 and avg=15; got total=%v, avg=%v", dateStr, total, avg)
			}
		case "2023-03-02":
			total, ok1 := row["total"].(float64)
			avg, ok2 := row["avg"].(float64)
			if !ok1 || !ok2 {
				t.Fatalf("Expected total and avg as float64 for date %s", dateStr)
			}
			if total != 45 || avg != 15 {
				t.Errorf("For date %s, expected total=45 and avg=15; got total=%v, avg=%v", dateStr, total, avg)
			}
		default:
			t.Errorf("Unexpected order_date: %s", dateStr)
		}
	}
}

// TestOrdersSelectCount verifies that the query "/api/test/orders/?select=count()"
// returns the total number of orders, and that a similar query with a where clause
// returns the count after filtering.
func TestOrdersSelectCount(t *testing.T) {
	dbPath := setupOrdersTestDB(t)
	defer os.Remove(dbPath)
	// Insert 4 orders.
	insertOrder(t, dbPath, 1, "2023-03-01", 10)
	insertOrder(t, dbPath, 2, "2023-03-01", 20)
	insertOrder(t, dbPath, 3, "2023-03-02", 30)
	insertOrder(t, dbPath, 4, "2023-03-02", 40)

	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	os.Setenv("ER_CHECK_SCOPE", "0")
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

	tokenStr := generateTestToken(t, secret, "read")

	router := server.SetupRouter()
	// First query: without where clause.
	req, err := http.NewRequest("GET", "/api/test/orders/?select=count()", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result))
	}
	countVal, ok := result[0]["count"].(float64)
	if !ok {
		t.Fatalf("Expected count as float64, got: %v", result[0]["count"])
	}
	if int(countVal) != 4 {
		t.Errorf("Expected count 4, got %v", countVal)
	}

	// Second query: with a where clause (e.g. orders with items > 2)
	req2, err := http.NewRequest("GET", "/api/test/orders/?select=count()&where.gt.items=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", "Bearer "+tokenStr)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d; body: %s", rr2.Code, rr2.Body.String())
	}
	var result2 []map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &result2); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if len(result2) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result2))
	}
	countVal2, ok := result2[0]["count"].(float64)
	if !ok {
		t.Fatalf("Expected count as float64, got: %v", result2[0]["count"])
	}
	// In our data, orders with items > 2 are those with items 3 and 4.
	if int(countVal2) != 2 {
		t.Errorf("Expected count 2 for where.gt.items=2, got %v", countVal2)
	}
}
