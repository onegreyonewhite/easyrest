package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	hplugin "github.com/hashicorp/go-plugin"
	lru "github.com/hashicorp/golang-lru/v2"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	_ "go.uber.org/automaxprocs"
	"golang.org/x/sync/singleflight"
	_ "modernc.org/sqlite"
)

var backgroundCtx = context.Background()

type ctxKey string

const userIDKey ctxKey = "USER_ID"

// sqlitePlugin implements easyrest.DBPlugin for SQLite.
type sqlitePlugin struct {
	db            *sql.DB
	preparedStmts *lru.Cache[string, *sql.Stmt]
	stmtGroup     singleflight.Group
}

type sqliteCachePlugin struct {
	dbPluginPointer *sqlitePlugin
}

// InitConnection opens the SQLite database based on the provided URI.
func (s *sqlitePlugin) InitConnection(uri string) error {
	// Expected format: sqlite://<path>
	if !strings.HasPrefix(uri, "sqlite://") {
		return errors.New("invalid sqlite URI")
	}
	dbPath := strings.TrimPrefix(uri, "sqlite://")
	var err error
	s.db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}

	// Initialize LRU cache for prepared statements
	s.preparedStmts, err = lru.New[string, *sql.Stmt](1000)
	if err != nil {
		return fmt.Errorf("failed to create LRU cache: %w", err)
	}

	// SQLite settings optimization
	s.db.SetMaxOpenConns(25)
	s.db.SetMaxIdleConns(5)
	s.db.SetConnMaxLifetime(30 * time.Minute)

	// Enable WAL mode for better performance
	_, err = s.db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		return err
	}

	// Increase cache size for better performance
	_, err = s.db.Exec("PRAGMA cache_size=10000")
	if err != nil {
		return err
	}

	return s.db.Ping()
}

func (s *sqliteCachePlugin) InitConnection(uri string) error {
	err := s.dbPluginPointer.InitConnection(uri)
	if err != nil {
		return err
	}
	_, err = s.dbPluginPointer.db.Exec("CREATE TABLE IF NOT EXISTS easyrest_cache (key TEXT PRIMARY KEY, value TEXT, expires_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
	if err != nil {
		return fmt.Errorf("failed to create cache table: %w", err)
	}

	// Launch background goroutine for cleanup
	go s.cleanupExpiredCacheEntries()

	return nil
}

// cleanupExpiredCacheEntries periodically deletes expired cache entries.
func (s *sqliteCachePlugin) cleanupExpiredCacheEntries() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Use CURRENT_TIMESTAMP directly in SQL for simplicity and accuracy
		_, err := s.dbPluginPointer.db.Exec("DELETE FROM easyrest_cache WHERE expires_at <= CURRENT_TIMESTAMP")
		if err != nil {
			// Log the error, but continue running the cleanup
			fmt.Fprintf(os.Stderr, "Error cleaning up expired cache entries: %v\n", err)
		}
	}
}

func (s *sqliteCachePlugin) Set(key string, value string, ttl time.Duration) error {
	_, err := s.dbPluginPointer.db.Exec("INSERT OR REPLACE INTO easyrest_cache (key, value, expires_at) VALUES (?, ?, ?)", key, value, time.Now().Add(ttl))
	if err != nil {
		return err
	}
	return nil
}

func (s *sqliteCachePlugin) Get(key string) (string, error) {
	var value string
	err := s.dbPluginPointer.db.QueryRow("SELECT value FROM easyrest_cache WHERE key = ? AND expires_at > ? ORDER BY expires_at LIMIT 1", key, time.Now()).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// Get prepared statement from cache or create new
func (s *sqlitePlugin) getPreparedStmt(query string, ctx context.Context) (*sql.Stmt, error) {
	// Try to get from cache first
	if stmt, exists := s.preparedStmts.Get(query); exists {
		return stmt, nil
	}

	// If not in cache, create using singleflight to prevent races
	v, err, _ := s.stmtGroup.Do(query, func() (interface{}, error) {
		// Check cache again in case another goroutine has created it
		if stmt, exists := s.preparedStmts.Get(query); exists {
			return stmt, nil
		}

		stmt, err := s.db.PrepareContext(ctx, query)
		if err != nil {
			return nil, err
		}

		s.preparedStmts.Add(query, stmt)
		return stmt, nil
	})

	if err != nil {
		return nil, err
	}

	return v.(*sql.Stmt), nil
}

// convertILIKEtoLike converts ILIKE operator to LIKE with COLLATE NOCASE
func convertILIKEtoLike(where map[string]any) map[string]any {
	result := make(map[string]any)
	for field, val := range where {
		switch v := val.(type) {
		case map[string]any:
			for op, operand := range v {
				if op == "ILIKE" {
					result[field+" COLLATE NOCASE"] = map[string]any{"LIKE": operand}
				} else {
					result[field] = v
				}
			}
		default:
			result[field] = v
		}
	}
	return result
}

// Function implementation to handle transactions, adapted for SQLite.
func (s *sqlitePlugin) handleTransaction(userID string, ctxMap map[string]any, operation func(tx *sql.Tx) (any, error)) (any, error) {
	ctxQuery := context.WithValue(backgroundCtx, userIDKey, userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin tx: %w", err)
	}

	// Default transaction preference is commit
	txPreference := "commit"
	isValidPreference := true
	preferenceError := ""

	if ctxMap != nil {
		// Check and validate prefer.tx preference
		if preferVal, ok := ctxMap["prefer"]; ok && preferVal != nil {
			if preferMap, ok := preferVal.(map[string]any); ok {
				if txVal, ok := preferMap["tx"]; ok && txVal != nil {
					// Check if 'tx' is a string
					if txStr, ok := txVal.(string); ok {
						if txStr != "" { // If it's a non-empty string
							txPreference = strings.ToLower(txStr)
							if txPreference != "commit" && txPreference != "rollback" {
								isValidPreference = false
								preferenceError = fmt.Sprintf("invalid value for prefer.tx: '%s'. Must be 'commit' or 'rollback'", txStr)
							}
							// If txStr is "", txPreference remains default "commit", isValidPreference remains true.
						}
						// If txStr is "", it's valid, just use default preference.
					} else { // 'tx' exists but is NOT a string
						isValidPreference = false
						preferenceError = fmt.Sprintf("invalid type for prefer.tx: expected string, got %T", txVal)
					}
				}
			} else {
				isValidPreference = false
				preferenceError = fmt.Sprintf("invalid type for prefer: expected map[string]any, got %T", preferVal)
			}
		}

		if !isValidPreference {
			// No need to rollback tx as nothing has happened yet.
			return nil, errors.New(preferenceError)
		}
		// SQLite does not need injectContext like MySQL
	}

	// Execute the core operation
	result, err := operation(tx)
	if err != nil {
		tx.Rollback()   // Rollback on operation error
		return nil, err // Return the original error from the operation
	}

	// Commit or Rollback based on preference
	if txPreference == "rollback" {
		if err := tx.Rollback(); err != nil {
			return nil, fmt.Errorf("failed to rollback transaction: %w", err)
		}
		// Modify result for Update/Delete if rollback occurred
		switch res := result.(type) {
		case int: // Assumed from TableUpdate/TableDelete
			return 0, nil
		case int64: // Handle potential int64 return from RowsAffected directly
			return int64(0), nil
		default: // Assumed from TableCreate or others; return original result
			return res, nil
		}
	} else { // commit or default
		if err := tx.Commit(); err != nil {
			// Attempt rollback if commit fails, but return the commit error
			rbErr := tx.Rollback()
			if rbErr != nil {
				return nil, fmt.Errorf("failed to commit transaction: %w (rollback also failed: %v)", err, rbErr)
			}
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}
	}

	// Return the original result from the operation if committed successfully
	return result, nil
}

// TableGet constructs and executes a SELECT query.
func (s *sqlitePlugin) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error) {

	fields := "*"
	if len(selectFields) > 0 {
		fields = strings.Join(selectFields, ", ")
	}
	var sb strings.Builder
	sb.WriteString("SELECT ")
	sb.WriteString(fields)
	sb.WriteString(" FROM ")
	sb.WriteString(table)

	// Convert ILIKE to LIKE COLLATE NOCASE before building where clause
	where = convertILIKEtoLike(where)
	whereClause, args, err := easyrest.BuildWhereClauseSorted(where)
	if err != nil {
		return nil, err
	}
	sb.WriteString(whereClause)
	if len(groupBy) > 0 {
		sb.WriteString(" GROUP BY ")
		sb.WriteString(strings.Join(groupBy, ", "))
	}
	if len(ordering) > 0 {
		sb.WriteString(" ORDER BY ")
		sb.WriteString(strings.Join(ordering, ", "))
	}
	if limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
		if offset > 0 {
			sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
		}
	} else if offset > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT -1 OFFSET %d", offset))
	}
	query := sb.String()

	ctxQuery := context.WithValue(backgroundCtx, userIDKey, userID)

	// Use prepared statement for better performance
	stmt, err := s.getPreparedStmt(query, ctxQuery)
	if err != nil {
		return nil, err
	}

	rows, err := stmt.QueryContext(ctxQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	numCols := len(cols)

	// Pre-allocate memory for results
	var results []map[string]any
	for rows.Next() {
		// Use pointer scanning for better performance
		columns := make([]any, numCols)
		columnPointers := make([]any, numCols)
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			return nil, err
		}

		rowMap := make(map[string]any, numCols)
		for i, colName := range cols {
			if t, ok := columns[i].(time.Time); ok {
				if t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0 {
					rowMap[colName] = t.Format("2006-01-02")
				} else {
					rowMap[colName] = t.Format("2006-01-02 15:04:05")
				}
			} else {
				rowMap[colName] = columns[i]
			}
		}
		results = append(results, rowMap)
	}

	return results, nil
}

// TableCreate builds and executes an INSERT query.
func (s *sqlitePlugin) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
	res, err := s.handleTransaction(userID, ctx, func(tx *sql.Tx) (any, error) {
		ctxQuery := context.WithValue(backgroundCtx, userIDKey, userID)
		var results []map[string]any
		for _, row := range data {
			cols := make([]string, 0, len(row))
			placeholders := make([]string, 0, len(row))
			args := make([]any, 0, len(row))
			for k, v := range row {
				cols = append(cols, k)
				placeholders = append(placeholders, "?")
				args = append(args, v)
			}
			baseQuery := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
			_, err := tx.ExecContext(ctxQuery, baseQuery, args...)
			if err != nil {
				// Error occurs within the loop, transaction will be rolled back by handleTransaction
				return nil, err
			}
			results = append(results, row)
		}
		// Return the collected input data.
		return results, nil
	})

	if err != nil {
		return nil, err // Error already includes context from handleTransaction or the operation
	}

	// Type assertion for the result
	if results, ok := res.([]map[string]any); ok {
		return results, nil
	}
	return nil, fmt.Errorf("unexpected result type from handleTransaction: %T", res)
}

// TableUpdate builds and executes an UPDATE query.
func (s *sqlitePlugin) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error) {
	res, err := s.handleTransaction(userID, ctx, func(tx *sql.Tx) (any, error) {
		ctxQuery := context.WithValue(backgroundCtx, userIDKey, userID)
		var setParts []string
		var args []any
		if len(data) > 0 {
			setParts = make([]string, 0, len(data))
			args = make([]any, 0, len(data))
		} else {
			setParts = []string{}
			args = []any{}
		}
		for k, v := range data {
			setParts = append(setParts, fmt.Sprintf("%s = ?", k))
			args = append(args, v)
		}
		var sb strings.Builder
		sb.WriteString("UPDATE ")
		sb.WriteString(table)
		sb.WriteString(" SET ")
		sb.WriteString(strings.Join(setParts, ", "))
		baseQuery := sb.String()

		// Convert ILIKE to LIKE COLLATE NOCASE before building where clause
		where = convertILIKEtoLike(where)
		whereClause, whereArgs, err := easyrest.BuildWhereClauseSorted(where)
		if err != nil {
			// Error in building WHERE clause, transaction will be rolled back
			return 0, err
		}
		baseQuery += whereClause
		args = append(args, whereArgs...)
		sqlRes, err := tx.ExecContext(ctxQuery, baseQuery, args...)
		if err != nil {
			// Error during execution, transaction will be rolled back
			return 0, err
		}
		affected, err := sqlRes.RowsAffected()
		if err != nil {
			// Error getting affected rows, transaction will be rolled back
			return 0, err
		}
		return int(affected), nil
	})

	if err != nil {
		return 0, err // Error already includes context from handleTransaction or the operation
	}

	// Type assertion for the result
	if affected, ok := res.(int); ok {
		return affected, nil
	}
	return 0, fmt.Errorf("unexpected result type from handleTransaction: %T", res)
}

// TableDelete builds and executes a DELETE query.
func (s *sqlitePlugin) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, error) {
	res, err := s.handleTransaction(userID, ctx, func(tx *sql.Tx) (any, error) {
		ctxQuery := context.WithValue(backgroundCtx, userIDKey, userID)
		// Convert ILIKE to LIKE COLLATE NOCASE before building where clause
		where = convertILIKEtoLike(where)
		whereClause, whereArgs, err := easyrest.BuildWhereClauseSorted(where)
		if err != nil {
			// Error in building WHERE clause, transaction will be rolled back
			return 0, err
		}
		var sb strings.Builder
		sb.WriteString("DELETE FROM ")
		sb.WriteString(table)
		sb.WriteString(whereClause)
		baseQuery := sb.String()
		sqlRes, err := tx.ExecContext(ctxQuery, baseQuery, whereArgs...)
		if err != nil {
			// Error during execution, transaction will be rolled back
			return 0, err
		}
		affected, err := sqlRes.RowsAffected()
		if err != nil {
			// Error getting affected rows, transaction will be rolled back
			return 0, err
		}
		return int(affected), nil
	})

	if err != nil {
		return 0, err // Error already includes context from handleTransaction or the operation
	}

	// Type assertion for the result
	if affected, ok := res.(int); ok {
		return affected, nil
	}
	return 0, fmt.Errorf("unexpected result type from handleTransaction: %T", res)
}

// CallFunction returns an error since it is not supported.
func (s *sqlitePlugin) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
	return nil, http.ErrNotSupported
}

// GetSchema returns a schema object with three keys:
// "tables" is a map from table names to JSON schema (Swagger 2.0 compatible),
// "views" is a map from view names to JSON schema,
// "rpc" is nil since SQLite does not support stored procedures.
func (s *sqlitePlugin) GetSchema(ctx map[string]any) (any, error) {
	tables := make(map[string]any)
	views := make(map[string]any)
	// Query for both tables and views, excluding internal objects.
	rows, err := s.db.Query("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var name, typ string
	var items = make(map[string]string)
	for rows.Next() {
		if err := rows.Scan(&name, &typ); err != nil {
			return nil, err
		}
		items[name] = typ
	}
	for name, typ := range items {
		schema, err := s.getJSONSchemaForTable(name)
		if err != nil {
			return nil, err
		}
		if typ == "table" {
			tables[name] = schema
		} else if typ == "view" {
			views[name] = schema
		}
	}
	result := map[string]any{
		"tables": tables,
		"views":  views,
		"rpc":    nil,
	}
	return result, nil
}

// getJSONSchemaForTable builds a JSON schema for a given table by querying PRAGMA table_info.
func (s *sqlitePlugin) getJSONSchemaForTable(tableName string) (map[string]any, error) {
	query := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	properties := make(map[string]any)
	var required []string
	for rows.Next() {
		var cid int
		var name, colType string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notnull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		jsType := mapSQLiteType(colType)
		prop := map[string]any{
			"type": jsType,
		}
		// If BLOB type, add format "byte".
		if strings.Contains(strings.ToUpper(colType), "BLOB") {
			prop["format"] = "byte"
		}
		// If the column allows null, mark as x-nullable.
		if notnull == 0 {
			prop["x-nullable"] = true
		}
		// If the column is primary key, mark as readOnly.
		if pk > 0 {
			prop["readOnly"] = true
		}
		properties[name] = prop
		// Add to required only if column is NOT NULL and has no DEFAULT value.
		if notnull == 1 && !dfltValue.Valid {
			required = append(required, name)
		}
	}
	// Always include "required" key (even if empty).
	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}

	return schema, nil
}

// mapSQLiteType maps an SQLite column type to a JSON schema type.
func mapSQLiteType(sqliteType string) string {
	upperType := strings.ToUpper(sqliteType)
	if strings.Contains(upperType, "INT") {
		return "integer"
	} else if strings.Contains(upperType, "CHAR") || strings.Contains(upperType, "CLOB") || strings.Contains(upperType, "TEXT") {
		return "string"
	} else if strings.Contains(upperType, "BLOB") {
		return "string"
	} else if strings.Contains(upperType, "REAL") || strings.Contains(upperType, "FLOA") || strings.Contains(upperType, "DOUB") {
		return "number"
	}
	return "string"
}

func main() {
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(easyrest.Version)
		return
	}

	impl := &sqlitePlugin{}
	cacheImpl := &sqlitePlugin{}
	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: easyrest.Handshake,
		Plugins: map[string]hplugin.Plugin{
			"db":    &easyrest.DBPluginPlugin{Impl: impl},
			"cache": &easyrest.CachePluginPlugin{Impl: &sqliteCachePlugin{dbPluginPointer: cacheImpl}},
		},
		Test: nil,
	})
}
