// postgres_plugin.go
package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

var Version = "v0.5.3"

var bgCtx = context.Background()

// DBPool abstracts pgxpool.Pool and pgxmock.PgxPoolIface for production and testing
// Only the methods used in pgPlugin are included
type DBPool interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// pgPlugin implements the DBPlugin interface for PostgreSQL.
type pgPlugin struct {
	db             DBPool
	defaultTimeout time.Duration             // Default timeout for operations
	bulkThreshold  int                       // Threshold for bulk operations
	timezoneCache  map[string]*time.Location // Cache for loaded timezones
}

// newContextWithTimeout creates a new context with timeout
func (p *pgPlugin) newContextWithTimeout() (context.Context, context.CancelFunc) {
	if p.defaultTimeout == 0 {
		p.defaultTimeout = 30 * time.Second
	}
	return context.WithTimeout(bgCtx, p.defaultTimeout)
}

// parseConnectionParams extracts plugin-specific parameters from the URI query,
// returning the base DSN and parsed values.
func parseConnectionParams(uri string) (dsn string, maxConns int32, minConns int32, maxLifetime, maxIdleTime time.Duration, timeout time.Duration, bulkThreshold int, autoCleanup string, err error) {
	if !strings.HasPrefix(uri, "postgres://") {
		err = errors.New("invalid postgres URI")
		return
	}

	parsedURI, err := url.Parse(uri)
	if err != nil {
		return
	}

	queryParams := parsedURI.Query()
	// Default values
	maxOpenConns := 100
	maxIdleConns := 25
	connMaxLifetimeMin := 5
	connMaxIdleTimeMin := 10
	timeoutSec := 30
	bulkThresholdVal := 100

	// Helper to parse integer query params
	parseInt := func(key string, target *int) error {
		if valStr := queryParams.Get(key); valStr != "" {
			parsedVal, parseErr := strconv.Atoi(valStr)
			if parseErr != nil {
				return fmt.Errorf("invalid %s value: %s", key, valStr)
			}
			*target = parsedVal
			queryParams.Del(key) // Remove param after parsing
		}
		return nil
	}

	// Parse integer parameters
	if err = parseInt("maxOpenConns", &maxOpenConns); err != nil {
		return
	}
	if err = parseInt("maxIdleConns", &maxIdleConns); err != nil {
		return
	}
	if err = parseInt("connMaxLifetime", &connMaxLifetimeMin); err != nil {
		return
	}
	if err = parseInt("connMaxIdleTime", &connMaxIdleTimeMin); err != nil {
		return
	}
	if err = parseInt("timeout", &timeoutSec); err != nil {
		return
	}
	if err = parseInt("bulkThreshold", &bulkThresholdVal); err != nil {
		return
	}

	// Get autoCleanup (string)
	autoCleanup = queryParams.Get("autoCleanup")
	queryParams.Del("autoCleanup") // Remove even if empty

	// Re-encode URI to form the base DSN
	parsedURI.RawQuery = queryParams.Encode()
	dsn = parsedURI.String()

	// Assign parsed values to return variables
	maxConns = int32(maxOpenConns)
	minConns = int32(maxIdleConns) // pgxpool uses MinConns
	maxLifetime = time.Duration(connMaxLifetimeMin) * time.Minute
	maxIdleTime = time.Duration(connMaxIdleTimeMin) * time.Minute
	timeout = time.Duration(timeoutSec) * time.Second
	bulkThreshold = bulkThresholdVal

	return // Return parsed values and DSN
}

// InitConnection opens a PostgreSQL connection using a URI with the prefix "postgres://".
func (p *pgPlugin) InitConnection(uri string) error {
	dsn, maxConns, minConns, maxLifetime, maxIdleTime, timeout, bulkThreshold, _, err := parseConnectionParams(uri)
	if err != nil {
		// Propagate parsing errors
		return err
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("failed to parse base DSN: %w", err)
	}

	// Apply parsed parameters to the config
	cfg.MaxConns = maxConns
	cfg.MinConns = minConns
	cfg.MaxConnLifetime = maxLifetime
	cfg.MaxConnIdleTime = maxIdleTime

	// Create the pool using the configured settings
	db, err := pgxpool.NewWithConfig(bgCtx, cfg)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Assign plugin settings
	p.defaultTimeout = timeout
	p.bulkThreshold = bulkThreshold

	// Ping the database to verify connection
	pingCtx, cancel := context.WithTimeout(bgCtx, 5*time.Second) // Use a short ping timeout
	defer cancel()
	if err := db.Ping(pingCtx); err != nil {
		db.Close() // Ensure pool is closed on ping failure
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Assign the pool to the plugin
	p.db = db
	p.timezoneCache = make(map[string]*time.Location) // Initialize cache

	return nil
}

// ApplyPluginContext sets session variables using set_config for all keys in ctx.
// For each key, it sets two variables: one with prefix "request." (complex types are marshaled to JSON)
// and one with prefix "erctx." using the default string representation.
// Keys are processed in sorted order.
func ApplyPluginContext(ctx context.Context, tx pgx.Tx, pluginCtx map[string]any) error {
	if len(pluginCtx) == 0 {
		return nil
	}
	for key, val := range pluginCtx {
		var requestVal, erctxVal string
		switch v := val.(type) {
		case string:
			requestVal = v
			erctxVal = v
		case int, int8, int16, int32, int64:
			requestVal = fmt.Sprintf("%d", v)
			erctxVal = requestVal
		case float32, float64:
			requestVal = fmt.Sprintf("%f", v)
			erctxVal = requestVal
		case bool:
			requestVal = fmt.Sprintf("%t", v)
			erctxVal = requestVal
		case map[string]any, []any:
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			requestVal = string(b)
			erctxVal = string(b)
		default:
			strVal := fmt.Sprintf("%v", v)
			requestVal = strVal
			erctxVal = strVal
		}
		query := "SELECT set_config($1, $2, true)"
		if _, err := tx.Exec(ctx, query, "request."+key, requestVal); err != nil {
			return fmt.Errorf("failed to set request.%s: %w", key, err) // Add context to error
		}
		if _, err := tx.Exec(ctx, query, "erctx."+key, erctxVal); err != nil {
			return fmt.Errorf("failed to set erctx.%s: %w", key, err) // Add context to error
		}
	}

	return nil
}

// processRows processes query results in batches
func (p *pgPlugin) processRows(rows pgx.Rows, loc *time.Location) ([]map[string]any, error) {
	cols := rows.FieldDescriptions()
	numCols := len(cols)
	results := make([]map[string]any, 0, 1000)
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		rowMap := make(map[string]any, numCols)
		for i, col := range cols {
			val := values[i]
			switch v := val.(type) {
			case time.Time:
				adjusted := v.In(loc)
				if adjusted.Hour() == 0 && adjusted.Minute() == 0 && adjusted.Second() == 0 && adjusted.Nanosecond() == 0 {
					rowMap[string(col.Name)] = adjusted.Format("2006-01-02")
				} else {
					rowMap[string(col.Name)] = adjusted.Format("2006-01-02 15:04:05")
				}
			case []byte:
				rowMap[string(col.Name)] = string(v)
			case string, int, int8, int16, int32, int64, float32, float64, bool:
				rowMap[string(col.Name)] = v
			default:
				rowMap[string(col.Name)] = fmt.Sprintf("%v", v)
			}
		}
		results = append(results, rowMap)
	}
	return results, nil
}

// TableGet executes a SELECT query with optional WHERE, GROUP BY, ORDER BY, LIMIT and OFFSET.
func (p *pgPlugin) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error) {

	queryCtx, cancel := p.newContextWithTimeout()
	defer cancel()

	var queryBuilder strings.Builder
	queryBuilder.Grow(100 + len(table) + len(strings.Join(selectFields, ", ")))

	queryBuilder.WriteString("SELECT ")
	if len(selectFields) > 0 {
		queryBuilder.WriteString(strings.Join(selectFields, ", "))
	} else {
		queryBuilder.WriteByte('*')
	}
	queryBuilder.WriteString(" FROM ")
	queryBuilder.WriteString(table)

	whereClause, args, err := easyrest.BuildWhereClauseSorted(where)
	if err != nil {
		return nil, err
	}
	queryBuilder.WriteString(whereClause)

	if len(groupBy) > 0 {
		queryBuilder.WriteString(" GROUP BY ")
		queryBuilder.WriteString(strings.Join(groupBy, ", "))
	}
	if len(ordering) > 0 {
		queryBuilder.WriteString(" ORDER BY ")
		queryBuilder.WriteString(strings.Join(ordering, ", "))
	}
	if limit > 0 {
		queryBuilder.WriteString(" LIMIT ")
		queryBuilder.WriteString(strconv.Itoa(limit))
	}
	if offset > 0 {
		queryBuilder.WriteString(" OFFSET ")
		queryBuilder.WriteString(strconv.Itoa(offset))
	}

	finalQuery := convertPlaceholders(queryBuilder.String())

	tx, err := p.db.Begin(queryCtx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(queryCtx)

	loc := time.UTC
	if ctx != nil {
		if p.timezoneCache == nil {
			p.timezoneCache = make(map[string]*time.Location)
		}
		if len(ctx) > 0 {
			if err := ApplyPluginContext(queryCtx, tx, ctx); err != nil {
				tx.Rollback(queryCtx)
				return nil, err
			}
		}
		if tz, ok := ctx["timezone"].(string); ok && tz != "" {
			var cachedLoc *time.Location
			var found bool
			if cachedLoc, found = p.timezoneCache[tz]; !found {
				if l, err := time.LoadLocation(tz); err == nil {
					p.timezoneCache[tz] = l
					loc = l
				} else {
					log.Printf("Warning: Could not load timezone '%s', using UTC: %v", tz, err)
				}
			} else {
				loc = cachedLoc
			}
		}
	}

	rows, err := tx.Query(queryCtx, finalQuery, args...)
	if err != nil {
		tx.Rollback(queryCtx)
		return nil, err
	}
	defer rows.Close()

	results, err := p.processRows(rows, loc)
	if err != nil {
		tx.Rollback(queryCtx)
		return nil, err
	}

	if err := tx.Commit(queryCtx); err != nil {
		return nil, err
	}

	return results, nil
}

// TableCreate performs an INSERT operation on the specified table
func (p *pgPlugin) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
	if len(data) == 0 {
		return []map[string]any{}, nil
	}

	// Get transaction preference
	txPreference, err := easyrest.GetTxPreference(ctx)
	if err != nil {
		return nil, err
	}

	// Use COPY for large datasets
	if len(data) >= p.bulkThreshold {
		// Note: bulkCreate currently does not support the rollback preference.
		// It creates a temp table, copies, inserts, and commits within its own transaction.
		if txPreference == "rollback" {
			return nil, fmt.Errorf("rollback preference is not currently supported for bulk create operations (rows >= %d)", p.bulkThreshold)
		}
		return p.bulkCreate(table, data, ctx) // bulkCreate handles its own commit
	}

	tx, err := p.db.Begin(bgCtx)
	if err != nil {
		return nil, err
	}
	// Defer rollback in case of errors before the final commit/rollback decision
	defer tx.Rollback(bgCtx) // This will be ignored if Commit() or Rollback() is called explicitly later

	if ctx != nil {
		if err := ApplyPluginContext(bgCtx, tx, ctx); err != nil {
			// tx.Rollback() is handled by defer
			return nil, err
		}
	}

	keys := make([]string, 0, len(data[0]))
	for k := range data[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	colsStr := strings.Join(keys, ", ")

	// Pre-allocate slices based on data dimensions
	numRows := len(data)
	numCols := len(keys)
	args := make([]any, 0, numRows*numCols)
	valueStrings := make([]string, 0, numRows)
	placeholderCounter := 1

	var rowPlaceholders strings.Builder
	rowPlaceholders.Grow(numCols*4 + 1) // Estimate size like "($1,$2)"

	for _, row := range data {
		rowPlaceholders.Reset()
		rowPlaceholders.WriteByte('(')
		for i, k := range keys {
			if i > 0 {
				rowPlaceholders.WriteByte(',')
			}
			rowPlaceholders.WriteByte('$')
			rowPlaceholders.WriteString(strconv.Itoa(placeholderCounter))
			args = append(args, row[k])
			placeholderCounter++
		}
		rowPlaceholders.WriteByte(')')
		valueStrings = append(valueStrings, rowPlaceholders.String())
	}

	var queryBuilder strings.Builder
	// Estimate capacity
	queryBuilder.Grow(50 + len(table) + len(colsStr) + len(strings.Join(valueStrings, ", ")))

	queryBuilder.WriteString("INSERT INTO ")
	queryBuilder.WriteString(table)
	queryBuilder.WriteString(" (")
	queryBuilder.WriteString(colsStr)
	queryBuilder.WriteString(") VALUES ")
	queryBuilder.WriteString(strings.Join(valueStrings, ","))

	finalQuery := queryBuilder.String() // No need for convertPlaceholders anymore

	if _, err := tx.Exec(bgCtx, finalQuery, args...); err != nil {
		// tx.Rollback() is handled by defer
		return nil, err
	}

	// Conditionally commit or rollback based on preference
	if txPreference == "rollback" {
		if err := tx.Rollback(bgCtx); err != nil {
			return nil, fmt.Errorf("failed to rollback transaction: %w", err)
		}
		// Return the data as if it were inserted, even though rolled back
		return data, nil
	} else {
		if err := tx.Commit(bgCtx); err != nil {
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}
		return data, nil
	}
}

// bulkCreate uses COPY for efficient insertion of large amounts of data
func (p *pgPlugin) bulkCreate(table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
	tx, err := p.db.Begin(bgCtx)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(data[0]))
	for k := range data[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build pgx CopyFromSource
	records := make([][]any, len(data))
	for i, row := range data {
		rowVals := make([]any, len(keys))
		for j, k := range keys {
			rowVals[j] = row[k]
		}
		records[i] = rowVals
	}

	columns := make([]string, len(keys))
	copy(columns, keys)

	_, err = tx.CopyFrom(
		bgCtx,
		pgx.Identifier{table},
		columns,
		pgx.CopyFromRows(records),
	)
	if err != nil {
		tx.Rollback(bgCtx)
		return nil, err
	}

	if err := tx.Commit(bgCtx); err != nil {
		return nil, err
	}

	return data, nil
}

// TableUpdate executes an UPDATE query on the specified table.
func (p *pgPlugin) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error) {
	// Get transaction preference
	txPreference, err := easyrest.GetTxPreference(ctx)
	if err != nil {
		return 0, err
	}

	tx, err := p.db.Begin(bgCtx)
	if err != nil {
		return 0, err
	}
	// Defer rollback in case of errors
	defer tx.Rollback(bgCtx)

	if ctx != nil {
		if err := ApplyPluginContext(bgCtx, tx, ctx); err != nil {
			// tx.Rollback() is handled by defer
			return 0, err
		}
	}

	// Pre-allocate slices
	setParts := make([]string, 0, len(data))
	args := make([]any, 0, len(data)) // Initial capacity for SET args

	// Sort keys for deterministic query generation
	dataKeys := make([]string, 0, len(data))
	for k := range data {
		dataKeys = append(dataKeys, k)
	}
	sort.Strings(dataKeys)

	for _, k := range dataKeys {
		setParts = append(setParts, fmt.Sprintf("%s = ?", k)) // Keep fmt.Sprintf here as it's simple and clear
		args = append(args, data[k])
	}

	whereClause, whereArgs, err := easyrest.BuildWhereClauseSorted(where)
	if err != nil {
		// tx.Rollback() is handled by defer
		return 0, err
	}
	args = append(args, whereArgs...) // Append WHERE args

	var queryBuilder strings.Builder
	queryBuilder.Grow(50 + len(table) + len(strings.Join(setParts, ", ")) + len(whereClause))

	queryBuilder.WriteString("UPDATE ")
	queryBuilder.WriteString(table)
	queryBuilder.WriteString(" SET ")
	queryBuilder.WriteString(strings.Join(setParts, ", "))
	queryBuilder.WriteString(whereClause)

	finalQuery := convertPlaceholders(queryBuilder.String())

	res, err := tx.Exec(bgCtx, finalQuery, args...)
	if err != nil {
		// tx.Rollback() is handled by defer
		return 0, err
	}
	affected := res.RowsAffected()

	// Conditionally commit or rollback based on preference
	if txPreference == "rollback" {
		if err := tx.Rollback(bgCtx); err != nil {
			return 0, fmt.Errorf("failed to rollback transaction: %w", err)
		}
		// Return affected rows count even if rolled back
		return int(affected), nil
	} else {
		if err := tx.Commit(bgCtx); err != nil {
			return 0, fmt.Errorf("failed to commit transaction: %w", err)
		}
		return int(affected), nil
	}
}

// TableDelete executes a DELETE query on the specified table.
func (p *pgPlugin) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, error) {
	// Get transaction preference
	txPreference, err := easyrest.GetTxPreference(ctx)
	if err != nil {
		return 0, err
	}

	tx, err := p.db.Begin(bgCtx)
	if err != nil {
		return 0, err
	}
	// Defer rollback in case of errors
	defer tx.Rollback(bgCtx)

	if ctx != nil {
		if err := ApplyPluginContext(bgCtx, tx, ctx); err != nil {
			// tx.Rollback() is handled by defer
			return 0, err
		}
	}

	whereClause, args, err := easyrest.BuildWhereClauseSorted(where)
	if err != nil {
		// tx.Rollback() is handled by defer
		return 0, err
	}

	var queryBuilder strings.Builder
	queryBuilder.Grow(20 + len(table) + len(whereClause))

	queryBuilder.WriteString("DELETE FROM ")
	queryBuilder.WriteString(table)
	queryBuilder.WriteString(whereClause)

	finalQuery := convertPlaceholders(queryBuilder.String())

	res, err := tx.Exec(bgCtx, finalQuery, args...)
	if err != nil {
		// tx.Rollback() is handled by defer
		return 0, err
	}
	affected := res.RowsAffected()

	// Conditionally commit or rollback
	if txPreference == "rollback" {
		if err := tx.Rollback(bgCtx); err != nil {
			return 0, fmt.Errorf("failed to rollback transaction: %w", err)
		}
		// Return affected rows count even if rolled back
		return int(affected), nil
	} else {
		if err := tx.Commit(bgCtx); err != nil {
			return 0, fmt.Errorf("failed to commit transaction: %w", err)
		}
		return int(affected), nil
	}
}

// CallFunction executes a function call using SELECT syntax.
// Parameters are passed in sorted order by key.
// It handles scalar, SETOF, JSON, and void return types.
func (p *pgPlugin) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
	queryCtx, cancel := p.newContextWithTimeout()
	defer cancel()

	// Get transaction preference
	txPreference, err := easyrest.GetTxPreference(ctx)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Pre-allocate slices
	placeholders := make([]string, 0, len(keys))
	args := make([]any, 0, len(keys))

	for _, k := range keys {
		placeholders = append(placeholders, "?")
		args = append(args, data[k])
	}
	placeholdersStr := strings.Join(placeholders, ", ")

	var queryBuilder strings.Builder
	queryBuilder.Grow(20 + len(funcName) + len(placeholdersStr))

	queryBuilder.WriteString("SELECT * FROM ")
	queryBuilder.WriteString(funcName)
	queryBuilder.WriteString("(")
	queryBuilder.WriteString(placeholdersStr)
	queryBuilder.WriteString(")")

	finalQuery := convertPlaceholders(queryBuilder.String())

	tx, err := p.db.Begin(queryCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(queryCtx)

	loc := time.UTC
	if ctx != nil {
		if err := ApplyPluginContext(queryCtx, tx, ctx); err != nil {
			return nil, fmt.Errorf("failed to apply plugin context: %w", err)
		}
		if tz, ok := ctx["timezone"].(string); ok && tz != "" {
			if l, err := time.LoadLocation(tz); err == nil {
				loc = l
			} else {
				log.Printf("Warning: Could not load timezone '%s': %v", tz, err)
			}
		}
	}

	rows, err := tx.Query(queryCtx, finalQuery, args...)
	if err != nil {
		// Check for specific PostgreSQL error indicating function doesn't return SETOF
		// This might require checking the pgerr code. For now, general error handling.
		// If the error suggests it's not a set-returning function, we could retry with SELECT funcName(...)
		return nil, fmt.Errorf("failed to execute function query: %w", err)
	}
	defer rows.Close() // Ensure rows are closed

	// Use processRows to handle potential SETOF results or single composite results
	results, err := p.processRows(rows, loc)
	if err != nil {
		return nil, fmt.Errorf("failed to process function results: %w", err)
	}

	// Check if rows.Err() occurred during iteration in processRows
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during rows iteration: %w", err)
	}

	// Conditionally commit or rollback based on preference
	var finalErr error
	if txPreference == "rollback" {
		if err := tx.Rollback(queryCtx); err != nil {
			finalErr = fmt.Errorf("failed to rollback transaction: %w", err)
		}
		// No need to log here, behavior is intentional
	} else {
		if err := tx.Commit(queryCtx); err != nil {
			finalErr = fmt.Errorf("failed to commit transaction: %w", err)
		}
	}

	// Return results even if rollback was requested, but prioritize transaction error
	if finalErr != nil {
		return nil, finalErr
	}

	// Analyze the results
	if len(results) == 0 {
		// Function returned void or an empty set
		return nil, nil
	}

	if len(results) == 1 {
		rowMap := results[0]
		if len(rowMap) == 1 {
			// Single row, single column: Potential scalar or JSON
			var value any
			// Get the single value from the map
			for _, v := range rowMap {
				value = v
				break
			}

			switch v := value.(type) {
			case []byte:
				// Attempt to unmarshal if it looks like JSON
				var parsedResult any
				if json.Unmarshal(v, &parsedResult) == nil {
					log.Printf("Successfully unmarshaled []byte result from function %s", funcName)
					return parsedResult, nil
				}
				log.Printf("Result from function %s is []byte but not valid JSON, returning raw bytes", funcName)
				return v, nil // Return raw bytes if not JSON
			case string:
				// Attempt to unmarshal if it looks like JSON
				var parsedResult any
				if json.Unmarshal([]byte(v), &parsedResult) == nil {
					log.Printf("Successfully unmarshaled string result from function %s", funcName)
					return parsedResult, nil
				}
				log.Printf("Result from function %s is string but not valid JSON, returning raw string", funcName)
				return v, nil // Return raw string if not JSON
			default:
				// Return other scalar types directly
				log.Printf("Returning scalar result of type %T from function %s", v, funcName)
				return v, nil
			}
		}
		// Single row, multiple columns: Return as is (map within a slice)
		log.Printf("Returning single composite row result from function %s", funcName)
		return results, nil
	}

	// Multiple rows: Return the slice of maps directly (SETOF result)
	log.Printf("Returning SETOF result (%d rows) from function %s", len(results), funcName)
	return results, nil
}

// convertPlaceholders replaces each "?" in the query with PostgreSQL-style "$1", "$2", etc.
func convertPlaceholders(query string) string {
	var buf bytes.Buffer
	buf.Grow(len(query) + 10)
	counter := 1
	for i := range len(query) {
		if query[i] == '?' {
			buf.WriteByte('$')
			buf.WriteString(strconv.Itoa(counter))
			counter++
		} else {
			buf.WriteByte(query[i])
		}
	}
	return buf.String()
}

// getTablesSchema builds a schema for each base table from information_schema.
func (p *pgPlugin) getTablesSchema(tx pgx.Tx) (map[string]any, error) {
	result := make(map[string]any)
	tableQuery := "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
	rows, err := tx.Query(bgCtx, tableQuery)
	if err != nil {
		return nil, err
	}
	var tableNames []string
	for rows.Next() {
		var tn string
		if err := rows.Scan(&tn); err != nil {
			rows.Close()
			return nil, err
		}
		if tn == "easyrest_cache" {
			continue
		}
		tableNames = append(tableNames, tn)
	}
	rows.Close()
	for _, tn := range tableNames {
		colQuery := "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1"
		colRows, err := tx.Query(bgCtx, colQuery, tn)
		if err != nil {
			return nil, err
		}
		properties := make(map[string]any)
		required := make([]string, 0, 8)
		for colRows.Next() {
			var colName, dataType, isNullable string
			var colDefault sql.NullString
			if err := colRows.Scan(&colName, &dataType, &isNullable, &colDefault); err != nil {
				colRows.Close()
				return nil, err
			}
			swType := mapPostgresType(dataType)
			prop := map[string]any{
				"type": swType,
			}
			if isNullable == "YES" {
				prop["x-nullable"] = true
			}
			if isNullable == "NO" && !colDefault.Valid {
				required = append(required, colName)
			}
			properties[colName] = prop
		}
		colRows.Close()
		schema := map[string]any{
			"type":       "object",
			"properties": properties,
		}
		if len(required) > 0 {
			schema["required"] = required
		}
		result[tn] = schema
	}
	return result, nil
}

// getViewsSchema builds a schema for each view from information_schema.
func (p *pgPlugin) getViewsSchema(tx pgx.Tx) (map[string]any, error) {
	result := make(map[string]any)
	query := "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'VIEW'"
	rows, err := tx.Query(bgCtx, query)
	if err != nil {
		return nil, err
	}
	var viewNames []string
	for rows.Next() {
		var vn string
		if err := rows.Scan(&vn); err != nil {
			rows.Close()
			return nil, err
		}
		viewNames = append(viewNames, vn)
	}
	rows.Close()
	for _, vn := range viewNames {
		colQuery := "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1"
		colRows, err := tx.Query(bgCtx, colQuery, vn)
		if err != nil {
			return nil, err
		}
		properties := make(map[string]any)
		required := make([]string, 0, 8)
		for colRows.Next() {
			var colName, dataType, isNullable string
			var colDefault sql.NullString
			if err := colRows.Scan(&colName, &dataType, &isNullable, &colDefault); err != nil {
				colRows.Close()
				return nil, err
			}
			swType := mapPostgresType(dataType)
			prop := map[string]any{
				"type": swType,
			}
			if isNullable == "YES" {
				prop["x-nullable"] = true
			}
			if isNullable == "NO" && !colDefault.Valid {
				required = append(required, colName)
			}
			properties[colName] = prop
		}
		colRows.Close()
		schema := map[string]any{
			"type":       "object",
			"properties": properties,
		}
		if len(required) > 0 {
			schema["required"] = required
		}
		result[vn] = schema
	}
	return result, nil
}

// getRPCSchema builds schemas for stored functions.
func (p *pgPlugin) getRPCSchema(tx pgx.Tx) (map[string]any, error) {
	result := make(map[string]any)
	// Exclude functions belonging to extensions by checking pg_depend
	rpcQuery := `
	SELECT r.routine_name, r.specific_name, r.data_type
	FROM information_schema.routines r
	JOIN pg_catalog.pg_proc p ON r.routine_name = p.proname
	JOIN pg_catalog.pg_namespace n ON p.pronamespace = n.oid
	LEFT JOIN pg_catalog.pg_depend dep ON dep.objid = p.oid AND dep.classid = 'pg_catalog.pg_proc'::regclass AND dep.deptype = 'e'
	WHERE r.specific_schema = 'public'
	  AND n.nspname = 'public' -- Ensure the schema matches in both catalogs
	  AND r.routine_type = 'FUNCTION'
	  AND dep.objid IS NULL -- Only include functions NOT dependent on an extension
	`
	rows, err := tx.Query(bgCtx, rpcQuery)
	if err != nil {
		return nil, err
	}
	var routines []struct {
		routineName  string
		specificName string
		returnType   string
	}
	for rows.Next() {
		var rn, sn, rt string
		if err := rows.Scan(&rn, &sn, &rt); err != nil {
			rows.Close()
			return nil, err
		}
		routines = append(routines, struct {
			routineName  string
			specificName string
			returnType   string
		}{rn, sn, rt})
	}
	rows.Close()
	for _, r := range routines {
		paramQuery := "SELECT parameter_name, data_type, parameter_mode, ordinal_position FROM information_schema.parameters WHERE specific_schema = 'public' AND specific_name = $1 ORDER BY ordinal_position"
		paramRows, err := tx.Query(bgCtx, paramQuery, r.specificName)
		if err != nil {
			return nil, err
		}
		properties := make(map[string]any)
		reqFields := make([]string, 0, 4)
		for paramRows.Next() {
			var paramName sql.NullString
			var dataType, paramMode string
			var ordinal int
			if err := paramRows.Scan(&paramName, &dataType, &paramMode, &ordinal); err != nil {
				paramRows.Close()
				return nil, err
			}
			if !paramName.Valid {
				continue
			}
			swType := mapPostgresType(dataType)
			prop := map[string]any{
				"type": swType,
			}
			properties[paramName.String] = prop
			reqFields = append(reqFields, paramName.String)
		}
		paramRows.Close()
		inSchema := map[string]any{
			"type":       "object",
			"properties": properties,
		}
		if len(reqFields) > 0 {
			inSchema["required"] = reqFields
		}
		outSchema := map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		}
		if strings.ToLower(r.returnType) != "void" {
			outSchema["properties"] = map[string]any{
				"result": map[string]any{
					"type": mapPostgresType(r.returnType),
				},
			}
		}
		result[r.routineName] = []any{inSchema, outSchema}
	}
	return result, nil
}

// mapPostgresType converts a PostgreSQL data type to a JSON schema type.
func mapPostgresType(dt string) string {
	up := strings.ToUpper(dt)
	if strings.Contains(up, "INT") {
		return "integer"
	}
	if strings.Contains(up, "CHAR") || strings.Contains(up, "TEXT") {
		return "string"
	}
	if strings.Contains(up, "BOOL") {
		return "boolean"
	}
	if strings.Contains(up, "DATE") {
		return "string"
	}
	if strings.Contains(up, "TIME") {
		return "string"
	}
	if strings.Contains(up, "NUMERIC") || strings.Contains(up, "DECIMAL") || strings.Contains(up, "REAL") || strings.Contains(up, "DOUBLE") {
		return "number"
	}
	return "string"
}

// GetSchema returns a schema object with "tables", "views" and "rpc" keys.
// It applies the provided context to the session before retrieving the schema.
func (p *pgPlugin) GetSchema(ctx map[string]any) (any, error) {
	tx, err := p.db.Begin(bgCtx)
	if err != nil {
		return nil, err
	}
	if ctx != nil {
		if err := ApplyPluginContext(bgCtx, tx, ctx); err != nil {
			tx.Rollback(bgCtx)
			return nil, err
		}
	}
	tables, err := p.getTablesSchema(tx)
	if err != nil {
		tx.Rollback(bgCtx)
		return nil, err
	}
	views, err := p.getViewsSchema(tx)
	if err != nil {
		tx.Rollback(bgCtx)
		return nil, err
	}
	rpc, err := p.getRPCSchema(tx)
	if err != nil {
		tx.Rollback(bgCtx)
		return nil, err
	}
	if err := tx.Commit(bgCtx); err != nil {
		return nil, err
	}
	return map[string]any{
		"tables": tables,
		"views":  views,
		"rpc":    rpc,
	}, nil
}

// pgCachePlugin implements the CachePlugin interface using PostgreSQL.
type pgCachePlugin struct {
	dbPluginPointer *pgPlugin
}

// InitConnection ensures the cache table exists and starts the cleanup goroutine.
// It relies on the underlying pgPlugin's InitConnection being called first or concurrently
// by the plugin framework to establish the database connection.
func (p *pgCachePlugin) InitConnection(uri string) error {
	// Parse params to get autoCleanup and the base DSN for the main plugin
	dsn, _, _, _, _, _, _, autoCleanup, err := parseConnectionParams(uri)
	if err != nil {
		return fmt.Errorf("failed to parse URI for cache: %w", err)
	}

	// Ensure the underlying DB connection is initialized *using the base DSN*.
	if p.dbPluginPointer.db == nil {
		// Use the base DSN (without pool params) to initialize the main plugin
		err := p.dbPluginPointer.InitConnection(dsn)
		if err != nil {
			return fmt.Errorf("failed to initialize underlying db connection for cache: %w", err)
		}
	}

	// Check again after potential initialization.
	if p.dbPluginPointer.db == nil {
		return errors.New("database connection not available for cache plugin")
	}

	// Create cache table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS easyrest_cache ( ` +
		`key TEXT PRIMARY KEY, ` +
		`value TEXT, ` +
		`expires_at TIMESTAMPTZ` +
		` );`
	// Use the established db pool to execute the command
	_, err = p.dbPluginPointer.db.Exec(bgCtx, createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create cache table: %w", err)
	}

	// Launch background goroutine for cleanup if requested
	if autoCleanup == "true" || autoCleanup == "1" {
		go p.cleanupExpiredCacheEntries()
	}

	return nil
}

// deleteExpiredEntries performs a single cleanup run.
func (p *pgCachePlugin) deleteExpiredEntries(ctx context.Context) error {
	if p.dbPluginPointer.db == nil {
		// Don't return error, just log, as the cleanup goroutine should continue.
		fmt.Fprintf(os.Stderr, "Error cleaning cache: DB connection is nil\n")
		return nil
	}
	// Use NOW() which corresponds to TIMESTAMPTZ
	_, err := p.dbPluginPointer.db.Exec(ctx, "DELETE FROM easyrest_cache WHERE expires_at <= NOW()")
	if err != nil {
		// Log the error, but don't necessarily stop the goroutine.
		fmt.Fprintf(os.Stderr, "Error cleaning up expired cache entries: %v\n", err)
		return err // Return error so tests can check it if needed
	}
	return nil
}

// cleanupExpiredCacheEntries periodically deletes expired cache entries.
func (p *pgCachePlugin) cleanupExpiredCacheEntries() {
	// Check more frequently initially, then back off
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Call the synchronous cleanup function.
		// Use background context for the periodic task itself.
		_ = p.deleteExpiredEntries(bgCtx)
		// We ignore the error here because the loop should continue regardless.
	}
}

// Set stores a key-value pair with a TTL in the cache.
func (p *pgCachePlugin) Set(key string, value string, ttl time.Duration) error {
	if p.dbPluginPointer.db == nil {
		return errors.New("database connection not available for cache set")
	}
	// Calculate expiration time using TIMESTAMPTZ
	expiresAt := time.Now().Add(ttl)
	query := `
	INSERT INTO easyrest_cache (key, value, expires_at)
	VALUES ($1, $2, $3)
	ON CONFLICT (key) DO UPDATE SET
		value = EXCLUDED.value,
		expires_at = EXCLUDED.expires_at;`

	// Use background context for simple cache operation.
	_, err := p.dbPluginPointer.db.Exec(bgCtx, query, key, value, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set cache entry: %w", err)
	}
	return nil
}

// Get retrieves a value from the cache if it exists and hasn't expired.
func (p *pgCachePlugin) Get(key string) (string, error) {
	if p.dbPluginPointer.db == nil {
		return "", errors.New("database connection not available for cache get")
	}
	var value string
	query := "SELECT value FROM easyrest_cache WHERE key = $1 AND expires_at > NOW()"

	// Use background context for simple cache operation.
	err := p.dbPluginPointer.db.QueryRow(bgCtx, query, key).Scan(&value)
	if err != nil {
		// Return standard sql.ErrNoRows if not found or expired, otherwise the specific error
		if errors.Is(err, sql.ErrNoRows) {
			return "", sql.ErrNoRows // Standard way to signal cache miss
		}
		return "", fmt.Errorf("failed to get cache entry: %w", err)
	}
	return value, nil
}

func NewPgPlugin() *pgPlugin {
	return &pgPlugin{}
}

func NewPgCachePlugin() *pgCachePlugin {
	return &pgCachePlugin{dbPluginPointer: NewPgPlugin()}
}
