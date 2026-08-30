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
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"github.com/onegreyonewhite/easyrest/plugins/data/sqlcache"
)

var bgCtx = context.Background()

const maxTimezoneCacheSize = 64

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
	defaultTimeout time.Duration                      // Default timeout for operations
	bulkThreshold  int                                // Threshold for bulk operations
	timezoneCache  *lru.Cache[string, *time.Location] // Cache for loaded timezones
	searchPath     string                             // Schema search path
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
func parseConnectionParams(uri string) (dsn string, maxConns int32, minConns int32, maxLifetime, maxIdleTime time.Duration, timeout time.Duration, bulkThreshold int, autoCleanup string, searchPath string, requireAuth string, err error) {
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

	// Get search_path (string)
	searchPath = queryParams.Get("search_path")
	if searchPath == "" {
		searchPath = "public" // Default to public schema
	}

	requireAuth = queryParams.Get("require_auth")
	queryParams.Del("require_auth")

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
	dsn, maxConns, minConns, maxLifetime, maxIdleTime, timeout, bulkThreshold, _, searchPath, requireAuth, err := parseConnectionParams(uri)
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
	if requireAuth != "" {
		cfg.ConnConfig.RequireAuth = requireAuth
	}

	// Create the pool using the configured settings
	db, err := pgxpool.NewWithConfig(bgCtx, cfg)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Assign plugin settings
	p.defaultTimeout = timeout
	p.bulkThreshold = bulkThreshold
	p.searchPath = searchPath

	// Ping the database to verify connection
	pingCtx, cancel := context.WithTimeout(bgCtx, 5*time.Second) // Use a short ping timeout
	defer cancel()
	if err := db.Ping(pingCtx); err != nil {
		db.Close() // Ensure pool is closed on ping failure
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Assign the pool to the plugin
	if p.db != nil {
		p.Close()
	}
	p.db = db
	if p.timezoneCache != nil {
		p.timezoneCache.Purge()
	}
	var tzErr error
	p.timezoneCache, tzErr = lru.New[string, *time.Location](maxTimezoneCacheSize)
	if tzErr != nil {
		db.Close()
		return fmt.Errorf("failed to create timezone cache: %w", tzErr)
	}

	return nil
}

// Close shuts down the database pool and clears cached timezones.
func (p *pgPlugin) Close() {
	if p.db != nil {
		if pool, ok := p.db.(*pgxpool.Pool); ok {
			pool.Close()
		}
		p.db = nil
	}
	if p.timezoneCache != nil {
		p.timezoneCache.Purge()
		p.timezoneCache = nil
	}
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
		if easyrest.IsContextRoutineKey(key) {
			continue
		}
		var requestVal, erctxVal string
		switch v := val.(type) {
		case string:
			requestVal = v
			erctxVal = v
		case int:
			requestVal = strconv.Itoa(v)
			erctxVal = requestVal
		case int64:
			requestVal = strconv.FormatInt(v, 10)
			erctxVal = requestVal
		case float64:
			requestVal = strconv.FormatFloat(v, 'f', -1, 64)
			erctxVal = requestVal
		case bool:
			requestVal = strconv.FormatBool(v)
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

// harvestResponseSettingsSQL lists transaction-local response.* GUCs (PostgREST
// response.headers / response.status plus any other response.* name) and cache.invalidate.
const harvestResponseSettingsSQL = `SELECT s.name, nullif(current_setting(s.name, true), '') FROM ( SELECT name FROM pg_catalog.pg_settings WHERE name LIKE 'response.%' UNION SELECT unnest(ARRAY['response.headers'::text, 'response.status'::text, 'cache.invalidate'::text]) ) AS s WHERE nullif(current_setting(s.name, true), '') IS NOT NULL ORDER BY 1`

func harvestResponseSettings(ctx context.Context, tx pgx.Tx) (map[string]string, error) {
	rows, err := tx.Query(ctx, harvestResponseSettingsSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to harvest response settings: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, fmt.Errorf("failed to scan response setting: %w", err)
		}
		if name == "" || value == "" {
			continue
		}
		out[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate response settings: %w", err)
	}
	return out, nil
}

func mergeHarvestedContext(ctx context.Context, tx pgx.Tx, pluginCtx map[string]any) (map[string]any, error) {
	settings, err := harvestResponseSettings(ctx, tx)
	if err != nil {
		return nil, err
	}
	return easyrest.MergeResponseSettings(pluginCtx, settings), nil
}

func runContextRoutine(ctx context.Context, tx pgx.Tx, pluginCtx map[string]any, key string) error {
	name := easyrest.ContextRoutineName(pluginCtx, key)
	if name == "" {
		return nil
	}
	rows, err := tx.Query(ctx, "SELECT "+name+"()")
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42883" {
			return nil
		}
		return fmt.Errorf("failed to run %s %s: %w", key, name, err)
	}
	defer rows.Close()
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42883" {
			return nil
		}
		return fmt.Errorf("failed to run %s %s: %w", key, name, err)
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
				rowMap[string(col.Name)] = easyrest.FormatSQLTime(v.In(loc))
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

// resolveLocation returns the timezone from plugin context, defaulting to UTC.
func (p *pgPlugin) resolveLocation(ctx map[string]any) *time.Location {
	loc := time.UTC
	if ctx == nil {
		return loc
	}
	if tz, ok := ctx["timezone"].(string); ok && tz != "" {
		if p.timezoneCache != nil {
			if cachedLoc, found := p.timezoneCache.Get(tz); found {
				return cachedLoc
			}
		}
		if l, loadErr := time.LoadLocation(tz); loadErr == nil {
			if p.timezoneCache != nil {
				p.timezoneCache.Add(tz, l)
			}
			return l
		} else {
			log.Printf("Warning: Could not load timezone '%s', using UTC: %v", tz, loadErr)
		}
	}
	return loc
}

func (p *pgPlugin) withTx(ctx context.Context, pluginCtx map[string]any, preference string, fn func(tx pgx.Tx, loc *time.Location) error) (map[string]any, error) {
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	loc := time.UTC
	if pluginCtx != nil {
		if err := ApplyPluginContext(ctx, tx, pluginCtx); err != nil {
			return nil, err
		}
		loc = p.resolveLocation(pluginCtx)
	}
	if err := runContextRoutine(ctx, tx, pluginCtx, easyrest.CtxDBPreRequest); err != nil {
		return nil, err
	}
	if err := fn(tx, loc); err != nil {
		return nil, err
	}
	if err := runContextRoutine(ctx, tx, pluginCtx, easyrest.CtxDBPostRequest); err != nil {
		return nil, err
	}
	outCtx, err := mergeHarvestedContext(ctx, tx, pluginCtx)
	if err != nil {
		return nil, err
	}
	if preference == "rollback" {
		if err := tx.Rollback(ctx); err != nil {
			return nil, fmt.Errorf("failed to rollback transaction: %w", err)
		}
	} else if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return outCtx, nil
}

// TableGet executes a SELECT query with optional WHERE, GROUP BY, ORDER BY, LIMIT and OFFSET.
func (p *pgPlugin) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {

	queryCtx, cancel := p.newContextWithTimeout()
	defer cancel()

	query, args, err := easyrest.BuildSelectQuery(table, selectFields, where, ordering, groupBy, limit, offset, easyrest.SelectOptions{})
	if err != nil {
		return nil, nil, err
	}
	finalQuery := convertPlaceholders(query)

	var results []map[string]any
	outCtx, err := p.withTx(queryCtx, ctx, "commit", func(tx pgx.Tx, loc *time.Location) error {
		rows, qerr := tx.Query(queryCtx, finalQuery, args...)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		results, qerr = p.processRows(rows, loc)
		return qerr
	})
	if err != nil {
		return nil, nil, err
	}
	return results, outCtx, nil
}

// TableCreate performs an INSERT operation on the specified table
func (p *pgPlugin) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	if len(data) == 0 {
		return []map[string]any{}, nil, nil
	}
	for _, row := range data {
		for k := range row {
			if err := easyrest.ValidateColumnName(k); err != nil {
				return nil, nil, err
			}
		}
	}

	// Get transaction preference
	txPreference, err := easyrest.GetTxPreference(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Use COPY for large datasets
	if len(data) >= p.bulkThreshold {
		// Note: bulkCreate currently does not support the rollback preference.
		// It creates a temp table, copies, inserts, and commits within its own transaction.
		if txPreference == "rollback" {
			return nil, nil, fmt.Errorf("rollback preference is not currently supported for bulk create operations (rows >= %d)", p.bulkThreshold)
		}
		result, outCtx, err := p.bulkCreate(table, data, ctx) // bulkCreate handles its own commit
		return result, outCtx, err
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

	outCtx, err := p.withTx(bgCtx, ctx, txPreference, func(tx pgx.Tx, _ *time.Location) error {
		_, execErr := tx.Exec(bgCtx, finalQuery, args...)
		return execErr
	})
	if err != nil {
		return nil, nil, err
	}
	return data, outCtx, nil
}

// bulkCreate uses COPY for efficient insertion of large amounts of data
func (p *pgPlugin) bulkCreate(table string, data []map[string]any, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	keys := make([]string, 0, len(data[0]))
	for k := range data[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)

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

	outCtx, err := p.withTx(bgCtx, ctx, "commit", func(tx pgx.Tx, _ *time.Location) error {
		_, copyErr := tx.CopyFrom(bgCtx, pgx.Identifier{table}, columns, pgx.CopyFromRows(records))
		return copyErr
	})
	if err != nil {
		return nil, nil, err
	}
	return data, outCtx, nil
}

// TableUpdate executes an UPDATE query on the specified table.
func (p *pgPlugin) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	for k := range data {
		if err := easyrest.ValidateColumnName(k); err != nil {
			return 0, nil, err
		}
	}

	// Get transaction preference
	txPreference, err := easyrest.GetTxPreference(ctx)
	if err != nil {
		return 0, nil, err
	}

	setParts := make([]string, 0, len(data))
	args := make([]any, 0, len(data)) // Initial capacity for SET args

	// Sort keys for deterministic query generation
	dataKeys := make([]string, 0, len(data))
	for k := range data {
		dataKeys = append(dataKeys, k)
	}
	sort.Strings(dataKeys)

	for _, k := range dataKeys {
		setParts = append(setParts, k+" = ?")
		args = append(args, data[k])
	}

	whereClause, whereArgs, err := easyrest.BuildWhereClauseSorted(where)
	if err != nil {
		// tx.Rollback() is handled by defer
		return 0, nil, err
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

	var affected int64
	outCtx, err := p.withTx(bgCtx, ctx, txPreference, func(tx pgx.Tx, _ *time.Location) error {
		res, execErr := tx.Exec(bgCtx, finalQuery, args...)
		if execErr != nil {
			return execErr
		}
		affected = res.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return int(affected), outCtx, nil
}

// TableDelete executes a DELETE query on the specified table.
func (p *pgPlugin) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	// Get transaction preference
	txPreference, err := easyrest.GetTxPreference(ctx)
	if err != nil {
		return 0, nil, err
	}

	whereClause, args, err := easyrest.BuildWhereClauseSorted(where)
	if err != nil {
		return 0, nil, err
	}

	var queryBuilder strings.Builder
	queryBuilder.Grow(20 + len(table) + len(whereClause))
	queryBuilder.WriteString("DELETE FROM ")
	queryBuilder.WriteString(table)
	queryBuilder.WriteString(whereClause)
	finalQuery := convertPlaceholders(queryBuilder.String())

	var affected int64
	outCtx, err := p.withTx(bgCtx, ctx, txPreference, func(tx pgx.Tx, _ *time.Location) error {
		res, execErr := tx.Exec(bgCtx, finalQuery, args...)
		if execErr != nil {
			return execErr
		}
		affected = res.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return int(affected), outCtx, nil
}

// CallFunction executes a function call using SELECT syntax.
// Parameters are passed in sorted order by key.
// It handles scalar, SETOF, JSON, and void return types.
func (p *pgPlugin) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, map[string]any, error) {
	queryCtx, cancel := p.newContextWithTimeout()
	defer cancel()

	// Get transaction preference
	txPreference, err := easyrest.GetTxPreference(ctx)
	if err != nil {
		return nil, nil, err
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

	var results []map[string]any
	outCtx, err := p.withTx(queryCtx, ctx, txPreference, func(tx pgx.Tx, loc *time.Location) error {
		rows, qerr := tx.Query(queryCtx, finalQuery, args...)
		if qerr != nil {
			return fmt.Errorf("failed to execute function query: %w", qerr)
		}
		defer rows.Close()
		results, qerr = p.processRows(rows, loc)
		if qerr != nil {
			return fmt.Errorf("failed to process function results: %w", qerr)
		}
		if qerr = rows.Err(); qerr != nil {
			return fmt.Errorf("error during rows iteration: %w", qerr)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Analyze the results
	if len(results) == 0 {
		// Function returned void or an empty set
		return nil, outCtx, nil
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
					return parsedResult, outCtx, nil
				}
				log.Printf("Result from function %s is []byte but not valid JSON, returning raw bytes", funcName)
				return v, outCtx, nil // Return raw bytes if not JSON
			case string:
				// Attempt to unmarshal if it looks like JSON
				var parsedResult any
				if json.Unmarshal([]byte(v), &parsedResult) == nil {
					log.Printf("Successfully unmarshaled string result from function %s", funcName)
					return parsedResult, outCtx, nil
				}
				log.Printf("Result from function %s is string but not valid JSON, returning raw string", funcName)
				return v, outCtx, nil // Return raw string if not JSON
			default:
				// Return other scalar types directly
				log.Printf("Returning scalar result of type %T from function %s", v, funcName)
				return v, outCtx, nil
			}
		}
		// Single row, multiple columns: Return as is (map within a slice)
		log.Printf("Returning single composite row result from function %s", funcName)
		return results, outCtx, nil
	}

	// Multiple rows: Return the slice of maps directly (SETOF result)
	log.Printf("Returning SETOF result (%d rows) from function %s", len(results), funcName)
	return results, outCtx, nil
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
	searchPath := p.searchPath
	if searchPath == "" {
		searchPath = "public" // Default fallback
	}

	result := make(map[string]any)
	tableQuery := "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'"
	rows, err := tx.Query(bgCtx, tableQuery, searchPath)
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
		colQuery := "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2"
		colRows, err := tx.Query(bgCtx, colQuery, searchPath, tn)
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
	searchPath := p.searchPath
	if searchPath == "" {
		searchPath = "public" // Default fallback
	}

	result := make(map[string]any)
	query := "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'VIEW'"
	rows, err := tx.Query(bgCtx, query, searchPath)
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
		colQuery := "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2"
		colRows, err := tx.Query(bgCtx, colQuery, searchPath, vn)
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
	searchPath := p.searchPath
	if searchPath == "" {
		searchPath = "public" // Default fallback
	}

	result := make(map[string]any)
	// Exclude functions belonging to extensions by checking pg_depend
	rpcQuery := `
	SELECT r.routine_name, r.specific_name, r.data_type
	FROM information_schema.routines r
	JOIN pg_catalog.pg_proc p ON r.routine_name = p.proname
	JOIN pg_catalog.pg_namespace n ON p.pronamespace = n.oid
	LEFT JOIN pg_catalog.pg_depend dep ON dep.objid = p.oid AND dep.classid = 'pg_catalog.pg_proc'::regclass AND dep.deptype = 'e'
	WHERE r.specific_schema = $1
	  AND n.nspname = $2 -- Ensure the schema matches in both catalogs
	  AND r.routine_type = 'FUNCTION'
	  AND dep.objid IS NULL -- Only include functions NOT dependent on an extension
	`
	rows, err := tx.Query(bgCtx, rpcQuery, searchPath, searchPath)
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
		paramQuery := "SELECT parameter_name, data_type, parameter_mode, ordinal_position FROM information_schema.parameters WHERE specific_schema = $1 AND specific_name = $2 ORDER BY ordinal_position"
		paramRows, err := tx.Query(bgCtx, paramQuery, searchPath, r.specificName)
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
func (p *pgPlugin) GetSchema(ctx map[string]any) (any, map[string]any, error) {
	tx, err := p.db.Begin(bgCtx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(bgCtx)

	if ctx != nil {
		if err := ApplyPluginContext(bgCtx, tx, ctx); err != nil {
			tx.Rollback(bgCtx)
			return nil, nil, err
		}
	}
	tables, err := p.getTablesSchema(tx)
	if err != nil {
		tx.Rollback(bgCtx)
		return nil, nil, err
	}
	views, err := p.getViewsSchema(tx)
	if err != nil {
		tx.Rollback(bgCtx)
		return nil, nil, err
	}
	rpc, err := p.getRPCSchema(tx)
	if err != nil {
		tx.Rollback(bgCtx)
		return nil, nil, err
	}
	outCtx, err := mergeHarvestedContext(bgCtx, tx, ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(bgCtx); err != nil {
		return nil, nil, err
	}
	return map[string]any{
		"tables": tables,
		"views":  views,
		"rpc":    rpc,
	}, outCtx, nil
}

var pgCacheDialect = sqlcache.Dialect{
	CreateTable:   `CREATE TABLE IF NOT EXISTS easyrest_cache ( key TEXT PRIMARY KEY, value TEXT, expires_at TIMESTAMPTZ );`,
	DeleteExpired: `DELETE FROM easyrest_cache WHERE expires_at <= NOW()`,
	Upsert: `
	INSERT INTO easyrest_cache (key, value, expires_at)
	VALUES ($1, $2, $3)
	ON CONFLICT (key) DO UPDATE SET
		value = EXCLUDED.value,
		expires_at = EXCLUDED.expires_at;`,
	SelectLive: `SELECT value FROM easyrest_cache WHERE key = $1 AND expires_at > NOW()`,
}

// pgCachePlugin stores ETag version tokens in PostgreSQL.
type pgCachePlugin struct {
	dbPluginPointer *pgPlugin
	store           sqlcache.Store
}

// InitConnection ensures the cache table exists and starts the cleanup goroutine.
// It relies on the underlying pgPlugin's InitConnection being called first or concurrently
// by the plugin framework to establish the database connection.
func (p *pgCachePlugin) InitConnection(uri string) error {
	// Parse params to get autoCleanup and the base DSN for the main plugin
	dsn, _, _, _, _, _, _, autoCleanup, _, _, err := parseConnectionParams(uri)
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

	p.bindStore()
	if err := p.store.EnsureTable(bgCtx); err != nil {
		return fmt.Errorf("failed to create cache table: %w", err)
	}
	if autoCleanup == "true" || autoCleanup == "1" {
		p.store.StartCleanup()
	}
	return nil
}

func (p *pgCachePlugin) bindStore() {
	p.store.Dialect = pgCacheDialect
	p.store.Exec = sqlcache.FuncExec{
		ExecFn: func(ctx context.Context, query string, args ...any) error {
			if p.dbPluginPointer == nil || p.dbPluginPointer.db == nil {
				fmt.Fprintf(os.Stderr, "Error cleaning cache: DB connection is nil\n")
				return nil
			}
			_, err := p.dbPluginPointer.db.Exec(ctx, query, args...)
			return err
		},
		QueryFn: func(ctx context.Context, query string, args ...any) (string, error) {
			if p.dbPluginPointer == nil || p.dbPluginPointer.db == nil {
				return "", errors.New("database connection not available for cache get")
			}
			var value string
			err := p.dbPluginPointer.db.QueryRow(ctx, query, args...).Scan(&value)
			return value, err
		},
	}
}

func (p *pgCachePlugin) deleteExpiredEntries(ctx context.Context) error {
	p.bindStore()
	err := p.store.DeleteExpired(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error cleaning up expired cache entries: %v\n", err)
	}
	return err
}

func (p *pgCachePlugin) Close() {
	p.store.Stop()
	if p.dbPluginPointer != nil {
		p.dbPluginPointer.Close()
	}
}

func (p *pgCachePlugin) Set(key string, value string, ttl time.Duration) error {
	if p.dbPluginPointer.db == nil {
		return errors.New("database connection not available for cache set")
	}
	p.bindStore()
	if err := p.store.Set(bgCtx, key, value, ttl); err != nil {
		return fmt.Errorf("failed to set cache entry: %w", err)
	}
	return nil
}

func (p *pgCachePlugin) Get(key string) (string, error) {
	if p.dbPluginPointer.db == nil {
		return "", errors.New("database connection not available for cache get")
	}
	p.bindStore()
	value, err := p.store.Get(bgCtx, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", sql.ErrNoRows
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

// pgQueryPlugin implements the DBQueryPlugin interface for read-only SQL queries.
type pgQueryPlugin struct {
	dbPluginPointer *pgPlugin
}

func (p *pgQueryPlugin) InitConnection(uri string) error {
	return p.dbPluginPointer.InitConnection(uri)
}

// Close releases the underlying database pool.
func (p *pgQueryPlugin) Close() {
	if p.dbPluginPointer != nil {
		p.dbPluginPointer.Close()
	}
}

func (p *pgQueryPlugin) QueryCall(query string, ctx map[string]any) ([]map[string]any, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("query is empty")
	}

	queryCtx, cancel := p.dbPluginPointer.newContextWithTimeout()
	defer cancel()

	tx, err := p.dbPluginPointer.db.Begin(queryCtx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(queryCtx)

	if _, err := tx.Exec(queryCtx, "SET TRANSACTION READ ONLY"); err != nil {
		return nil, fmt.Errorf("failed to set read-only transaction: %w", err)
	}

	loc := time.UTC
	if len(ctx) > 0 {
		if err := ApplyPluginContext(queryCtx, tx, ctx); err != nil {
			return nil, err
		}
		loc = p.dbPluginPointer.resolveLocation(ctx)
	}

	rows, err := tx.Query(queryCtx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results, err := p.dbPluginPointer.processRows(rows, loc)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(queryCtx); err != nil {
		return nil, err
	}

	return results, nil
}

func NewPgQueryPlugin() *pgQueryPlugin {
	return &pgQueryPlugin{dbPluginPointer: NewPgPlugin()}
}
