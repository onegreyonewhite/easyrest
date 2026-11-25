// mysql_plugin.go
package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"github.com/onegreyonewhite/easyrest/plugins/data/sqlcache"
)

// rowScanner is the interface needed by scanRows to fetch results.
type rowScanner interface {
	Columns() ([]string, error)
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// openDB is a package variable so we can override in tests (to return a sqlmock DB).
var openDB = sql.Open

// RoutineParam holds one parameter definition.
type RoutineParam struct {
	Name     string
	DataType string
	Mode     string
	Ordinal  int
}

// RoutineInfo holds parameter definitions for a routine.
type RoutineInfo struct {
	Name       string
	Params     []RoutineParam
	ReturnType string
}

// mysqlPlugin implements easyrest.DBPlugin for MySQL.
type mysqlPlugin struct {
	db             *sql.DB
	routines       map[string]RoutineInfo
	defaultTimeout time.Duration
	sessionMu      sync.Mutex
	sessions       *easyrest.SharedTx[*mysqlShared]
}

type mysqlShared struct {
	conn     *sql.Conn
	tx       *sql.Tx
	cancel   context.CancelFunc
	prepared bool
}

var _ easyrest.DBTransactor = (*mysqlPlugin)(nil)

// injectContext sets request/erctx session variables from ctx.
// SkipDBSessionKey omits response.*, cache.*, hook names, and keys that start with "_".
func (m *mysqlPlugin) injectContext(conn *sql.Conn, ctx map[string]any) error {
	if ctx == nil {
		return nil
	}
	flatCtx, err := easyrest.FormatToContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to format context: %w", err)
	}
	if len(flatCtx) == 0 {
		return nil
	}

	// Sort the flattened keys to guarantee a stable, deterministic order.
	var sortedKeys []string
	sortedKeys = make([]string, 0, len(flatCtx))
	for k := range flatCtx {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	var builder strings.Builder
	builder.WriteString("SET ")
	var args []any
	args = make([]any, 0, len(flatCtx)*2+1) // +1 for possible timezone

	first := true
	for _, k := range sortedKeys {
		if !first {
			builder.WriteString(", ")
		}
		builder.WriteString("@erctx_")
		builder.WriteString(k)
		builder.WriteString(" = ?, @request_")
		builder.WriteString(k)
		builder.WriteString(" = ?")
		val := flatCtx[k]
		args = append(args, val, val)
		first = false
	}

	if tzRaw, ok := ctx["timezone"]; ok {
		if tzStr, ok2 := tzRaw.(string); ok2 && tzStr != "" {
			if !first {
				builder.WriteString(", ")
			}
			builder.WriteString("time_zone = ?")
			args = append(args, tzStr)
		}
	}

	_, err = conn.ExecContext(context.Background(), builder.String(), args...)
	if err != nil {
		return fmt.Errorf("failed to set session variables: %w", err)
	}
	return nil
}

const harvestUserVarsSQL = `SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.user_variables_by_thread WHERE THREAD_ID = ( SELECT THREAD_ID FROM performance_schema.threads WHERE PROCESSLIST_ID = CONNECTION_ID() ) AND (VARIABLE_NAME LIKE 'response.%' OR VARIABLE_NAME = 'cache.invalidate')`

const harvestFallbackSQL = "SELECT @`response.headers` AS h, @`response.status` AS s, @`cache.invalidate` AS c"

const clearKnownResponseVarsSQL = "SET @`response.headers` = NULL, @`response.status` = NULL, @`cache.invalidate` = NULL"

type sessionQueryExec interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func harvestResponseSettings(q sessionQueryExec) (map[string]string, error) {
	settings, err := harvestFromPerformanceSchema(q)
	if err != nil {
		settings, err = harvestFallbackKnownKeys(q)
		if err != nil {
			return nil, fmt.Errorf("failed to harvest response settings: %w", err)
		}
	}
	return settings, nil
}

func harvestFromPerformanceSchema(q sessionQueryExec) (map[string]string, error) {
	rows, err := q.QueryContext(context.Background(), harvestUserVarsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var name string
		var value sql.NullString
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		if name == "" || !value.Valid || value.String == "" {
			continue
		}
		out[name] = value.String
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func harvestFallbackKnownKeys(q sessionQueryExec) (map[string]string, error) {
	var headers, status, invalidate sql.NullString
	if err := q.QueryRowContext(context.Background(), harvestFallbackSQL).Scan(&headers, &status, &invalidate); err != nil {
		return nil, err
	}
	out := make(map[string]string)
	if headers.Valid && headers.String != "" {
		out["response.headers"] = headers.String
	}
	if status.Valid && status.String != "" {
		out["response.status"] = status.String
	}
	if invalidate.Valid && invalidate.String != "" {
		out[easyrest.CtxCacheInvalidate] = invalidate.String
	}
	return out, nil
}

func namesToClear(settings map[string]string) []string {
	seen := map[string]struct{}{
		"response.headers":          {},
		"response.status":           {},
		easyrest.CtxCacheInvalidate: {},
	}
	out := []string{"response.headers", "response.status", easyrest.CtxCacheInvalidate}
	extra := make([]string, 0)
	for k := range settings {
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		extra = append(extra, k)
	}
	sort.Strings(extra)
	return append(out, extra...)
}

func clearResponseSettingsSQL(names []string) string {
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("SET ")
	for i, n := range names {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("@`")
		b.WriteString(n)
		b.WriteString("` = NULL")
	}
	return b.String()
}

func clearResponseSettings(q sessionQueryExec, settings map[string]string) error {
	sqlText := clearResponseSettingsSQL(namesToClear(settings))
	if sqlText == "" {
		return nil
	}
	if _, err := q.ExecContext(context.Background(), sqlText); err != nil {
		return fmt.Errorf("failed to clear response settings: %w", err)
	}
	return nil
}

func mergeHarvestedContext(q sessionQueryExec, pluginCtx map[string]any) (map[string]any, map[string]string, error) {
	settings, err := harvestResponseSettings(q)
	if err != nil {
		return nil, nil, err
	}
	return easyrest.MergeResponseSettings(pluginCtx, settings), settings, nil
}

func runContextRoutine(q sessionQueryExec, pluginCtx map[string]any, key string) error {
	name := easyrest.ContextRoutineName(pluginCtx, key)
	if name == "" {
		return nil
	}
	rows, err := q.QueryContext(context.Background(), "CALL "+name+"()")
	if err != nil {
		var me *mysqldriver.MySQLError
		if errors.As(err, &me) && me.Number == 1305 {
			return nil
		}
		return fmt.Errorf("failed to run %s %s: %w", key, name, err)
	}
	defer rows.Close()
	for rows.Next() {
	}
	for rows.NextResultSet() {
		for rows.Next() {
		}
	}
	if err := rows.Err(); err != nil {
		var me *mysqldriver.MySQLError
		if errors.As(err, &me) && me.Number == 1305 {
			return nil
		}
		return fmt.Errorf("failed to run %s %s: %w", key, name, err)
	}
	return nil
}

// scanRows converts row data into []map[string]any.
// Pre-allocates memory for results with a capacity of 100 for better performance.
func looksLikeJSON(b []byte) bool {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	if i >= len(b) {
		return false
	}
	c := b[i]
	return c == '{' || c == '[' || c == '"' || c == 't' || c == 'f' || c == 'n' || c == '-' || (c >= '0' && c <= '9')
}

func scanRows(r rowScanner) ([]map[string]any, error) {
	return scanRowsText(r, nil)
}

// scanRowsText is scanRows, but columns in textCols stay strings.
// ->> extracts must not be decoded just because the text looks like JSON.
func scanRowsText(r rowScanner, textCols map[string]struct{}) ([]map[string]any, error) {
	cols, err := r.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}
	numCols := len(cols)
	results := make([]map[string]any, 0, 100) // Pre-allocate memory for results
	columns := make([]any, numCols)
	pointers := make([]any, numCols)
	for i := range columns {
		pointers[i] = &columns[i]
	}

	for r.Next() {
		if err := r.Scan(pointers...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		rowMap := make(map[string]any, numCols)
		for i, colName := range cols {
			val := columns[i]
			if t, ok := val.(time.Time); ok {
				rowMap[colName] = easyrest.FormatSQLTime(t)
			} else if b, ok := val.([]byte); ok {
				if _, keepText := textCols[colName]; keepText {
					rowMap[colName] = string(b)
					continue
				}
				if looksLikeJSON(b) {
					var jsonData any
					err := json.Unmarshal(b, &jsonData)
					if err == nil {
						rowMap[colName] = jsonData
						continue
					}
				}
				rowMap[colName] = string(b)
			} else {
				rowMap[colName] = val
			}
		}
		results = append(results, rowMap)
	}
	if err := r.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}
	return results, nil
}

// InitConnection opens the MySQL connection, sets utf8mb4, loads routines.
// Supports the following URI parameters:
// - maxOpenConns: Maximum number of open connections (default: 100)
// - maxIdleConns: Maximum number of idle connections (default: 20)
// - connMaxLifetime: Connection reuse time in minutes (default: 5)
// - connMaxIdleTime: Connection idle time in minutes (default: 10)
// - timeout: Query timeout in seconds (default: 30)
// - parseTime: Parse MySQL TIME/TIMESTAMP/DATETIME as time.Time
func (m *mysqlPlugin) InitConnection(uri string) error {
	if !strings.HasPrefix(uri, "mysql://") {
		return errors.New("invalid MySQL URI")
	}

	parsedURI, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("failed to parse URI: %w", err)
	}

	queryParams := parsedURI.Query()
	maxOpenConns := 100
	maxIdleConns := 20
	connMaxLifetime := 5
	connMaxIdleTime := 10
	timeout := 30 // Timeout in seconds

	queryParams.Del("autoCleanup")

	// Remove connection parameters from query before creating DSN
	if val := queryParams.Get("maxOpenConns"); val != "" {
		if n, err := fmt.Sscanf(val, "%d", &maxOpenConns); err != nil || n != 1 {
			return fmt.Errorf("invalid maxOpenConns value: %s", val)
		}
		queryParams.Del("maxOpenConns")
	}

	if val := queryParams.Get("maxIdleConns"); val != "" {
		if n, err := fmt.Sscanf(val, "%d", &maxIdleConns); err != nil || n != 1 {
			return fmt.Errorf("invalid maxIdleConns value: %s", val)
		}
		queryParams.Del("maxIdleConns")
	}

	if val := queryParams.Get("connMaxLifetime"); val != "" {
		if n, err := fmt.Sscanf(val, "%d", &connMaxLifetime); err != nil || n != 1 {
			return fmt.Errorf("invalid connMaxLifetime value: %s", val)
		}
		queryParams.Del("connMaxLifetime")
	}

	if val := queryParams.Get("connMaxIdleTime"); val != "" {
		if n, err := fmt.Sscanf(val, "%d", &connMaxIdleTime); err != nil || n != 1 {
			return fmt.Errorf("invalid connMaxIdleTime value: %s", val)
		}
		queryParams.Del("connMaxIdleTime")
	}

	if val := queryParams.Get("timeout"); val != "" {
		if n, err := fmt.Sscanf(val, "%d", &timeout); err != nil || n != 1 {
			return fmt.Errorf("invalid timeout value: %s", val)
		}
		queryParams.Del("timeout")
	}

	var dsn strings.Builder

	if parsedURI.User != nil {
		dsn.WriteString(parsedURI.User.Username())
		if password, ok := parsedURI.User.Password(); ok {
			dsn.WriteByte(':')
			dsn.WriteString(password)
		}
		dsn.WriteByte('@')
	}

	host := parsedURI.Hostname()
	port := parsedURI.Port()
	if strings.Contains(host, "(") && strings.Contains(host, ")") {
		dsn.WriteString(host)
	} else {
		dsn.WriteString("tcp(")
		dsn.WriteString(host)
		if port != "" {
			dsn.WriteByte(':')
			dsn.WriteString(port)
		}
		dsn.WriteByte(')')
	}

	if len(parsedURI.Path) > 1 {
		dsn.WriteByte('/')
		dsn.WriteString(strings.TrimPrefix(parsedURI.Path, "/"))
	}

	if len(queryParams) > 0 {
		dsn.WriteByte('?')
		dsn.WriteString(queryParams.Encode())
	}

	db, err := openDB("mysql", dsn.String())
	if err != nil {
		return fmt.Errorf("failed to open MySQL: %w", err)
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(time.Duration(connMaxLifetime) * time.Minute)
	db.SetConnMaxIdleTime(time.Duration(connMaxIdleTime) * time.Minute)
	m.defaultTimeout = time.Duration(timeout) * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), m.defaultTimeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping MySQL: %w", err)
	}

	_, err = db.ExecContext(ctx, "SET NAMES utf8mb4 COLLATE utf8mb4_general_ci")
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to set charset: %w", err)
	}

	if m.db != nil && m.db != db {
		m.db.Close()
	}
	m.db = db
	if err := m.loadRoutines(); err != nil {
		m.db.Close()
		m.db = nil
		return fmt.Errorf("failed to load routines: %w", err)
	}

	return nil
}

var _ easyrest.RawQuerier = (*mysqlPlugin)(nil)

// RawQuery runs one SQL statement on the writable connection.
func (m *mysqlPlugin) RawQuery(ctx context.Context, query string) ([]map[string]any, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("query is empty")
	}
	if m.db == nil {
		return nil, errors.New("database connection not available")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	queryCtx, cancel := context.WithTimeout(ctx, m.defaultTimeout)
	if m.defaultTimeout == 0 {
		queryCtx, cancel = context.WithTimeout(ctx, 30*time.Second)
	}
	defer cancel()
	rows, err := m.db.QueryContext(queryCtx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// Close shuts down the MySQL connection pool.
func (m *mysqlPlugin) Close() {
	m.sessionMu.Lock()
	sessions := m.sessions
	m.sessions = nil
	m.sessionMu.Unlock()
	if sessions != nil {
		sessions.Close()
	}
	if m.db != nil {
		m.db.Close()
		m.db = nil
	}
}

// loadRoutines populates m.routines from information_schema.parameters.
func (m *mysqlPlugin) loadRoutines() error {
	m.routines = make(map[string]RoutineInfo)
	query := `
SELECT SPECIFIC_NAME, PARAMETER_NAME, DATA_TYPE, PARAMETER_MODE, ORDINAL_POSITION
FROM information_schema.parameters
WHERE SPECIFIC_SCHEMA = DATABASE()
ORDER BY SPECIFIC_NAME, ORDINAL_POSITION;`
	rows, err := m.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query routines: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var specificName, paramName, dataType, paramMode sql.NullString
		var ordinal sql.NullInt64
		if err := rows.Scan(&specificName, &paramName, &dataType, &paramMode, &ordinal); err != nil {
			return fmt.Errorf("failed to scan routine row: %w", err)
		}
		rName := specificName.String
		rInfo, ok := m.routines[rName]
		if !ok {
			rInfo = RoutineInfo{Name: rName, Params: []RoutineParam{}}
		}
		op := 0
		if ordinal.Valid {
			op = int(ordinal.Int64)
		}
		if op == 0 {
			// function return
			rInfo.ReturnType = dataType.String
		} else {
			mode := paramMode.String
			if mode == "" {
				mode = "IN"
			}
			if mode == "IN" || mode == "INOUT" {
				rInfo.Params = append(rInfo.Params, RoutineParam{
					Name:     paramName.String,
					DataType: dataType.String,
					Mode:     mode,
					Ordinal:  op,
				})
			}
		}
		m.routines[rName] = rInfo
	}
	return nil
}

// GetSchema enumerates tables + views and routines, building a swagger-ish schema.
func (m *mysqlPlugin) GetSchema(ctx map[string]any) (any, map[string]any, error) {
	tables, err := m.getTablesSchema()
	if err != nil {
		return nil, nil, err
	}
	rpc, err := m.getRPCSchema()
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{
		"tables": tables,
		"rpc":    rpc,
	}, nil, nil
}

// getTablesSchema enumerates both tables and views from INFORMATION_SCHEMA.TABLES.
func (m *mysqlPlugin) getTablesSchema() (map[string]any, error) {
	result := make(map[string]any)
	rows, err := m.db.Query(`
SELECT TABLE_NAME, TABLE_TYPE
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = DATABASE()
`)
	if err != nil {
		return nil, fmt.Errorf("failed to list tables/views: %w", err)
	}
	defer rows.Close()

	type tblInfo struct {
		Name string
		Type string // "BASE TABLE" or "VIEW"
	}
	var entries []tblInfo
	for rows.Next() {
		var tname, ttype string
		if err := rows.Scan(&tname, &ttype); err != nil {
			return nil, err
		}
		entries = append(entries, tblInfo{Name: tname, Type: ttype})
	}
	for _, e := range entries {
		sch, err := m.buildTableSchema(e.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to build schema for %s %s: %w", e.Type, e.Name, err)
		}
		result[e.Name] = sch
	}
	return result, nil
}

// buildTableSchema queries COLUMNS for the given table/view name.
func (m *mysqlPlugin) buildTableSchema(tableName string) (map[string]any, error) {
	query := `
SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_KEY
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
`
	rows, err := m.db.Query(query, tableName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	properties := make(map[string]any)
	var required []string
	for rows.Next() {
		var colName, dt, nullable, defv, ckey sql.NullString
		if err := rows.Scan(&colName, &dt, &nullable, &defv, &ckey); err != nil {
			return nil, err
		}
		colType := mapMySQLType(dt.String)
		prop := map[string]any{
			"type": colType,
		}
		isPri := (strings.ToUpper(ckey.String) == "PRI")
		if strings.ToUpper(nullable.String) == "YES" {
			prop["x-nullable"] = true
		}
		if isPri {
			// readOnly => not required
			prop["readOnly"] = true
		} else if strings.ToUpper(nullable.String) == "NO" && !defv.Valid {
			required = append(required, colName.String)
		}

		properties[colName.String] = prop
	}
	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema, nil
}

// mapMySQLType => returns swagger-ish type for the data type.
func mapMySQLType(dt string) string {
	up := strings.ToUpper(dt)
	if strings.Contains(up, "INT") {
		return "integer"
	}
	if strings.Contains(up, "CHAR") || strings.Contains(up, "TEXT") {
		return "string"
	}
	if strings.Contains(up, "BLOB") {
		return "string"
	}
	if strings.Contains(up, "FLOAT") || strings.Contains(up, "DOUBLE") || strings.Contains(up, "DEC") || strings.Contains(up, "REAL") {
		return "number"
	}
	return "string"
}

// getRPCSchema uses m.routines to build routineName => [inSchema, outSchema].
func (m *mysqlPlugin) getRPCSchema() (map[string]any, error) {
	rmap := make(map[string]any)
	for name, info := range m.routines {
		inProps := make(map[string]any)
		var inReq []string
		for _, param := range info.Params {
			propType := mapMySQLType(param.DataType)
			prop := map[string]any{
				"type": propType,
			}
			inProps[param.Name] = prop
			inReq = append(inReq, param.Name)
		}
		inSchema := map[string]any{
			"type":       "object",
			"properties": inProps,
		}
		if len(inReq) > 0 {
			inSchema["required"] = inReq
		}
		outSchema := map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		}
		if info.ReturnType != "" {
			t := mapMySQLType(info.ReturnType)
			outSchema["properties"] = map[string]any{
				"result": map[string]any{
					"type": t,
				},
			}
		}
		rmap[name] = []any{inSchema, outSchema}
	}
	return rmap, nil
}

// CallFunction executes a stored procedure/function with final parameters.
func (m *mysqlPlugin) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, map[string]any, error) {
	rInfo, ok := m.routines[funcName]
	if !ok {
		return nil, nil, fmt.Errorf("routine %s not found", funcName)
	}
	sort.Slice(rInfo.Params, func(i, j int) bool {
		return rInfo.Params[i].Ordinal < rInfo.Params[j].Ordinal
	})
	var placeholders []string
	var callArgs []any
	for _, param := range rInfo.Params {
		placeholders = append(placeholders, "?")
		val, found := data[param.Name]
		if !found {
			return nil, nil, fmt.Errorf("missing required argument: %s", param.Name)
		}
		callArgs = append(callArgs, val)
	}
	// check for extra args
	for k := range data {
		found := false
		for _, rp := range rInfo.Params {
			if strings.EqualFold(rp.Name, k) {
				found = true
				break
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("unexpected argument: %s", k)
		}
	}
	var callSB strings.Builder
	if rInfo.ReturnType != "" {
		callSB.WriteString("SELECT ")
		callSB.WriteString(funcName)
		callSB.WriteByte('(')
		callSB.WriteString(strings.Join(placeholders, ", "))
		callSB.WriteString(") AS result")
	} else {
		callSB.WriteString("CALL ")
		callSB.WriteString(funcName)
		callSB.WriteByte('(')
		callSB.WriteString(strings.Join(placeholders, ", "))
		callSB.WriteByte(')')
	}
	callQuery := callSB.String()

	// Use handleTransaction for managing the transaction and context
	res, outCtx, err := m.handleTransaction(ctx, func(tx *sql.Tx) (any, error) {
		rows, err := tx.QueryContext(context.Background(), callQuery, callArgs...)
		if err != nil {
			// Error during query execution, transaction will be rolled back by handleTransaction
			return nil, fmt.Errorf("failed to call routine: %w", err)
		}
		defer rows.Close()
		result, err := scanRows(rows)
		if err != nil {
			// Error during scanning, transaction will be rolled back by handleTransaction
			return nil, fmt.Errorf("failed to scan routine result: %w", err)
		}
		// Return the scanned result. Commit/Rollback is handled by handleTransaction.
		return result, nil
	})

	if err != nil {
		return nil, nil, err // Error already includes context from handleTransaction or the operation
	}

	// Return the result obtained from handleTransaction
	return res, outCtx, nil
}

// handleTransaction manages the transaction lifecycle including context injection and conditional commit/rollback.
func (m *mysqlPlugin) handleTransaction(ctxMap map[string]any, operation func(tx *sql.Tx) (any, error)) (any, map[string]any, error) {
	if id, ok := easyrest.SharedTxID(ctxMap); ok {
		var result any
		err := m.txSessions().Use(id, func(h *mysqlShared) error {
			if err := m.injectContext(h.conn, ctxMap); err != nil {
				return fmt.Errorf("failed to inject context: %w", err)
			}
			if !h.prepared {
				if err := runContextRoutine(h.tx, ctxMap, easyrest.CtxDBPreRequest); err != nil {
					return err
				}
				h.prepared = true
			}
			var opErr error
			result, opErr = operation(h.tx)
			return opErr
		})
		return result, nil, err
	}
	conn, err := m.db.Conn(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback()

	// Default transaction preference is commit
	txPreference := "commit"

	if ctxMap != nil {
		txPreference, err = easyrest.GetTxPreference(ctxMap)
		if err != nil {
			return nil, nil, err
		}

		// Inject context *after* validating preference, but before the main operation
		if err := m.injectContext(conn, ctxMap); err != nil {
			tx.Rollback() // Rollback on injection error
			return nil, nil, fmt.Errorf("failed to inject context: %w", err)
		}
	}

	if err := runContextRoutine(tx, ctxMap, easyrest.CtxDBPreRequest); err != nil {
		tx.Rollback()
		return nil, nil, err
	}

	// Execute the core operation
	result, err := operation(tx)
	if err != nil {
		tx.Rollback()        // Rollback on operation error
		return nil, nil, err // Return the original error from the operation
	}

	if err := runContextRoutine(tx, ctxMap, easyrest.CtxDBPostRequest); err != nil {
		tx.Rollback()
		return nil, nil, err
	}

	outCtx, settings, err := mergeHarvestedContext(tx, ctxMap)
	if err != nil {
		tx.Rollback()
		return nil, nil, err
	}

	// Commit or Rollback based on preference
	if txPreference == "rollback" {
		if err := tx.Rollback(); err != nil {
			// Even rollback can fail, though it's less critical than a failed commit
			return nil, nil, fmt.Errorf("failed to rollback transaction: %w", err)
		}
		if err := clearResponseSettings(conn, settings); err != nil {
			return nil, nil, err
		}
		// Modify result for Update/Delete if rollback occurred
		// For Update/Delete, the operation returns int(affectedRows). If rolled back, return 0.
		// For Create, the operation returns []map[string]any (input data). Return it as is.
		switch res := result.(type) {
		case int: // Assumed from TableUpdate/TableDelete
			return 0, outCtx, nil
		case int64: // Handle potential int64 return from RowsAffected directly
			return int64(0), outCtx, nil
		default: // Assumed from TableCreate or others; return original result
			return res, outCtx, nil
		}
	} else { // commit or default
		if err := tx.Commit(); err != nil {
			// Attempt rollback if commit fails, but return the commit error
			rbErr := tx.Rollback()
			if rbErr != nil {
				return nil, nil, fmt.Errorf("failed to commit transaction: %w (rollback also failed: %v)", err, rbErr)
			}
			return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
		}
	}

	if err := clearResponseSettings(conn, settings); err != nil {
		return nil, nil, err
	}

	// Return the original result from the operation if committed successfully
	return result, outCtx, nil
}

// convertILIKEtoLower transforms ILIKE operations in a WHERE clause map
// to use LOWER() on both the column and the value with a LIKE operator.
// Other operators for the same field remain unchanged.
func convertILIKEtoLower(where map[string]any) map[string]any {
	if where == nil {
		return nil
	}
	hasILIKE := false
	for _, condition := range where {
		conditionMap, ok := condition.(map[string]any)
		if !ok {
			continue
		}
		for op := range conditionMap {
			if strings.EqualFold(op, "ILIKE") {
				hasILIKE = true
				break
			}
		}
		if hasILIKE {
			break
		}
	}
	if !hasILIKE {
		return where
	}
	result := make(map[string]any, len(where))
	for field, condition := range where {
		switch conditionMap := condition.(type) {
		case map[string]any:
			// This field has operator(s) defined in a map
			newConditions := make(map[string]any) // For operators other than ILIKE
			foundILIKE := false

			for op, operand := range conditionMap {
				if strings.EqualFold(op, "ILIKE") {
					operandStr, ok := operand.(string)
					if ok {
						// Handle ILIKE: Create LOWER(field) LIKE lower(value)
						lowerOperand := strings.ToLower(operandStr)
						lowerFieldKey := fmt.Sprintf("LOWER(%s)", field)
						result[lowerFieldKey] = map[string]any{"LIKE": lowerOperand}
						foundILIKE = true
					} else {
						// ILIKE operand is not a string, keep original op
						newConditions[op] = operand
					}
				} else {
					// Keep other operators associated with the original field name
					newConditions[op] = operand
				}
			}

			// If there were non-ILIKE operators, add them to the result under the original field name
			if len(newConditions) > 0 {
				result[field] = newConditions
			} else if !foundILIKE {
				// If the map only contained non-string ILIKE, add the original back
				// This case is unlikely but handles potential edge scenarios.
				result[field] = conditionMap
			}

		default:
			// This is a direct equality check (e.g., "field": "value") or other non-map condition.
			// Keep it as is.
			result[field] = condition
		}
	}
	return result
}

func resolveMySQLCount(ctx context.Context, tx *sql.Tx, mode string, pluginCtx map[string]any, inner string, args []any) (int64, bool, error) {
	var planned int64
	hasPlanned := false
	if mode == "planned" || mode == "estimated" {
		var raw string
		if err := tx.QueryRowContext(ctx, "EXPLAIN FORMAT=JSON "+inner, args...).Scan(&raw); err != nil {
			return 0, false, fmt.Errorf("failed to explain query: %w", err)
		}
		n, err := mysqlExaminedRows([]byte(raw))
		if err != nil {
			return 0, false, err
		}
		planned = n
		hasPlanned = true
	}
	return easyrest.CountFromEstimate(mode, planned, hasPlanned, easyrest.CountMaxRows(pluginCtx), func() (int64, error) {
		var n int64
		if err := tx.QueryRowContext(ctx, easyrest.CountSQL(inner), args...).Scan(&n); err != nil {
			return 0, fmt.Errorf("failed to count rows: %w", err)
		}
		return n, nil
	})
}

func mysqlExaminedRows(raw []byte) (int64, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("failed to parse explain: %w", err)
	}
	block, ok := doc["query_block"].(map[string]any)
	if !ok {
		return 0, fmt.Errorf("failed to parse explain: missing query_block")
	}
	n, ok := lastRowsExamined(block)
	if !ok {
		return 0, fmt.Errorf("failed to parse explain: missing rows_examined_per_scan")
	}
	return easyrest.RoundCount(n), nil
}

func lastRowsExamined(node map[string]any) (float64, bool) {
	var found float64
	ok := false
	if table, isMap := node["table"].(map[string]any); isMap {
		if n, yes := jsonFloat(table["rows_examined_per_scan"]); yes {
			found, ok = n, true
		}
	}
	if nested, isSlice := node["nested_loop"].([]any); isSlice {
		for _, item := range nested {
			child, isMap := item.(map[string]any)
			if !isMap {
				continue
			}
			if n, yes := lastRowsExamined(child); yes {
				found, ok = n, true
			}
		}
	}
	return found, ok
}

func jsonFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

// TableGet builds and executes a SELECT query.
func (m *mysqlPlugin) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {

	originalFields := selectFields
	selectFields, err := easyrest.RewriteJSONSelectFields(selectFields, easyrest.DialectMySQL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build SELECT: %w", err)
	}
	groupBy, err = easyrest.RewriteJSONSelectFields(groupBy, easyrest.DialectMySQL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build SELECT: %w", err)
	}
	selectOpts := easyrest.SelectOptions{WhereRewriter: convertILIKEtoLower, Dialect: easyrest.DialectMySQL}
	textCols := easyrest.JSONTextColumns(originalFields)
	query, args, err := easyrest.BuildSelectQuery(table, selectFields, where, ordering, groupBy, limit, offset, selectOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build WHERE: %w", err)
	}
	mode := easyrest.CountPreference(ctx)
	var inner string
	var countArgs []any
	if mode != "" {
		built, cargs, cerr := easyrest.BuildSelectQuery(table, selectFields, where, nil, groupBy, 0, 0, selectOpts)
		if cerr != nil {
			return nil, nil, fmt.Errorf("failed to build count: %w", cerr)
		}
		inner = built
		countArgs = cargs
	}

	queryCtx := context.Background()

	conn, err := m.db.Conn(queryCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()
	if ctx != nil {
		if err := m.injectContext(conn, ctx); err != nil {
			return nil, nil, err
		}
	}
	tx, err := conn.BeginTx(queryCtx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := runContextRoutine(tx, ctx, easyrest.CtxDBPreRequest); err != nil {
		return nil, nil, err
	}

	var total int64
	counted := false
	if mode != "" {
		got, ok, rerr := resolveMySQLCount(queryCtx, tx, mode, ctx, inner, countArgs)
		if rerr != nil {
			return nil, nil, rerr
		}
		if ok {
			total = got
			counted = true
		}
	}

	rows, err := tx.QueryContext(queryCtx, query, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()
	result, err := scanRowsText(rows, textCols)
	if err != nil {
		return nil, nil, err
	}
	easyrest.NormalizeJSONArrowRows(result, originalFields)
	if err := runContextRoutine(tx, ctx, easyrest.CtxDBPostRequest); err != nil {
		return nil, nil, err
	}
	outCtx, settings, err := mergeHarvestedContext(tx, ctx)
	if err != nil {
		return nil, nil, err
	}
	if counted {
		if outCtx == nil {
			outCtx = ctx
		}
		outCtx = easyrest.WithTotal(outCtx, total)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	if err := clearResponseSettings(conn, settings); err != nil {
		return nil, nil, err
	}
	return result, outCtx, nil
}

// TableCreate builds and executes an INSERT statement from data.
func (m *mysqlPlugin) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	for _, row := range data {
		for k := range row {
			if err := easyrest.ValidateColumnName(k); err != nil {
				return nil, nil, err
			}
		}
	}
	res, outCtx, err := m.handleTransaction(ctx, func(tx *sql.Tx) (any, error) {
		var results []map[string]any
		queryCtx := context.Background()
		for _, row := range data {
			var cols []string
			var placeholders []string
			var args []any
			var keys []string
			for k := range row {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				cols = append(cols, k)
				placeholders = append(placeholders, "?")
				args = append(args, row[k])
			}
			var insertSB strings.Builder
			insertSB.WriteString("INSERT INTO ")
			insertSB.WriteString(table)
			insertSB.WriteString(" (")
			insertSB.WriteString(strings.Join(cols, ", "))
			insertSB.WriteString(") VALUES (")
			insertSB.WriteString(strings.Join(placeholders, ", "))
			insertSB.WriteByte(')')
			if _, err := tx.ExecContext(queryCtx, insertSB.String(), args...); err != nil {
				// Error occurs within the loop, transaction will be rolled back by handleTransaction
				return nil, fmt.Errorf("failed to execute insert: %w", err)
			}
			// Append the original input row to results. This is returned even on rollback.
			results = append(results, row)
		}
		// Return the collected input data.
		return results, nil
	})

	if err != nil {
		return nil, nil, err // Error already includes context from handleTransaction or the operation
	}

	// Type assertion for the result
	if results, ok := res.([]map[string]any); ok {
		return results, outCtx, nil
	}
	// This should ideally not happen if handleTransaction works correctly.
	return nil, nil, fmt.Errorf("unexpected result type from handleTransaction: %T", res)
}

// TableUpdate builds and executes an UPDATE statement.
func (m *mysqlPlugin) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	for k := range data {
		if err := easyrest.ValidateColumnName(k); err != nil {
			return 0, nil, err
		}
	}
	res, outCtx, err := m.handleTransaction(ctx, func(tx *sql.Tx) (any, error) {
		var keys []string
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var setParts []string
		var args []any
		for _, k := range keys {
			setParts = append(setParts, k+" = ?")
			args = append(args, data[k])
		}
		var updateSB strings.Builder
		updateSB.WriteString("UPDATE ")
		updateSB.WriteString(table)
		updateSB.WriteString(" SET ")
		updateSB.WriteString(strings.Join(setParts, ", "))
		updateQ := updateSB.String()
		processedWhere := convertILIKEtoLower(where)
		whereClause, whereArgs, err := easyrest.BuildWhereClauseSortedFor(processedWhere, easyrest.DialectMySQL)
		if err != nil {
			// Error in building WHERE clause, transaction will be rolled back
			return 0, fmt.Errorf("failed to build WHERE: %w", err)
		}
		updateQ += whereClause
		args = append(args, whereArgs...)
		sqlRes, err := tx.ExecContext(context.Background(), updateQ, args...)
		if err != nil {
			// Error during execution, transaction will be rolled back
			return 0, fmt.Errorf("failed to execute update: %w", err)
		}
		affected, err := sqlRes.RowsAffected()
		if err != nil {
			// Error getting affected rows, transaction will be rolled back
			return 0, fmt.Errorf("failed to get rowsAffected: %w", err)
		}
		// Return the number of affected rows (as int64 for safety, handleTransaction will convert if needed).
		return int(affected), nil // Return as int directly
	})

	if err != nil {
		return 0, nil, err // Error already includes context from handleTransaction or the operation
	}

	// Type assertion for the result
	if affected, ok := res.(int); ok {
		return affected, outCtx, nil
	}
	// This should ideally not happen if handleTransaction works correctly.
	return 0, nil, fmt.Errorf("unexpected result type from handleTransaction: %T", res)
}

// TableDelete builds and executes a DELETE statement.
func (m *mysqlPlugin) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	res, outCtx, err := m.handleTransaction(ctx, func(tx *sql.Tx) (any, error) {
		processedWhere := convertILIKEtoLower(where)
		whereClause, whereArgs, err := easyrest.BuildWhereClauseSortedFor(processedWhere, easyrest.DialectMySQL)
		if err != nil {
			// Error in building WHERE clause, transaction will be rolled back
			return 0, fmt.Errorf("failed to build WHERE: %w", err)
		}
		delQ := "DELETE FROM " + table + whereClause
		sqlRes, err := tx.ExecContext(context.Background(), delQ, whereArgs...)
		if err != nil {
			// Error during execution, transaction will be rolled back
			return 0, fmt.Errorf("failed to execute delete: %w", err)
		}
		affected, err := sqlRes.RowsAffected()
		if err != nil {
			// Error getting affected rows, transaction will be rolled back
			return 0, fmt.Errorf("failed to retrieve rowsAffected: %w", err)
		}
		// Return the number of affected rows (as int64 for safety, handleTransaction will convert if needed).
		return int(affected), nil // Return as int directly
	})

	if err != nil {
		return 0, nil, err // Error already includes context from handleTransaction or the operation
	}

	// Type assertion for the result
	if affected, ok := res.(int); ok {
		return affected, outCtx, nil
	}
	// This should ideally not happen if handleTransaction works correctly.
	return 0, nil, fmt.Errorf("unexpected result type from handleTransaction: %T", res)
}

var mysqlCacheDialect = sqlcache.Dialect{
	CreateTable:   "CREATE TABLE IF NOT EXISTS easyrest_cache (`key` VARCHAR(255) PRIMARY KEY, value TEXT, expires_at DATETIME) ENGINE = MEMORY",
	DeleteExpired: "DELETE FROM easyrest_cache WHERE expires_at <= NOW()",
	Upsert:        "INSERT INTO easyrest_cache (`key`, value, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value), expires_at = VALUES(expires_at)",
	SelectLive:    "SELECT value FROM easyrest_cache WHERE `key` = ? AND expires_at > NOW()",
	DeleteKey:     "DELETE FROM easyrest_cache WHERE `key` = ?",
}

// mysqlCachePlugin stores ETag version tokens in MySQL.
type mysqlCachePlugin struct {
	dbPluginPointer *mysqlPlugin
	store           sqlcache.Store
}

// InitConnection ensures the cache table exists and starts the cleanup goroutine.
// It relies on the underlying mysqlPlugin's InitConnection being called first or concurrently
// by the plugin framework to establish the database connection.
func (p *mysqlCachePlugin) InitConnection(uri string) error {
	// Parse the URI to extract query parameters
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("failed to parse URI: %w", err)
	}

	// Get the autoCleanup query parameter
	autoCleanup := parsedURL.Query().Get("autoCleanup")

	// Remove the autoCleanup parameter from the URI
	query := parsedURL.Query()
	query.Del("autoCleanup")
	parsedURL.RawQuery = query.Encode()
	uri = parsedURL.String()

	// Ensure the underlying DB connection is initialized.
	if p.dbPluginPointer.db == nil {
		// Attempt to initialize the main plugin connection if not already done.
		err := p.dbPluginPointer.InitConnection(uri)
		if err != nil {
			return fmt.Errorf("failed to initialize underlying db connection for cache: %w", err)
		}
	}

	// Check again after potential initialization.
	if p.dbPluginPointer.db == nil {
		return errors.New("database connection not available for cache plugin")
	}

	p.bindStore()
	if err := p.store.EnsureTable(context.Background()); err != nil {
		return fmt.Errorf("failed to create cache table: %w", err)
	}
	if autoCleanup == "1" || autoCleanup == "true" {
		p.store.StartCleanup()
	}
	return nil
}

func (p *mysqlCachePlugin) bindStore() {
	p.store.Dialect = mysqlCacheDialect
	p.store.Exec = sqlcache.SQLDB{DB: p.dbPluginPointer.db}
}

func (p *mysqlCachePlugin) Close() {
	p.store.Stop()
	if p.dbPluginPointer != nil {
		p.dbPluginPointer.Close()
	}
}

func (p *mysqlCachePlugin) Set(key string, value string, ttl time.Duration) error {
	if p.dbPluginPointer.db == nil {
		return errors.New("database connection not available for cache set")
	}
	p.bindStore()
	if err := p.store.Set(context.Background(), key, value, ttl); err != nil {
		return fmt.Errorf("failed to set cache entry: %w", err)
	}
	return nil
}

func (p *mysqlCachePlugin) Get(key string) (string, error) {
	if p.dbPluginPointer.db == nil {
		return "", errors.New("database connection not available for cache get")
	}
	p.bindStore()
	value, err := p.store.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		return "", fmt.Errorf("failed to get cache entry: %w", err)
	}
	return value, nil
}

func (p *mysqlCachePlugin) Delete(key string) error {
	if p.dbPluginPointer.db == nil {
		return errors.New("database connection not available for cache delete")
	}
	p.bindStore()
	if err := p.store.Delete(context.Background(), key); err != nil {
		return fmt.Errorf("failed to delete cache entry: %w", err)
	}
	return nil
}

func (m *mysqlPlugin) txSessions() *easyrest.SharedTx[*mysqlShared] {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	if m.sessions == nil {
		m.sessions = easyrest.NewSharedTx[*mysqlShared](16, time.Second)
	}
	return m.sessions
}

func (m *mysqlPlugin) openSessions() *easyrest.SharedTx[*mysqlShared] {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	return m.sessions
}

func (h *mysqlShared) finish(commit bool) error {
	var err error
	if commit {
		err = h.tx.Commit()
	} else {
		err = h.tx.Rollback()
		if errors.Is(err, sql.ErrTxDone) {
			err = nil
		}
	}
	if h.cancel != nil {
		h.cancel()
	}
	if h.conn != nil {
		if cerr := h.conn.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// BeginTx starts a transaction that later calls join via ctx _tx.
func (m *mysqlPlugin) BeginTx(ctx map[string]any) (string, map[string]any, error) {
	if m.db == nil {
		return "", nil, errors.New("mysql connection is not open")
	}
	deadline := easyrest.SharedTxDeadline(ctx, time.Now())
	conn, err := m.db.Conn(context.Background())
	if err != nil {
		return "", nil, fmt.Errorf("failed to get connection: %w", err)
	}
	txCtx, cancel := context.WithDeadline(context.Background(), deadline)
	tx, err := conn.BeginTx(txCtx, nil)
	if err != nil {
		cancel()
		conn.Close()
		return "", nil, fmt.Errorf("failed to begin tx: %w", err)
	}
	handle := &mysqlShared{conn: conn, tx: tx, cancel: cancel}
	id, err := m.txSessions().Put(handle, deadline, func(h *mysqlShared) {
		_ = h.finish(false)
	})
	if err != nil {
		_ = handle.finish(false)
		return "", nil, err
	}
	return id, nil, nil
}

// CommitTx runs the post-request hook, harvests session settings, and commits.
func (m *mysqlPlugin) CommitTx(id string, ctx map[string]any) (map[string]any, error) {
	sessions := m.openSessions()
	if sessions == nil {
		return nil, easyrest.ErrSharedTxNotFound
	}
	var out map[string]any
	err := sessions.Commit(id, func(h *mysqlShared) error {
		if err := runContextRoutine(h.tx, ctx, easyrest.CtxDBPostRequest); err != nil {
			return err
		}
		harvested, settings, err := mergeHarvestedContext(h.tx, ctx)
		if err != nil {
			return err
		}
		out = harvested
		if err := h.tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
		if err := clearResponseSettings(h.conn, settings); err != nil {
			return err
		}
		h.cancel()
		return h.conn.Close()
	})
	return out, err
}

// RollbackTx rolls back the shared transaction. An unknown id returns nil.
func (m *mysqlPlugin) RollbackTx(id string) error {
	sessions := m.openSessions()
	if sessions == nil {
		return nil
	}
	return sessions.Rollback(id, func(h *mysqlShared) error {
		return h.finish(false)
	})
}

func NewMysqlPlugin() *mysqlPlugin {
	return &mysqlPlugin{}
}

func NewMysqlCachePlugin() *mysqlCachePlugin {
	return &mysqlCachePlugin{dbPluginPointer: NewMysqlPlugin()}
}

// mysqlQueryPlugin implements the DBQueryPlugin interface for read-only SQL queries.
type mysqlQueryPlugin struct {
	dbPluginPointer *mysqlPlugin
}

func (m *mysqlQueryPlugin) InitConnection(uri string) error {
	return m.dbPluginPointer.InitConnection(uri)
}

// Close releases the underlying database pool.
func (m *mysqlQueryPlugin) Close() {
	if m.dbPluginPointer != nil {
		m.dbPluginPointer.Close()
	}
}

func (m *mysqlQueryPlugin) QueryCall(query string, ctx map[string]any) ([]map[string]any, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("query is empty")
	}

	queryCtx := context.Background()

	conn, err := m.dbPluginPointer.db.Conn(queryCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	if ctx != nil {
		if err := m.dbPluginPointer.injectContext(conn, ctx); err != nil {
			return nil, err
		}
	}

	if _, err := conn.ExecContext(queryCtx, "START TRANSACTION READ ONLY"); err != nil {
		return nil, fmt.Errorf("failed to start read-only transaction: %w", err)
	}

	rows, err := conn.QueryContext(queryCtx, query)
	if err != nil {
		_, _ = conn.ExecContext(queryCtx, "ROLLBACK")
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	results, err := scanRows(rows)
	if err != nil {
		_, _ = conn.ExecContext(queryCtx, "ROLLBACK")
		return nil, err
	}

	if _, err := conn.ExecContext(queryCtx, "COMMIT"); err != nil {
		return nil, fmt.Errorf("failed to commit read-only transaction: %w", err)
	}

	return results, nil
}

func NewMysqlQueryPlugin() *mysqlQueryPlugin {
	return &mysqlQueryPlugin{dbPluginPointer: NewMysqlPlugin()}
}
