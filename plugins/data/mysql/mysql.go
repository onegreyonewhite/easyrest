// mysql_plugin.go
package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
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
}

// injectContext sets *all* keys from ctx under two prefixes: erctx_ and request_.
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

// scanRows converts row data into []map[string]any.
// Pre-allocates memory for results with a capacity of 100 for better performance.
func scanRows(r rowScanner) ([]map[string]any, error) {
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
				if t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0 {
					rowMap[colName] = t.Format("2006-01-02")
				} else {
					rowMap[colName] = t.Format("2006-01-02 15:04:05")
				}
			} else if b, ok := val.([]byte); ok {
				// Attempt to unmarshal as JSON
				var jsonData any
				err := json.Unmarshal(b, &jsonData)
				if err == nil {
					// If successful, use the unmarshaled data
					rowMap[colName] = jsonData
				} else {
					// If not JSON, treat as a regular string
					rowMap[colName] = string(b)
				}
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
		return fmt.Errorf("failed to ping MySQL: %w", err)
	}

	m.db = db
	_, err = m.db.ExecContext(ctx, "SET NAMES utf8mb4 COLLATE utf8mb4_general_ci")
	if err != nil {
		return fmt.Errorf("failed to set charset: %w", err)
	}

	if err := m.loadRoutines(); err != nil {
		return fmt.Errorf("failed to load routines: %w", err)
	}

	return nil
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
func (m *mysqlPlugin) GetSchema(ctx map[string]any) (any, error) {
	tables, err := m.getTablesSchema()
	if err != nil {
		return nil, err
	}
	rpc, err := m.getRPCSchema()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"tables": tables,
		"rpc":    rpc,
	}, nil
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
func (m *mysqlPlugin) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
	rInfo, ok := m.routines[funcName]
	if !ok {
		return nil, fmt.Errorf("routine %s not found", funcName)
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
			return nil, fmt.Errorf("missing required argument: %s", param.Name)
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
			return nil, fmt.Errorf("unexpected argument: %s", k)
		}
	}
	var callQuery string
	if rInfo.ReturnType != "" {
		callQuery = fmt.Sprintf("SELECT %s(%s) AS result", funcName, strings.Join(placeholders, ", "))
	} else {
		callQuery = fmt.Sprintf("CALL %s(%s)", funcName, strings.Join(placeholders, ", "))
	}

	// Use handleTransaction for managing the transaction and context
	res, err := m.handleTransaction(ctx, func(tx *sql.Tx) (any, error) {
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
		return nil, err // Error already includes context from handleTransaction or the operation
	}

	// Return the result obtained from handleTransaction
	return res, nil
}

// handleTransaction manages the transaction lifecycle including context injection and conditional commit/rollback.
func (m *mysqlPlugin) handleTransaction(ctxMap map[string]any, operation func(tx *sql.Tx) (any, error)) (any, error) {
	conn, err := m.db.Conn(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin tx: %w", err)
	}

	// Default transaction preference is commit
	txPreference := "commit"

	if ctxMap != nil {
		txPreference, err = easyrest.GetTxPreference(ctxMap)
		if err != nil {
			return nil, err
		}

		// Inject context *after* validating preference, but before the main operation
		if err := m.injectContext(conn, ctxMap); err != nil {
			tx.Rollback() // Rollback on injection error
			return nil, fmt.Errorf("failed to inject context: %w", err)
		}
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
			// Even rollback can fail, though it's less critical than a failed commit
			return nil, fmt.Errorf("failed to rollback transaction: %w", err)
		}
		// Modify result for Update/Delete if rollback occurred
		// For Update/Delete, the operation returns int(affectedRows). If rolled back, return 0.
		// For Create, the operation returns []map[string]any (input data). Return it as is.
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

// convertILIKEtoLower transforms ILIKE operations in a WHERE clause map
// to use LOWER() on both the column and the value with a LIKE operator.
// Other operators for the same field remain unchanged.
func convertILIKEtoLower(where map[string]any) map[string]any {
	if where == nil {
		return nil
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

// TableGet builds and executes a SELECT query.
func (m *mysqlPlugin) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error) {

	var query strings.Builder
	query.WriteString("SELECT ")
	if len(selectFields) > 0 {
		query.WriteString(strings.Join(selectFields, ", "))
	} else {
		query.WriteString("*")
	}
	query.WriteString(" FROM ")
	query.WriteString(table)

	processedWhere := convertILIKEtoLower(where)
	whereClause, args, err := easyrest.BuildWhereClauseSorted(processedWhere)
	if err != nil {
		return nil, fmt.Errorf("failed to build WHERE: %w", err)
	}
	query.WriteString(whereClause)
	if len(groupBy) > 0 {
		query.WriteString(" GROUP BY ")
		query.WriteString(strings.Join(groupBy, ", "))
	}
	if len(ordering) > 0 {
		query.WriteString(" ORDER BY ")
		query.WriteString(strings.Join(ordering, ", "))
	}
	if limit > 0 {
		query.WriteString(" LIMIT ")
		query.WriteString(strconv.Itoa(limit))
	}
	if offset > 0 {
		query.WriteString(" OFFSET ")
		query.WriteString(strconv.Itoa(offset))
	}

	queryCtx := context.Background()

	conn, err := m.db.Conn(queryCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()
	if ctx != nil {
		if err := m.injectContext(conn, ctx); err != nil {
			return nil, err
		}
	}
	rows, err := conn.QueryContext(queryCtx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// TableCreate builds and executes an INSERT statement from data.
func (m *mysqlPlugin) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
	res, err := m.handleTransaction(ctx, func(tx *sql.Tx) (any, error) {
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
			insertQ := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
			if _, err := tx.ExecContext(queryCtx, insertQ, args...); err != nil {
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
		return nil, err // Error already includes context from handleTransaction or the operation
	}

	// Type assertion for the result
	if results, ok := res.([]map[string]any); ok {
		return results, nil
	}
	// This should ideally not happen if handleTransaction works correctly.
	return nil, fmt.Errorf("unexpected result type from handleTransaction: %T", res)
}

// TableUpdate builds and executes an UPDATE statement.
func (m *mysqlPlugin) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error) {
	res, err := m.handleTransaction(ctx, func(tx *sql.Tx) (any, error) {
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
		whereClause, whereArgs, err := easyrest.BuildWhereClauseSorted(processedWhere)
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
		return 0, err // Error already includes context from handleTransaction or the operation
	}

	// Type assertion for the result
	if affected, ok := res.(int); ok {
		return affected, nil
	}
	// This should ideally not happen if handleTransaction works correctly.
	return 0, fmt.Errorf("unexpected result type from handleTransaction: %T", res)
}

// TableDelete builds and executes a DELETE statement.
func (m *mysqlPlugin) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, error) {
	res, err := m.handleTransaction(ctx, func(tx *sql.Tx) (any, error) {
		processedWhere := convertILIKEtoLower(where)
		whereClause, whereArgs, err := easyrest.BuildWhereClauseSorted(processedWhere)
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
		return 0, err // Error already includes context from handleTransaction or the operation
	}

	// Type assertion for the result
	if affected, ok := res.(int); ok {
		return affected, nil
	}
	// This should ideally not happen if handleTransaction works correctly.
	return 0, fmt.Errorf("unexpected result type from handleTransaction: %T", res)
}

// mysqlCachePlugin implements the CachePlugin interface using MySQL.
type mysqlCachePlugin struct {
	dbPluginPointer *mysqlPlugin
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

	// Create cache table if it doesn't exist
	// Use DATETIME for expires_at in MySQL
	createTableSQL := "CREATE TABLE IF NOT EXISTS easyrest_cache (`key` VARCHAR(255) PRIMARY KEY, value TEXT, expires_at DATETIME) ENGINE = MEMORY"

	// Use a background context as table creation is an initialization step.
	_, err = p.dbPluginPointer.db.ExecContext(context.Background(), createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create cache table: %w", err)
	}

	// Launch background goroutine for cleanup if autoCleanup is set
	if autoCleanup == "1" || autoCleanup == "true" {
		go p.cleanupExpiredCacheEntries()
	}

	return nil
}

// cleanupExpiredCacheEntries periodically deletes expired cache entries.
func (p *mysqlCachePlugin) cleanupExpiredCacheEntries() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	queryCtx := context.Background()

	for range ticker.C {
		if p.dbPluginPointer.db == nil {
			fmt.Printf("Error cleaning cache: DB connection is nil\n") // Use fmt.Printf for logging in plugins
			continue                                                   // Skip this cycle
		}
		// Use NOW() for current time in MySQL
		// Use background context for cleanup task.
		_, err := p.dbPluginPointer.db.ExecContext(queryCtx, "DELETE FROM easyrest_cache WHERE expires_at <= NOW()")
		if err != nil {
			// Log the error, but continue running the cleanup
			fmt.Printf("Error cleaning up expired cache entries: %v\n", err) // Use fmt.Printf
		}
	}
}

// Set stores a key-value pair with a TTL in the cache.
func (p *mysqlCachePlugin) Set(key string, value string, ttl time.Duration) error {
	if p.dbPluginPointer.db == nil {
		return errors.New("database connection not available for cache set")
	}
	// Calculate expiration time
	expiresAt := time.Now().Add(ttl)
	// MySQL uses INSERT ... ON DUPLICATE KEY UPDATE - Use interpreted string
	query := "INSERT INTO easyrest_cache (`key`, value, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value), expires_at = VALUES(expires_at)"

	// Use background context for simple cache operation.
	_, err := p.dbPluginPointer.db.ExecContext(context.Background(), query, key, value, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set cache entry: %w", err)
	}
	return nil
}

// Get retrieves a value from the cache if it exists and hasn't expired.
func (p *mysqlCachePlugin) Get(key string) (string, error) {
	if p.dbPluginPointer.db == nil {
		return "", errors.New("database connection not available for cache get")
	}
	var value string
	// MySQL uses NOW() for current time comparison - Use interpreted string
	query := "SELECT value FROM easyrest_cache WHERE `key` = ? AND expires_at > NOW()"

	// Use background context for simple cache operation.
	err := p.dbPluginPointer.db.QueryRowContext(context.Background(), query, key).Scan(&value)
	if err != nil {
		// Return standard sql.ErrNoRows if not found or expired, otherwise the specific error
		if errors.Is(err, sql.ErrNoRows) {
			return "", sql.ErrNoRows // Standard way to signal cache miss
		}
		return "", fmt.Errorf("failed to get cache entry: %w", err)
	}
	return value, nil
}

func NewMysqlPlugin() *mysqlPlugin {
	return &mysqlPlugin{}
}

func NewMysqlCachePlugin() *mysqlCachePlugin {
	return &mysqlCachePlugin{dbPluginPointer: NewMysqlPlugin()}
}
