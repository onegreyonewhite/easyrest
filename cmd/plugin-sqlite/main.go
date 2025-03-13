package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	hplugin "github.com/hashicorp/go-plugin"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// sqlitePlugin implements easyrest.DBPlugin for SQLite.
type sqlitePlugin struct {
	db *sql.DB
}

// InitConnection opens the SQLite database based on the provided URI.
func (s *sqlitePlugin) InitConnection(uri string) error {
	// Expected format: sqlite://<path>
	if !strings.HasPrefix(uri, "sqlite://") {
		return errors.New("Invalid sqlite URI")
	}
	dbPath := strings.TrimPrefix(uri, "sqlite://")
	var err error
	s.db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	return s.db.Ping()
}

// convertILIKEtoLike converts ILIKE operator to LIKE with COLLATE NOCASE
func convertILIKEtoLike(where map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for field, val := range where {
		switch v := val.(type) {
		case map[string]interface{}:
			for op, operand := range v {
				if op == "ILIKE" {
					result[field+" COLLATE NOCASE"] = map[string]interface{}{"LIKE": operand}
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

// TableGet constructs and executes a SELECT query.
func (s *sqlitePlugin) TableGet(userID, table string, selectFields []string, where map[string]interface{},
	ordering []string, groupBy []string, limit, offset int, ctx map[string]interface{}) ([]map[string]interface{}, error) {

	fields := "*"
	if len(selectFields) > 0 {
		fields = strings.Join(selectFields, ", ")
	}
	query := fmt.Sprintf("SELECT %s FROM %s", fields, table)

	// Convert ILIKE to LIKE COLLATE NOCASE before building where clause
	where = convertILIKEtoLike(where)
	whereClause, args, err := easyrest.BuildWhereClause(where)
	if err != nil {
		return nil, err
	}
	query += whereClause
	if len(groupBy) > 0 {
		query += " GROUP BY " + strings.Join(groupBy, ", ")
	}
	if len(ordering) > 0 {
		query += " ORDER BY " + strings.Join(ordering, ", ")
	}
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else if offset > 0 {
		query += fmt.Sprintf(" LIMIT -1 OFFSET %d", offset)
	}

	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	rows, err := s.db.QueryContext(ctxQuery, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	numCols := len(cols)
	columns := make([]interface{}, numCols)
	columnPointers := make([]interface{}, numCols)
	for i := range columns {
		columnPointers[i] = &columns[i]
	}
	var results []map[string]interface{}
	for rows.Next() {
		if err := rows.Scan(columnPointers...); err != nil {
			return nil, err
		}
		rowMap := make(map[string]interface{}, numCols)
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
func (s *sqlitePlugin) TableCreate(userID, table string, data []map[string]interface{}, ctx map[string]interface{}) ([]map[string]interface{}, error) {
	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return nil, err
	}
	var results []map[string]interface{}
	for _, row := range data {
		var cols []string
		var placeholders []string
		var args []interface{}
		for k, v := range row {
			cols = append(cols, k)
			placeholders = append(placeholders, "?")
			args = append(args, v)
		}
		baseQuery := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
		_, err := tx.ExecContext(ctxQuery, baseQuery, args...)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		results = append(results, row)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return results, nil
}

// TableUpdate builds and executes an UPDATE query.
func (s *sqlitePlugin) TableUpdate(userID, table string, data map[string]interface{}, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return 0, err
	}
	var setParts []string
	var args []interface{}
	for k, v := range data {
		setParts = append(setParts, fmt.Sprintf("%s = ?", k))
		args = append(args, v)
	}
	baseQuery := fmt.Sprintf("UPDATE %s SET %s", table, strings.Join(setParts, ", "))

	// Convert ILIKE to LIKE COLLATE NOCASE before building where clause
	where = convertILIKEtoLike(where)
	whereClause, whereArgs, err := easyrest.BuildWhereClause(where)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	baseQuery += whereClause
	args = append(args, whereArgs...)
	res, err := tx.ExecContext(ctxQuery, baseQuery, args...)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(affected), nil
}

// TableDelete builds and executes a DELETE query.
func (s *sqlitePlugin) TableDelete(userID, table string, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return 0, err
	}

	// Convert ILIKE to LIKE COLLATE NOCASE before building where clause
	where = convertILIKEtoLike(where)
	whereClause, whereArgs, err := easyrest.BuildWhereClause(where)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	baseQuery := fmt.Sprintf("DELETE FROM %s%s", table, whereClause)
	res, err := tx.ExecContext(ctxQuery, baseQuery, whereArgs...)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(affected), nil
}

// CallFunction returns an error since it is not supported.
func (s *sqlitePlugin) CallFunction(userID, funcName string, data map[string]interface{}, ctx map[string]interface{}) (interface{}, error) {
	return nil, http.ErrNotSupported
}

// GetSchema returns a schema object with three keys:
// "tables" is a map from table names to JSON schema (Swagger 2.0 compatible),
// "views" is a map from view names to JSON schema,
// "rpc" is nil since SQLite does not support stored procedures.
func (s *sqlitePlugin) GetSchema(ctx map[string]interface{}) (interface{}, error) {
	tables := make(map[string]interface{})
	views := make(map[string]interface{})
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
	result := map[string]interface{}{
		"tables": tables,
		"views":  views,
		"rpc":    nil,
	}
	return result, nil
}

// getJSONSchemaForTable builds a JSON schema for a given table by querying PRAGMA table_info.
func (s *sqlitePlugin) getJSONSchemaForTable(tableName string) (map[string]interface{}, error) {
	query := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	properties := make(map[string]interface{})
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
		prop := map[string]interface{}{
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
	schema := map[string]interface{}{
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
	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: easyrest.Handshake,
		Plugins: map[string]hplugin.Plugin{
			"db": &easyrest.DBPluginPlugin{Impl: impl},
		},
	})
}
