package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
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

// substituteContextValues recursively substitutes any string value that starts with "erctx."
// with its corresponding value from flatCtx. It returns the substituted value.
func substituteContextValues(input interface{}, flatCtx map[string]string) interface{} {
	switch v := input.(type) {
	case string:
		if strings.HasPrefix(v, "erctx.") {
			key := strings.TrimPrefix(v, "erctx.")
			normalizedKey := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			if val, exists := flatCtx[normalizedKey]; exists {
				return val
			}
			return v
		}
		return v
	case map[string]interface{}:
		m := make(map[string]interface{})
		for key, value := range v {
			m[key] = substituteContextValues(value, flatCtx)
		}
		return m
	case []interface{}:
		s := make([]interface{}, len(v))
		for i, item := range v {
			s[i] = substituteContextValues(item, flatCtx)
		}
		return s
	default:
		return v
	}
}

// substituteContextInData applies substitution for each map in a slice.
func substituteContextInData(data []map[string]interface{}, flatCtx map[string]string) []map[string]interface{} {
	result := make([]map[string]interface{}, len(data))
	for i, row := range data {
		if substituted, ok := substituteContextValues(row, flatCtx).(map[string]interface{}); ok {
			result[i] = substituted
		} else {
			result[i] = row
		}
	}
	return result
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

// TableGet receives an extra context parameter. If provided, it substitutes any
// where clause operand that begins with "erctx." with its value from the context.
func (s *sqlitePlugin) TableGet(userID, table string, selectFields []string, where map[string]interface{},
	ordering []string, groupBy []string, limit, offset int, ctx map[string]interface{}) ([]map[string]interface{}, error) {

	// If context is provided, substitute values in the where clause.
	if ctx != nil {
		flatCtx, err := easyrest.FormatToContext(ctx)
		if err != nil {
			return nil, err
		}
		substituted := substituteContextValues(where, flatCtx)
		if m, ok := substituted.(map[string]interface{}); ok {
			where = m
		} else {
			return nil, fmt.Errorf("expected map[string]interface{} after substitution")
		}
	}

	fields := "*"
	if len(selectFields) > 0 {
		fields = strings.Join(selectFields, ", ")
	}
	query := fmt.Sprintf("SELECT %s FROM %s", fields, table)
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
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
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

// TableCreate substitutes context references in the data values and then builds a standard INSERT query.
func (s *sqlitePlugin) TableCreate(userID, table string, data []map[string]interface{}, ctx map[string]interface{}) ([]map[string]interface{}, error) {
	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return nil, err
	}
	var results []map[string]interface{}
	var flatCtx map[string]string
	if ctx != nil {
		flatCtx, err = easyrest.FormatToContext(ctx)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	// Substitute context references in each row.
	data = substituteContextInData(data, flatCtx)
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

// TableUpdate substitutes context references in both the update data and where clause.
func (s *sqlitePlugin) TableUpdate(userID, table string, data map[string]interface{}, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return 0, err
	}
	var flatCtx map[string]string
	if ctx != nil {
		flatCtx, err = easyrest.FormatToContext(ctx)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	// Substitute in both data and where maps recursively.
	substitutedData, ok := substituteContextValues(data, flatCtx).(map[string]interface{})
	if !ok {
		tx.Rollback()
		return 0, fmt.Errorf("failed to substitute context in data")
	}
	substitutedWhere, ok := substituteContextValues(where, flatCtx).(map[string]interface{})
	if !ok {
		tx.Rollback()
		return 0, fmt.Errorf("failed to substitute context in where")
	}

	var setParts []string
	var args []interface{}
	for k, v := range substitutedData {
		setParts = append(setParts, fmt.Sprintf("%s = ?", k))
		args = append(args, v)
	}
	baseQuery := fmt.Sprintf("UPDATE %s SET %s", table, strings.Join(setParts, ", "))
	whereClause, whereArgs, err := easyrest.BuildWhereClause(substitutedWhere)
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

// TableDelete substitutes context references in the where clause.
func (s *sqlitePlugin) TableDelete(userID, table string, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return 0, err
	}
	var flatCtx map[string]string
	if ctx != nil {
		flatCtx, err = easyrest.FormatToContext(ctx)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	substitutedWhere, ok := substituteContextValues(where, flatCtx).(map[string]interface{})
	if !ok {
		tx.Rollback()
		return 0, fmt.Errorf("failed to substitute context in where")
	}
	whereClause, whereArgs, err := easyrest.BuildWhereClause(substitutedWhere)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	baseQuery := fmt.Sprintf("DELETE FROM %s%s", table, whereClause)
	ctxQuery = context.WithValue(context.Background(), "USER_ID", userID)
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

// CallFunction returns a message including the passed context.
func (s *sqlitePlugin) CallFunction(userID, funcName string, data map[string]interface{}, ctx map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"message": fmt.Sprintf("Function '%s' called by user %s with data: %v and context: %v", funcName, userID, data, ctx),
	}, nil
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
