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

// Helper function to check if any value in a map (string value) contains "erctx."
func mapNeedsCTE(m map[string]interface{}) bool {
	for _, v := range m {
		if s, ok := v.(string); ok && strings.Contains(s, "erctx.") {
			return true
		}
	}
	return false
}

// Helper function to check if any value in a slice of maps contains "erctx."
func dataNeedsCTE(data []map[string]interface{}) bool {
	for _, row := range data {
		if mapNeedsCTE(row) {
			return true
		}
	}
	return false
}

// TableGet now uses queryNeedsCTE as before.
func queryNeedsCTE(selectFields []string, where map[string]interface{}) bool {
	// Check select fields.
	for _, field := range selectFields {
		if strings.Contains(field, "erctx.") {
			return true
		}
	}
	// Check where values.
	for _, val := range where {
		switch v := val.(type) {
		case map[string]interface{}:
			for _, operand := range v {
				if s, ok := operand.(string); ok && strings.Contains(s, "erctx.") {
					return true
				}
			}
		case string:
			if strings.Contains(v, "erctx.") {
				return true
			}
		}
	}
	return false
}

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

// TableGet now receives an extra context parameter (ctx).
// If ctx is non-empty, it is flattened and injected via a CTE named erctx.
func (s *sqlitePlugin) TableGet(userID, table string, selectFields []string, where map[string]interface{},
	ordering []string, groupBy []string, limit, offset int, ctx map[string]interface{}) (results []map[string]interface{}, err error) {

	fields := "*"
	if len(selectFields) > 0 {
		fields = strings.Join(selectFields, ", ")
	}
	query := fmt.Sprintf("SELECT %s FROM %s", fields, table)
	// Build the WHERE clause using the helper from plugin/helpers.go.
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

	// Only wrap with CTE if either select or where contains "erctx.".
	if queryNeedsCTE(selectFields, where) && ctx != nil {
		flatCtx, err := easyrest.FormatToContext(ctx)
		if err != nil {
			return nil, err
		}
		if len(flatCtx) > 0 {
			parts := make([]string, 0, len(flatCtx))
			cteParams := make([]interface{}, 0, len(flatCtx))
			for k, v := range flatCtx {
				parts = append(parts, fmt.Sprintf("? AS %s", k))
				cteParams = append(cteParams, v)
			}
			cteExpr := strings.Join(parts, ", ")
			// Modify FROM clause to include ", erctx"
			modifiedFrom := fmt.Sprintf("FROM %s, erctx", table)
			query = strings.Replace(query, fmt.Sprintf("FROM %s", table), modifiedFrom, 1)
			query = fmt.Sprintf("WITH erctx AS (SELECT %s) %s", cteExpr, query)
			// Prepend the CTE parameters to the arguments.
			args = append(cteParams, args...)
		}
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

// TableCreate wraps the INSERT query with a CTE if context is provided.
func (s *sqlitePlugin) TableCreate(userID, table string, data []map[string]interface{}, ctx map[string]interface{}) ([]map[string]interface{}, error) {
	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return nil, err
	}
	var results []map[string]interface{}
	for _, row := range data {
		cols := make([]string, 0, len(row))
		placeholders := make([]string, 0, len(row))
		args := make([]interface{}, 0, len(row))
		for k, v := range row {
			cols = append(cols, k)
			placeholders = append(placeholders, "?")
			args = append(args, v)
		}
		baseQuery := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
		// Only wrap with CTE if context is provided and data contains "erctx."
		if ctx != nil && dataNeedsCTE(data) {
			flatCtx, err := easyrest.FormatToContext(ctx)
			if err != nil {
				tx.Rollback()
				return nil, err
			}
			if len(flatCtx) > 0 {
				parts := make([]string, 0, len(flatCtx))
				cteParams := make([]interface{}, 0, len(flatCtx))
				for k, v := range flatCtx {
					parts = append(parts, fmt.Sprintf("? AS %s", k))
					cteParams = append(cteParams, v)
				}
				cteExpr := strings.Join(parts, ", ")
				baseQuery = fmt.Sprintf("WITH erctx AS (SELECT %s) %s", cteExpr, baseQuery)
				args = append(cteParams, args...)
			}
		}
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

// TableUpdate wraps the UPDATE query with a CTE if context is provided.
func (s *sqlitePlugin) TableUpdate(userID, table string, data map[string]interface{}, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return 0, err
	}
	setParts := make([]string, 0, len(data))
	args := make([]interface{}, 0, len(data))
	for k, v := range data {
		setParts = append(setParts, fmt.Sprintf("%s = ?", k))
		args = append(args, v)
	}
	baseQuery := fmt.Sprintf("UPDATE %s SET %s", table, strings.Join(setParts, ", "))
	whereClause, whereArgs, err := easyrest.BuildWhereClause(where)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	baseQuery += whereClause
	args = append(args, whereArgs...)
	// For TableUpdate, wrap with CTE only if context is provided and either data or where contains "erctx."
	if ctx != nil && (mapNeedsCTE(data) || mapNeedsCTE(where)) {
		flatCtx, err := easyrest.FormatToContext(ctx)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
		if len(flatCtx) > 0 {
			parts := make([]string, 0, len(flatCtx))
			cteParams := make([]interface{}, 0, len(flatCtx))
			for k, v := range flatCtx {
				parts = append(parts, fmt.Sprintf("? AS %s", k))
				cteParams = append(cteParams, v)
			}
			cteExpr := strings.Join(parts, ", ")
			baseQuery = fmt.Sprintf("WITH erctx AS (SELECT %s) %s", cteExpr, baseQuery)
			args = append(cteParams, args...)
		}
	}
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

// TableDelete wraps the DELETE query with a CTE if context is provided.
func (s *sqlitePlugin) TableDelete(userID, table string, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
	ctxQuery := context.WithValue(context.Background(), "USER_ID", userID)
	tx, err := s.db.BeginTx(ctxQuery, nil)
	if err != nil {
		return 0, err
	}
	whereClause, whereArgs, err := easyrest.BuildWhereClause(where)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	baseQuery := fmt.Sprintf("DELETE FROM %s%s", table, whereClause)
	args := whereArgs
	// For TableDelete, wrap with CTE only if context is provided and where contains "erctx."
	if ctx != nil && mapNeedsCTE(where) {
		flatCtx, err := easyrest.FormatToContext(ctx)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
		if len(flatCtx) > 0 {
			parts := make([]string, 0, len(flatCtx))
			cteParams := make([]interface{}, 0, len(flatCtx))
			for k, v := range flatCtx {
				parts = append(parts, fmt.Sprintf("? AS %s", k))
				cteParams = append(cteParams, v)
			}
			cteExpr := strings.Join(parts, ", ")
			baseQuery = fmt.Sprintf("WITH erctx AS (SELECT %s) %s", cteExpr, baseQuery)
			args = append(cteParams, args...)
		}
	}
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
