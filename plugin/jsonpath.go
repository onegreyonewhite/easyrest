package plugin

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
)

// SQL dialects for JSON arrow expressions. Empty means PostgreSQL.
const (
	DialectPostgres = "postgres"
	DialectSQLite   = "sqlite"
	DialectMySQL    = "mysql"
)

// ErrJSONIndexAlias is returned when a JSON path ends on an array index
// and the caller did not supply an alias.
var ErrJSONIndexAlias = errors.New("json path ending in an array index needs an alias")

type jsonStep struct {
	asText  bool
	key     string
	index   int
	isIndex bool
}

type jsonPath struct {
	column string
	steps  []jsonStep
}

func (p jsonPath) finalText() bool {
	return len(p.steps) > 0 && p.steps[len(p.steps)-1].asText
}

func (p jsonPath) asTextPath() jsonPath {
	cp := p
	cp.steps = append([]jsonStep(nil), p.steps...)
	if n := len(cp.steps); n > 0 {
		cp.steps[n-1].asText = true
	}
	return cp
}

func (p jsonPath) defaultAlias() (string, bool) {
	if len(p.steps) == 0 || p.steps[len(p.steps)-1].isIndex {
		return "", false
	}
	return p.steps[len(p.steps)-1].key, true
}

// PostgresJSONExpr parses a user JSON path (json_data->phones->0->>number)
// into a PostgreSQL arrow expression.
func PostgresJSONExpr(raw string) (expr string, asText bool, err error) {
	p, ok := parseUserJSONPath(raw)
	if !ok {
		return "", false, fmt.Errorf("invalid json path")
	}
	return p.postgresExpr(), p.finalText(), nil
}

// RenderJSONSelect renders a user JSON path as a PostgreSQL select item.
// alias is an explicit unquoted alias. An empty alias uses the last object key,
// quoted so mixed case survives PostgreSQL. A path that ends on an index
// returns ErrJSONIndexAlias when alias is empty.
func RenderJSONSelect(raw, alias string) (item, groupExpr string, err error) {
	p, ok := parseUserJSONPath(raw)
	if !ok {
		return "", "", fmt.Errorf("invalid json path")
	}
	expr := p.postgresExpr()
	if alias == "" {
		name, ok := p.defaultAlias()
		if !ok {
			return "", "", ErrJSONIndexAlias
		}
		alias = `"` + name + `"`
	}
	return expr + " AS " + alias, expr, nil
}

// RewriteJSONSelectFields rewrites PostgreSQL JSON arrow select items for dialect.
// Postgres and sqlite keep the expressions. MySQL collapses each chain into one
// JSON path and quotes aliases with backticks.
func RewriteJSONSelectFields(fields []string, dialect string) ([]string, error) {
	if dialect != DialectMySQL || len(fields) == 0 {
		return fields, nil
	}
	needs := false
	for _, f := range fields {
		if strings.Contains(f, "->") {
			needs = true
			break
		}
	}
	if !needs {
		return fields, nil
	}
	out := make([]string, len(fields))
	for i, f := range fields {
		expr, alias, quoted, ok := splitJSONSelect(f)
		if !ok {
			out[i] = f
			continue
		}
		p, parsed := parsePostgresJSONExpr(expr)
		if !parsed {
			return nil, fmt.Errorf("invalid json path: %s", f)
		}
		rendered := p.mysqlExpr()
		if alias == "" {
			out[i] = rendered
			continue
		}
		if quoted {
			out[i] = rendered + " AS `" + strings.ReplaceAll(alias, "`", "``") + "`"
			continue
		}
		out[i] = rendered + " AS " + alias
	}
	return out, nil
}

// JSONTextColumns returns select aliases produced by ->> .
// Callers keep those values as text instead of decoding them as JSON.
func JSONTextColumns(fields []string) map[string]struct{} {
	cols := jsonArrowCols(fields)
	if len(cols) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(cols))
	for _, c := range cols {
		if c.asText {
			out[c.alias] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeJSONArrowRows shapes driver values for JSON arrow select items.
// -> becomes a decoded JSON value. ->> stays text, including numbers that
// SQLite returns as integers.
func NormalizeJSONArrowRows(rows []map[string]any, fields []string) {
	if len(rows) == 0 || len(fields) == 0 {
		return
	}
	cols := jsonArrowCols(fields)
	if len(cols) == 0 {
		return
	}
	for _, row := range rows {
		if row == nil {
			continue
		}
		for _, c := range cols {
			v, ok := row[c.alias]
			if !ok || v == nil {
				continue
			}
			if c.asText {
				row[c.alias] = jsonArrowText(v)
				continue
			}
			row[c.alias] = jsonArrowValue(v)
		}
	}
}

// ValidateJSONArrowValue checks a -> filter value. ->> values are not validated.
// op is the SQL operator (=, >, IN, ...). dialect sqlite rejects ordering of
// JSON values that are not numbers or strings.
func ValidateJSONArrowValue(op, value, dialect string) error {
	if op == "IS" || op == "LIKE" || op == "ILIKE" {
		return nil
	}
	if dialect == "" {
		dialect = DialectPostgres
	}
	values := []string{value}
	if op == "IN" {
		values = splitCSV(value)
	}
	for _, v := range values {
		if !json.Valid([]byte(v)) {
			return fmt.Errorf("json -> value must be valid json")
		}
		if dialect == DialectSQLite && isOrderOp(op) {
			kind, _, ok := jsonScalarKind(v)
			if !ok || (kind != "number" && kind != "string") {
				return fmt.Errorf("json -> ordering on sqlite supports only numbers and strings")
			}
		}
	}
	return nil
}

// DialectFromContext reads db.type from a plugin context.
func DialectFromContext(ctx map[string]any) string {
	s, ok := CtxString(ctx, CtxDBType)
	if !ok {
		return DialectPostgres
	}
	switch s {
	case DialectMySQL, DialectSQLite:
		return s
	default:
		return DialectPostgres
	}
}

func (p jsonPath) postgresExpr() string {
	var b strings.Builder
	b.Grow(len(p.column) + len(p.steps)*8)
	b.WriteString(p.column)
	for _, st := range p.steps {
		b.WriteString("->")
		if st.asText {
			b.WriteByte('>')
		}
		if st.isIndex {
			b.WriteString(strconv.Itoa(st.index))
			continue
		}
		b.WriteByte('\'')
		b.WriteString(strings.ReplaceAll(st.key, "'", "''"))
		b.WriteByte('\'')
	}
	return b.String()
}

func (p jsonPath) mysqlExpr() string {
	var b strings.Builder
	b.Grow(len(p.column) + len(p.steps)*8)
	b.WriteString(p.column)
	if p.finalText() {
		b.WriteString("->>")
	} else {
		b.WriteString("->")
	}
	b.WriteString("'$")
	for _, st := range p.steps {
		if st.isIndex {
			b.WriteByte('[')
			b.WriteString(strconv.Itoa(st.index))
			b.WriteByte(']')
			continue
		}
		b.WriteByte('.')
		b.WriteString(st.key)
	}
	b.WriteByte('\'')
	return b.String()
}

func parseUserJSONPath(raw string) (jsonPath, bool) {
	s := strings.TrimSpace(raw)
	col, rest, ok := takeIdent(s)
	if !ok {
		return jsonPath{}, false
	}
	var steps []jsonStep
	for {
		rest = strings.TrimSpace(rest)
		if rest == "" {
			break
		}
		if !strings.HasPrefix(rest, "->") {
			return jsonPath{}, false
		}
		rest = rest[2:]
		asText := false
		if strings.HasPrefix(rest, ">") {
			asText = true
			rest = rest[1:]
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return jsonPath{}, false
		}
		st := jsonStep{asText: asText}
		if rest[0] >= '0' && rest[0] <= '9' {
			j := 0
			for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
				j++
			}
			n, err := strconv.Atoi(rest[:j])
			if err != nil {
				return jsonPath{}, false
			}
			st.isIndex = true
			st.index = n
			rest = rest[j:]
		} else {
			key, next, ok := takeIdent(rest)
			if !ok {
				return jsonPath{}, false
			}
			st.key = key
			rest = next
		}
		if asText && strings.TrimSpace(rest) != "" {
			return jsonPath{}, false
		}
		steps = append(steps, st)
	}
	if len(steps) == 0 {
		return jsonPath{}, false
	}
	return jsonPath{column: col, steps: steps}, true
}

func parsePostgresJSONExpr(s string) (jsonPath, bool) {
	col, i, ok := readIdentAt(s, 0)
	if !ok || i >= len(s) {
		return jsonPath{}, false
	}
	var steps []jsonStep
	for i < len(s) {
		if i+1 >= len(s) || s[i] != '-' || s[i+1] != '>' {
			return jsonPath{}, false
		}
		i += 2
		asText := false
		if i < len(s) && s[i] == '>' {
			asText = true
			i++
		}
		st := jsonStep{asText: asText}
		if i < len(s) && s[i] == '\'' {
			key, next, ok := readSQLString(s, i)
			if !ok || !IsValidIdentifier(key) {
				return jsonPath{}, false
			}
			st.key = key
			i = next
		} else if i < len(s) && s[i] >= '0' && s[i] <= '9' {
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			n, err := strconv.Atoi(s[i:j])
			if err != nil {
				return jsonPath{}, false
			}
			st.isIndex = true
			st.index = n
			i = j
		} else {
			return jsonPath{}, false
		}
		if asText && i != len(s) {
			return jsonPath{}, false
		}
		steps = append(steps, st)
	}
	if len(steps) == 0 {
		return jsonPath{}, false
	}
	return jsonPath{column: col, steps: steps}, true
}

func takeIdent(s string) (ident, rest string, ok bool) {
	ident, n, ok := readIdentAt(s, 0)
	if !ok {
		return "", s, false
	}
	return ident, s[n:], true
}

func readIdentAt(s string, i int) (string, int, bool) {
	if i >= len(s) || !isIdentStart(s[i]) {
		return "", i, false
	}
	j := i + 1
	for j < len(s) && isIdentCont(s[j]) {
		j++
	}
	return s[i:j], j, true
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func readSQLString(s string, i int) (string, int, bool) {
	if i >= len(s) || s[i] != '\'' {
		return "", i, false
	}
	i++
	var b strings.Builder
	for i < len(s) {
		if s[i] == '\'' {
			if i+1 < len(s) && s[i+1] == '\'' {
				b.WriteByte('\'')
				i += 2
				continue
			}
			return b.String(), i + 1, true
		}
		b.WriteByte(s[i])
		i++
	}
	return "", i, false
}

func unwrapWhereField(field string) (inner string, lower, nocase bool) {
	inner = field
	if strings.HasPrefix(inner, "LOWER(") && strings.HasSuffix(inner, ")") {
		lower = true
		inner = inner[len("LOWER(") : len(inner)-1]
	}
	const nocaseSuffix = " COLLATE NOCASE"
	if strings.HasSuffix(inner, nocaseSuffix) {
		nocase = true
		inner = strings.TrimSpace(strings.TrimSuffix(inner, nocaseSuffix))
		if len(inner) >= 2 && inner[0] == '(' && inner[len(inner)-1] == ')' {
			inner = inner[1 : len(inner)-1]
		}
	}
	return inner, lower, nocase
}

func jsonWherePath(field string) (jsonPath, bool, bool, bool) {
	inner, lower, nocase := unwrapWhereField(field)
	p, ok := parsePostgresJSONExpr(inner)
	return p, lower, nocase, ok
}

func splitJSONSelect(item string) (expr, alias string, quoted, ok bool) {
	if !strings.Contains(item, "->") {
		return "", "", false, false
	}
	expr = item
	if i := strings.LastIndex(item, " AS "); i >= 0 {
		expr = item[:i]
		alias = item[i+4:]
		if len(alias) >= 2 && alias[0] == '"' && alias[len(alias)-1] == '"' {
			alias = strings.ReplaceAll(alias[1:len(alias)-1], `""`, `"`)
			quoted = true
		}
	}
	if _, parsed := parsePostgresJSONExpr(expr); !parsed {
		return "", "", false, false
	}
	return expr, alias, quoted, true
}

type jsonArrowCol struct {
	alias  string
	asText bool
}

func jsonArrowCols(fields []string) []jsonArrowCol {
	cols := make([]jsonArrowCol, 0)
	for _, f := range fields {
		expr, alias, _, ok := splitJSONSelect(f)
		if !ok || alias == "" {
			continue
		}
		p, parsed := parsePostgresJSONExpr(expr)
		if !parsed {
			continue
		}
		cols = append(cols, jsonArrowCol{alias: alias, asText: p.finalText()})
	}
	return cols
}

func jsonArrowText(v any) any {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case int:
		return strconv.Itoa(t)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprint(t)
	}
}

func jsonArrowValue(v any) any {
	var raw []byte
	switch t := v.(type) {
	case string:
		raw = []byte(t)
	case []byte:
		raw = t
	default:
		return v
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return v
	}
	return out
}

func isOrderOp(op string) bool {
	switch op {
	case ">", ">=", "<", "<=":
		return true
	default:
		return false
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func jsonScalarKind(s string) (kind, literal string, ok bool) {
	if !json.Valid([]byte(s)) {
		return "", "", false
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", "", false
	}
	switch t := v.(type) {
	case json.Number:
		return "number", t.String(), true
	case float64:
		return "number", strconv.FormatFloat(t, 'f', -1, 64), true
	case string:
		return "string", t, true
	case bool:
		return "bool", "", true
	case nil:
		return "null", "", true
	case []any:
		return "array", "", true
	case map[string]any:
		return "object", "", true
	default:
		return "", "", false
	}
}

func applyFieldWrap(lhs string, lower, nocase bool) string {
	if lower {
		lhs = "LOWER(" + lhs + ")"
	}
	if nocase {
		lhs = lhs + " COLLATE NOCASE"
	}
	return lhs
}

func parentJSON(p jsonPath, dialect string) string {
	expr := p.postgresExpr()
	if dialect == DialectMySQL {
		expr = p.mysqlExpr()
	}
	return "(" + expr + ")"
}

// arrowCompare builds the left side, placeholder, and bound arg for one -> / ->> compare.
func arrowCompare(p jsonPath, op, dialect, value string) (lhs, placeholder string, arg any, err error) {
	if dialect == "" {
		dialect = DialectPostgres
	}
	if !p.finalText() && (op == "LIKE" || op == "ILIKE") {
		return "", "", nil, fmt.Errorf("like and ilike require ->>")
	}
	if p.finalText() || op == "IS" {
		return parentJSON(p, dialect), "?", value, nil
	}
	if !json.Valid([]byte(value)) {
		return "", "", nil, fmt.Errorf("json -> value must be valid json")
	}
	switch dialect {
	case DialectMySQL:
		return parentJSON(p, dialect), "CAST(? AS JSON)", value, nil
	case DialectSQLite:
		if isOrderOp(op) {
			kind, lit, ok := jsonScalarKind(value)
			if !ok || (kind != "number" && kind != "string") {
				return "", "", nil, fmt.Errorf("json -> ordering on sqlite supports only numbers and strings")
			}
			text := p.asTextPath()
			if kind == "number" {
				return "CAST((" + text.postgresExpr() + ") AS REAL)", "CAST(? AS REAL)", value, nil
			}
			return parentJSON(text, DialectSQLite), "?", lit, nil
		}
		return parentJSON(p, DialectSQLite), "json(?)", value, nil
	default:
		return parentJSON(p, DialectPostgres), "?::jsonb", value, nil
	}
}

func jsonCond(p jsonPath, lower, nocase bool, op string, operand any, dialect string) (string, []any, error) {
	if dialect == "" {
		dialect = DialectPostgres
	}
	if !p.finalText() && (op == "LIKE" || op == "ILIKE") {
		return "", nil, fmt.Errorf("like and ilike require ->>")
	}
	if op == "IN" {
		s, ok := operand.(string)
		if !ok {
			return "", nil, fmt.Errorf("json -> value must be valid json")
		}
		parts := splitCSV(s)
		lhs, _, _, err := arrowCompare(p, "=", dialect, firstOrEmpty(parts))
		if err != nil {
			return "", nil, err
		}
		if len(parts) == 0 {
			// An empty IN list matches the plain-field form: IN (NULL), no args.
			if !p.finalText() {
				lhs = parentJSON(p, dialect)
			}
			lhs = applyFieldWrap(lhs, lower, nocase)
			return lhs + " IN (NULL)", nil, nil
		}
		lhs = applyFieldWrap(lhs, lower, nocase)
		args := make([]any, 0, len(parts))
		var b strings.Builder
		b.WriteString(lhs)
		b.WriteString(" IN (")
		for i, part := range parts {
			_, ph, arg, err := arrowCompare(p, "=", dialect, part)
			if err != nil {
				return "", nil, err
			}
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(ph)
			args = append(args, arg)
		}
		b.WriteByte(')')
		return b.String(), args, nil
	}
	if p.finalText() || op == "IS" {
		lhs := applyFieldWrap(parentJSON(p, dialect), lower, nocase)
		return lhs + " " + op + " ?", []any{operand}, nil
	}
	s, ok := operand.(string)
	if !ok {
		return "", nil, fmt.Errorf("json -> value must be valid json")
	}
	lhs, ph, arg, err := arrowCompare(p, op, dialect, s)
	if err != nil {
		return "", nil, err
	}
	lhs = applyFieldWrap(lhs, lower, nocase)
	return lhs + " " + op + " " + ph, []any{arg}, nil
}

func firstOrEmpty(parts []string) string {
	if len(parts) == 0 {
		return "null"
	}
	return parts[0]
}
