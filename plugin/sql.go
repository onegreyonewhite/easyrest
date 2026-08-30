package plugin

import (
	"strconv"
	"strings"
	"time"
)

// SelectOptions customizes BuildSelectQuery for dialect quirks.
type SelectOptions struct {
	WhereRewriter    func(map[string]any) map[string]any
	OffsetNeedsLimit bool
}

// BuildSelectQuery assembles a parameterized SELECT with '?' placeholders.
func BuildSelectQuery(table string, selectFields []string, where map[string]any, ordering, groupBy []string, limit, offset int, opts SelectOptions) (string, []any, error) {
	if opts.WhereRewriter != nil {
		where = opts.WhereRewriter(where)
	}

	var sb strings.Builder
	sb.Grow(100 + len(table) + len(strings.Join(selectFields, ", ")))
	sb.WriteString("SELECT ")
	if len(selectFields) > 0 {
		sb.WriteString(strings.Join(selectFields, ", "))
	} else {
		sb.WriteByte('*')
	}
	sb.WriteString(" FROM ")
	sb.WriteString(table)

	whereClause, args, err := BuildWhereClauseSorted(where)
	if err != nil {
		return "", nil, err
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
		sb.WriteString(" LIMIT ")
		sb.WriteString(strconv.Itoa(limit))
		if offset > 0 {
			sb.WriteString(" OFFSET ")
			sb.WriteString(strconv.Itoa(offset))
		}
	} else if offset > 0 {
		if opts.OffsetNeedsLimit {
			sb.WriteString(" LIMIT -1 OFFSET ")
			sb.WriteString(strconv.Itoa(offset))
		} else {
			sb.WriteString(" OFFSET ")
			sb.WriteString(strconv.Itoa(offset))
		}
	}
	return sb.String(), args, nil
}

// FormatSQLTime formats t as a date or datetime string.
func FormatSQLTime(t time.Time) string {
	if t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0 {
		return t.Format("2006-01-02")
	}
	return t.Format("2006-01-02 15:04:05")
}
