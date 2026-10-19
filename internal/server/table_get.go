package server

import (
	"math"
	"net/http"
	"strconv"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func contextTotal(pluginCtx map[string]any) (int64, bool) {
	if pluginCtx == nil {
		return 0, false
	}
	switch n := pluginCtx["total"].(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(math.Round(n)), true
	default:
		return 0, false
	}
}

func formatContentRange(start, end int, pluginCtx map[string]any) string {
	suffix := "*"
	if total, ok := contextTotal(pluginCtx); ok {
		suffix = strconv.FormatInt(total, 10)
	}
	return strconv.Itoa(start) + "-" + strconv.Itoa(end) + "/" + suffix
}

func preferPageSize(pluginCtx map[string]any) int {
	prefer, ok := pluginCtx["prefer"].(map[string]any)
	if !ok {
		return 0
	}
	raw, ok := prefer["page_size"]
	if !ok || raw == nil {
		return 0
	}
	s, ok := raw.(string)
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func tableFlatContext(w http.ResponseWriter, r *http.Request, bag *apiRequest, queryValues map[string][]string) (map[string]string, bool) {
	if !queryNeedsContextSubst(queryValues) {
		return nil, true
	}
	flatCtx, err := easyrest.FormatToContext(bag.pluginCtx)
	if err != nil {
		middlewareHTTPError(w, r, bag.dbKey, bag.pluginCtx, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	return flatCtx, true
}

func tableGet(w http.ResponseWriter, r *http.Request) {
	bag := apiRequestFrom(r)
	dbKey := bag.dbKey
	table := bag.resource
	pluginCtx := bag.pluginCtx
	queryValues := bag.query
	flatCtx, ok := tableFlatContext(w, r, bag, queryValues)
	if !ok {
		return
	}

	preferSize := preferPageSize(pluginCtx)
	pageSize := bag.pluginCfg.DefaultLimit
	if preferSize > 0 {
		pageSize = preferSize
	}

	limit := 0
	offset := 0
	rangeUnitHeader := r.Header.Get("Range-Unit")
	rangeHeader := r.Header.Get("Range")
	usedHeaderRange := false
	if strings.ToLower(rangeUnitHeader) == "items" && rangeHeader != "" {
		parts := strings.SplitN(rangeHeader, "-", 2)
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && start >= 0 && end >= start {
				offset = start
				limit = end - start + 1
				usedHeaderRange = true
			}
		}
	}
	if !usedHeaderRange {
		limit, _ = strconv.Atoi(queryValues.Get("limit"))
		offset, _ = strconv.Atoi(queryValues.Get("offset"))
		if offset < 0 {
			offset = 0
		}
	}

	maxRows := 0
	if usedHeaderRange {
		maxRows = limit
	} else if limit > 0 {
		maxRows = limit
	}

	selectParam := queryValues.Get("select")

	selectFields, groupBy, err := processSelectParam(selectParam, flatCtx, pluginCtx)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error processing select parameter: "+err.Error(), http.StatusBadRequest)
		return
	}

	where, err := ParseWhereClause(queryValues, flatCtx, pluginCtx)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
		return
	}

	ordering := ParseCSV(queryValues.Get("ordering"))
	if err := sanitizeIdentifierList(ordering); err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error processing ordering parameter: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, sliced := readWindow(bag.content.Renderer.Plugin, maxRows, offset, pageSize)
	if preferSize > 0 && (sliced || limit == 0) {
		appendPreferenceApplied(w, "page_size="+strconv.Itoa(preferSize))
	}

	serveContentRead(contentRead{
		w:              w,
		r:              r,
		dbKey:          dbKey,
		pluginCtx:      pluginCtx,
		query:          queryValues,
		plug:           bag.dbPlug,
		renderer:       bag.content.Renderer,
		userID:         bag.userID,
		table:          table,
		selectFields:   selectFields,
		where:          where,
		ordering:       ordering,
		groupBy:        groupBy,
		limit:          maxRows,
		offset:         offset,
		page:           pageSize,
		range416AtZero: true,
		usedRange:      usedHeaderRange,
		rangeHeader:    rangeHeader,
	})
}
