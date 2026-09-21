package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

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

func tableFlatContext(w http.ResponseWriter, bag *apiRequest, queryValues map[string][]string) (map[string]string, bool) {
	if !queryNeedsContextSubst(queryValues) {
		return nil, true
	}
	flatCtx, err := easyrest.FormatToContext(bag.pluginCtx)
	if err != nil {
		middlewareHTTPError(w, bag.dbKey, bag.pluginCtx, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
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
	flatCtx, ok := tableFlatContext(w, bag, queryValues)
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
		middlewareHTTPError(w, dbKey, pluginCtx, "Error processing select parameter: "+err.Error(), http.StatusBadRequest)
		return
	}

	where, err := ParseWhereClause(queryValues, flatCtx, pluginCtx)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
		return
	}

	ordering := ParseCSV(queryValues.Get("ordering"))
	if err := sanitizeIdentifierList(ordering); err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error processing ordering parameter: "+err.Error(), http.StatusBadRequest)
		return
	}

	if bag.respType == contentTypeNDJSON && pageSize > 0 {
		if preferSize > 0 {
			appendPreferenceApplied(w, "page_size="+strconv.Itoa(preferSize))
		}
		streamTableGetNDJSON(w, r, dbKey, pluginCtx, bag.dbPlug, queryValues, bag.userID, table, selectFields, where, ordering, groupBy, pageSize, offset, maxRows)
		return
	}

	if limit == 0 {
		limit = pageSize
		if preferSize > 0 {
			appendPreferenceApplied(w, "page_size="+strconv.Itoa(preferSize))
		}
	}

	startTime := time.Now()
	rows, returnedCtx, err := bag.dbPlug.TableGet(bag.userID, table, selectFields, where, ordering, groupBy, limit, offset, pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	queryTime := time.Since(startTime)

	setDBServerTiming(w, queryTime)

	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error in TableGet: "+err.Error(), http.StatusInternalServerError)
		return
	}

	status := http.StatusOK

	rowCount := len(rows)
	startIdx := offset
	endIdx := offset + rowCount - 1
	if rowCount == 0 {
		endIdx = offset - 1
	}

	if startIdx > endIdx {
		status = http.StatusRequestedRangeNotSatisfiable
		if usedHeaderRange {
			parts := strings.SplitN(rangeHeader, "-", 2)
			if len(parts) == 2 {
				end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err2 == nil {
					startIdx = end
					endIdx = end
				}
			}
		}
		rows = []map[string]any{}
	}
	w.Header().Set("Content-Range", strconv.Itoa(startIdx)+"-"+strconv.Itoa(endIdx)+"/*")
	w.Header().Set("Range-Unit", "items")
	w.Header().Set("Accept-Ranges", "items")

	middlewareMakeResponse(w, r, dbKey, pluginCtx, status, rows, queryValues)
}
