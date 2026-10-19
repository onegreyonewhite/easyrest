package server

import (
	stdlog "log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// contentRead is the shared TableGet loop for table GET and REST list.
// Callers fill select, where, ordering, and the caller's limit and offset
// before the first fetch. It does not store a context.Context.
type contentRead struct {
	w              http.ResponseWriter
	r              *http.Request
	dbKey          string
	pluginCtx      map[string]any
	query          url.Values
	plug           easyrest.DBPlugin
	renderer       contentPluginRef
	userID         string
	table          string
	selectFields   []string
	where          map[string]any
	ordering       []string
	groupBy        []string
	limit          int
	offset         int
	page           int
	paginate       bool
	range416AtZero bool
	usedRange      bool
	rangeHeader    string
	linkCtx        map[string]any
	fail           func(error)
	prepareRows    func([]map[string]any) error
}

func serveContentRead(q contentRead) {
	if q.canceled() {
		return
	}
	if q.linkCtx == nil {
		q.linkCtx = q.pluginCtx
	}
	cw := newContentWriter(q.w, q.r, q.dbKey, q.pluginCtx, q.query, q.renderer, true)
	window, sliced := readWindow(cw.plug, q.limit, q.offset, q.page)
	cw.flush = sliced
	if q.canceled() {
		return
	}

	start := time.Now()
	rows, returned, err := q.plug.TableGet(q.userID, q.table, q.selectFields, q.where, q.ordering, q.groupBy, window.Limit, window.Offset, q.pluginCtx)
	q.pluginCtx = applyReturnedPluginContext(q.pluginCtx, returned)
	cw.pluginCtx = q.pluginCtx
	totalDB := time.Since(start)
	setDBServerTiming(q.w, totalDB)
	if err != nil {
		if q.fail != nil {
			q.fail(err)
			return
		}
		_ = cw.WriteError(http.StatusInternalServerError, "Error in TableGet: "+err.Error())
		return
	}
	if q.prepareRows != nil {
		if err := q.prepareRows(rows); err != nil {
			_ = cw.WriteError(http.StatusInternalServerError, err.Error())
			return
		}
	}

	status := http.StatusOK
	if !sliced {
		status, rows = applyReadRange(q.w, rows, q.offset, q.range416AtZero, q.usedRange, q.rangeHeader, q.pluginCtx)
	}
	status = cw.prepare(status, true)
	if cw.status < 200 || cw.status > 299 {
		payload, pag := q.pagePayload(rows, true)
		_ = cw.Write(cw.status, payload, pag)
		return
	}
	if sliced {
		q.w.Header().Set("Range-Unit", "items")
		q.w.Header().Set("Accept-Ranges", "items")
	}

	totalSuffix := ""
	if total, ok := contextTotal(q.pluginCtx); ok {
		totalSuffix = strconv.FormatInt(total, 10)
	}
	written := 0
	if sliced {
		q.w.Header().Add("Trailer", "X-Content-Range")
		q.w.Header().Add("Trailer", "Server-Timing")
		defer func() {
			q.w.Header().Set("X-Content-Range", ndjsonContentRangeTotal(q.offset, written, totalSuffix))
			q.w.Header().Set("Server-Timing", formatDBServerTiming(totalDB))
		}()
	}
	stripPreferCount(q.pluginCtx)

	var inFlight <-chan rowPage
	defer drainRowPage(&inFlight)

	fetch := window.Limit
	cursor := q.offset
	for {
		if q.canceled() {
			return
		}
		nextFetch := 0
		total, hasTotal := contextTotal(q.pluginCtx)
		if readContinues(sliced, len(rows), fetch, written, q.limit, q.offset, total, hasTotal) {
			nextFetch = nextFetchLimit(cw.plug, q.limit, written+len(rows), q.page, cursor+fetch)
			if nextFetch > 0 {
				inFlight = prefetchRowPage(q.plug, q.userID, q.table, q.selectFields, q.where, q.ordering, q.groupBy, nextFetch, cursor+fetch, q.pluginCtx)
			}
		}
		payload, pag := q.pagePayload(rows, written == 0)
		if err := cw.Write(cw.status, payload, pag); err != nil {
			stdlog.Printf("Error encoding response: %v", err)
			return
		}
		written += len(rows)
		if inFlight == nil {
			return
		}
		page := <-inFlight
		inFlight = nil
		totalDB += page.dur
		if q.canceled() {
			return
		}
		q.pluginCtx = applyReturnedPluginContext(q.pluginCtx, page.ctx)
		cw.pluginCtx = q.pluginCtx
		if page.err != nil {
			stdlog.Printf("Error in TableGet during content stream: %v", page.err)
			_ = cw.WriteError(http.StatusOK, "Error in TableGet: "+page.err.Error())
			return
		}
		rows = page.rows
		if q.prepareRows != nil {
			if err := q.prepareRows(rows); err != nil {
				_ = cw.WriteError(http.StatusOK, err.Error())
				return
			}
		}
		cursor += fetch
		fetch = nextFetch
	}
}

func (q contentRead) canceled() bool {
	return q.r != nil && q.r.Context().Err() != nil
}

func (q contentRead) pagePayload(rows []map[string]any, first bool) (any, map[string]any) {
	if !q.paginate {
		return rows, nil
	}
	rows = restListRows(rows)
	if !first {
		return map[string]any{easyrest.PagResults: rows}, map[string]any{easyrest.PagResults: easyrest.PagResults}
	}
	total, hasTotal := contextTotal(q.pluginCtx)
	next, prev := restListLinks(q.linkCtx, q.r, q.limit, q.offset, total, hasTotal)
	pag := map[string]any{
		easyrest.PagResults: easyrest.PagResults,
		easyrest.PagNext:    next,
		easyrest.PagPrev:    prev,
	}
	if hasTotal {
		pag[easyrest.PagCount] = total
	}
	return map[string]any{easyrest.PagResults: rows}, pag
}

func readWindow(plug easyrest.ContentPlugin, limit, offset, page int) (easyrest.ContentWindow, bool) {
	if plug == nil {
		return easyrest.ContentWindow{Limit: limit, Offset: offset}, false
	}
	windows, repeat := plug.PrepareGet(limit, offset, page)
	if len(windows) == 0 || windows[0].Limit <= 0 {
		return easyrest.ContentWindow{Limit: limit, Offset: offset}, false
	}
	return windows[0], repeat
}

func readContinues(sliced bool, got, fetch, written, callerLimit, start int, total int64, hasTotal bool) bool {
	if !sliced || fetch <= 0 || got != fetch {
		return false
	}
	next := written + got
	if callerLimit > 0 {
		return next < callerLimit
	}
	if hasTotal {
		return int64(start)+int64(next) < total
	}
	return true
}

func nextFetchLimit(plug easyrest.ContentPlugin, callerLimit, written, page, offset int) int {
	remaining := 0
	if callerLimit > 0 {
		remaining = callerLimit - written
		if remaining <= 0 {
			return 0
		}
	}
	if plug == nil {
		return 0
	}
	windows, repeat := plug.PrepareGet(remaining, offset, page)
	if !repeat || len(windows) == 0 || windows[0].Limit <= 0 {
		return 0
	}
	return windows[0].Limit
}

func applyReadRange(w http.ResponseWriter, rows []map[string]any, offset int, atZero, usedHeader bool, rangeHeader string, pluginCtx map[string]any) (int, []map[string]any) {
	status := http.StatusOK
	rowCount := len(rows)
	startIdx := offset
	endIdx := offset + rowCount - 1
	if rowCount == 0 {
		endIdx = offset - 1
	}
	unsatisfiable := startIdx > endIdx
	if !atZero {
		unsatisfiable = offset > 0 && unsatisfiable
	}
	if unsatisfiable {
		status = http.StatusRequestedRangeNotSatisfiable
		if usedHeader {
			parts := strings.SplitN(rangeHeader, "-", 2)
			if len(parts) == 2 {
				end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err == nil {
					startIdx = end
					endIdx = end
				}
			}
		}
		rows = []map[string]any{}
	}
	w.Header().Set("Content-Range", formatContentRange(startIdx, endIdx, pluginCtx))
	w.Header().Set("Range-Unit", "items")
	w.Header().Set("Accept-Ranges", "items")
	return status, rows
}
