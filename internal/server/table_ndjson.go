package server

import (
	stdlog "log"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func refreshNDJSONWriteDeadline(w http.ResponseWriter) {
	timeout := currentConfig().Server.WriteTimeout
	if timeout <= 0 {
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout))
}

func writeNDJSONPage(w http.ResponseWriter, enc *json.Encoder, rows []map[string]any) error {
	if err := writeNDJSON(enc, rows); err != nil {
		return err
	}
	_ = http.NewResponseController(w).Flush()
	refreshNDJSONWriteDeadline(w)
	return nil
}

func ndjsonFetchSize(pageLimit, maxRows, written int) int {
	if pageLimit <= 0 {
		return 0
	}
	if maxRows <= 0 {
		return pageLimit
	}
	remaining := maxRows - written
	if remaining <= 0 {
		return 0
	}
	if remaining < pageLimit {
		return remaining
	}
	return pageLimit
}

func streamTableGetNDJSON(
	w http.ResponseWriter,
	r *http.Request,
	dbKey string,
	pluginCtx map[string]any,
	dbPlug easyrest.DBPlugin,
	queryValues url.Values,
	userID, table string,
	selectFields []string,
	where map[string]any,
	ordering, groupBy []string,
	pageLimit, offset, maxRows int,
) {
	if err := r.Context().Err(); err != nil {
		return
	}

	fetch := ndjsonFetchSize(pageLimit, maxRows, 0)
	if fetch <= 0 {
		return
	}

	startTime := time.Now()
	rows, returnedCtx, err := dbPlug.TableGet(userID, table, selectFields, where, ordering, groupBy, fetch, offset, pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	firstDur := time.Since(startTime)
	setDBServerTiming(w, firstDur)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error in TableGet: "+err.Error(), http.StatusInternalServerError)
		return
	}

	status := statusFromPluginContext(pluginCtx, http.StatusOK)
	if status < 200 || status > 299 {
		middlewareMakeResponse(w, r, dbKey, pluginCtx, status, rows, queryValues)
		return
	}

	setHandlerStatus(pluginCtx, status)
	runPostRequestMiddlewares(w, dbKey, pluginCtx)
	applyContextResponseHeaders(w, pluginCtx)
	status = statusFromPluginContext(pluginCtx, status)
	if status < 200 || status > 299 {
		makeResponseWithQuery(w, r, status, rows, queryValues)
		return
	}

	addResponseFormatVary(w)
	w.Header().Set("Range-Unit", "items")
	w.Header().Set("Accept-Ranges", "items")
	w.Header().Add("Trailer", "X-Content-Range")
	w.Header().Add("Trailer", "Server-Timing")

	streamer, ok := encoderFor(contentTypeNDJSON).(streamEncoder)
	if !ok {
		respondNDJSON(w, status, rows)
		return
	}
	rangeStart := offset
	totalDB := firstDur
	pages := streamer.Begin(w, status)

	var inFlight <-chan rowPage
	defer drainRowPage(&inFlight)

	written := 0
	defer func() {
		w.Header().Set("X-Content-Range", ndjsonContentRange(rangeStart, written))
		w.Header().Set("Server-Timing", formatDBServerTiming(totalDB))
	}()

	for {
		nextFetch := 0
		if len(rows) == fetch {
			nextFetch = ndjsonFetchSize(pageLimit, maxRows, written+len(rows))
			if nextFetch > 0 {
				inFlight = prefetchRowPage(dbPlug, userID, table, selectFields, where, ordering, groupBy, nextFetch, offset+fetch, pluginCtx)
			}
		}
		if err := pages.WritePage(rows); err != nil {
			stdlog.Printf("Error encoding NDJSON stream: %v", err)
			return
		}
		written += len(rows)
		if inFlight == nil {
			return
		}
		if err := r.Context().Err(); err != nil {
			return
		}
		page := <-inFlight
		inFlight = nil
		totalDB += page.dur
		if err := r.Context().Err(); err != nil {
			return
		}
		pluginCtx = applyReturnedPluginContext(pluginCtx, page.ctx)
		if page.err != nil {
			stdlog.Printf("Error in TableGet during NDJSON stream: %v", page.err)
			return
		}
		rows = page.rows
		offset += fetch
		fetch = nextFetch
	}
}

func ndjsonContentRange(start, written int) string {
	end := start + written - 1
	if written == 0 {
		end = start - 1
	}
	return strconv.Itoa(start) + "-" + strconv.Itoa(end) + "/*"
}

type rowPage struct {
	rows []map[string]any
	ctx  map[string]any
	err  error
	dur  time.Duration
}

func drainRowPage(ch *<-chan rowPage) {
	if ch == nil || *ch == nil {
		return
	}
	<-*ch
	*ch = nil
}

// prefetchRowPage starts the next TableGet while the caller encodes the current
// page. It clones pluginCtx because TableGet plus a shared map is not
// concurrency-safe. Page N+1 must be requested with the context harvested from
// page N (caller starts this only after page N returns). TableGet has no
// context.Context, so an in-flight call cannot be cancelled; the caller MUST
// receive from the returned channel before returning.
func prefetchRowPage(
	dbPlug easyrest.DBPlugin,
	userID, table string,
	selectFields []string,
	where map[string]any,
	ordering, groupBy []string,
	pageLimit, offset int,
	pluginCtx map[string]any,
) <-chan rowPage {
	ch := make(chan rowPage, 1)
	ctxCopy := maps.Clone(pluginCtx)
	go func() {
		start := time.Now()
		rows, returned, err := dbPlug.TableGet(userID, table, selectFields, where, ordering, groupBy, pageLimit, offset, ctxCopy)
		ch <- rowPage{rows: rows, ctx: returned, err: err, dur: time.Since(start)}
	}()
	return ch
}
