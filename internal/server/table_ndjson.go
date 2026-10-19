package server

import (
	"maps"
	"net/http"
	"strconv"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func refreshNDJSONWriteDeadline(w http.ResponseWriter) {
	timeout := currentConfig().Server.WriteTimeout
	if timeout <= 0 {
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout))
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

func stripPreferCount(pluginCtx map[string]any) {
	prefer, _ := pluginCtx["prefer"].(map[string]any)
	if prefer == nil {
		return
	}
	delete(prefer, "count")
}

func ndjsonContentRange(start, written int) string {
	return ndjsonContentRangeTotal(start, written, "")
}

func ndjsonContentRangeTotal(start, written int, total string) string {
	end := start + written - 1
	if written == 0 {
		end = start - 1
	}
	suffix := "*"
	if total != "" {
		suffix = total
	}
	return strconv.Itoa(start) + "-" + strconv.Itoa(end) + "/" + suffix
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
