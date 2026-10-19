package server

import (
	"errors"
	"fmt"
	stdlog "log"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/go-chi/chi/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

var (
	restPathParamRE = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)
)

// restSwap is mounted once at /restapi. publishRestAPI replaces the handler.
var restSwap atomic.Pointer[http.Handler]

type restSwapHandler struct{}

func (restSwapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := restSwap.Load()
	if h == nil || *h == nil {
		http.NotFound(w, r)
		return
	}
	(*h).ServeHTTP(w, r)
}

func mountRestAPI(r chi.Router) {
	r.Mount("/restapi", restSwapHandler{})
}

func publishRestAPI() {
	h := compileRestRouter(currentConfig())
	restSwap.Store(&h)
}

type restQueryFilter struct {
	name  string
	field string
	op    string
	not   bool
}

type restTableAction struct {
	source          string
	table           string
	primaryKey      string
	pathParams      []string
	filters         []restQueryFilter
	writeKeys       map[string]struct{}
	readOnly        map[string]struct{}
	selectFields    []string
	callFunc        string
	includePK       bool
	sourceField     string
	props           map[string]any
	endpointName    string
	checkScope      bool
	public          bool
	cache           bool
	globalMW        []string
	apiMW           []string
	endpointContent []string
	appContent      []string
	contentReady    bool
	parsers         []contentPluginRef
	renderers       []contentPluginRef
	storageName     string
	fieldProps      map[string]any
	appAuth         *[]string
	endpointAuth    *[]string
	actionAuth      *[]string
	appAnon         map[string]any
	endpointScopes  []string
	actionScopes    []string
	handler         string
	successStatus   int
}

func restPathParamNames(urlPath string) []string {
	matches := restPathParamRE.FindAllStringSubmatch(urlPath, -1)
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, match[1])
	}
	return names
}

func (a restTableAction) pathValues(r *http.Request) map[string]string {
	values := make(map[string]string, len(a.pathParams))
	for _, name := range a.pathParams {
		values[name] = chi.URLParam(r, name)
	}
	return values
}

func whereEquals(values map[string]string) map[string]any {
	where := make(map[string]any, len(values))
	for field, value := range values {
		where[field] = map[string]any{"=": value}
	}
	return where
}

func (a restTableAction) whereFromPath(r *http.Request) map[string]any {
	return whereEquals(a.pathValues(r))
}

func (a restTableAction) detailWhere(r *http.Request) map[string]any {
	values := a.pathValues(r)
	pk := a.primaryKey
	if pk == "" {
		pk = "id"
	}
	values[pk] = chi.URLParam(r, "id")
	return whereEquals(values)
}

func (a restTableAction) authorize(w http.ResponseWriter, r *http.Request, read bool) (string, *http.Request, bool) {
	var (
		userID string
		err    error
	)
	if names := a.allowedAuth(); names != nil {
		userID, r, err = authenticateAllowed(r, *names, a.appAnon)
	} else {
		userID, r, err = Authenticate(r)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return "", r, false
	}
	if !a.checkScope || a.public {
		return userID, r, true
	}
	claims := getTokenClaims(r)
	for _, scope := range restRequiredScopes(a.actionScopes, a.endpointScopes, a.endpointName, read) {
		if CheckScope(claims, scope) {
			continue
		}
		http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
		return "", r, false
	}
	return userID, r, true
}

func (a restTableAction) allowedAuth() *[]string {
	if a.actionAuth != nil {
		return a.actionAuth
	}
	if a.endpointAuth != nil {
		return a.endpointAuth
	}
	return a.appAuth
}

func (a restTableAction) openContext(w http.ResponseWriter, r *http.Request, read bool, fn string) (string, *http.Request, map[string]any, bool) {
	userID, r, ok := a.authorize(w, r, read)
	if !ok {
		return "", r, nil, false
	}
	if fn == "" {
		fn = a.callFunc
	}
	ctx := buildPluginContext(r, a.source, a.cacheTable(), fn)
	ctx, ok = a.preMiddleware(w, ctx)
	if !ok {
		return userID, r, ctx, false
	}
	return userID, r, ctx, true
}

// dbContext is the map passed to the database plugin.
// The table name is added for the call when cache did not already set it,
// so cache middleware still ignores writes that have no explicit table.
func (a restTableAction) dbContext(ctx map[string]any) map[string]any {
	if ctx == nil {
		ctx = map[string]any{}
	}
	if _, ok := ctx[easyrest.CtxTable]; ok || a.table == "" {
		return ctx
	}
	out := make(map[string]any, len(ctx)+1)
	maps.Copy(out, ctx)
	out[easyrest.CtxTable] = a.table
	return out
}

// restWrite is the plugin result and the response a REST write or state call should send.
type restWrite struct {
	returned map[string]any
	status   int
	body     any
	err      error
	noBody   bool
}

// finishContext gives the plugin context to REST post middleware and the response.
func (a restTableAction) finishContext(w http.ResponseWriter, r *http.Request, ctx map[string]any, out restWrite) {
	ctx = applyReturnedPluginContext(ctx, out.returned)
	status := out.status
	if out.err != nil {
		status = http.StatusInternalServerError
		var handlerErr *HandlerError
		if errors.As(out.err, &handlerErr) && handlerErr.Status != 0 {
			status = handlerErr.Status
		}
	}
	a.postHeaders(w, ctx, status)
	applyContextResponseHeaders(w, ctx)
	status = statusFromPluginContext(ctx, status)
	if out.err != nil {
		http.Error(w, out.err.Error(), status)
		return
	}
	if out.noBody {
		w.WriteHeader(status)
		return
	}
	a.writeContent(w, r, status, out.body)
}

func (a restTableAction) middlewareChain() []easyrest.MiddlewarePlugin {
	loaded := map[string]easyrest.MiddlewarePlugin{}
	if ptr := MiddlewarePlugins.Load(); ptr != nil {
		loaded = *ptr
	}
	cfg := currentConfig()
	chain := resolveMiddlewareNames(a.globalMW, *cfg, loaded)
	return append(chain, resolveMiddlewareNames(a.apiMW, *cfg, loaded)...)
}

func (a restTableAction) preMiddleware(w http.ResponseWriter, ctx map[string]any) (map[string]any, bool) {
	if ctx == nil {
		ctx = map[string]any{}
	}
	for _, plug := range a.middlewareChain() {
		next, status, err := plug.PreRequest(a.source, ctx)
		if next != nil {
			ctx = next
		}
		if status != nil && err == nil {
			applyContextResponseHeaders(w, ctx)
			w.WriteHeader(*status)
			return ctx, false
		}
		if err != nil || status != nil {
			code := http.StatusBadRequest
			if status != nil {
				code = *status
			}
			msg := "middleware error"
			if err != nil {
				msg = err.Error()
			}
			http.Error(w, msg, code)
			return ctx, false
		}
	}
	return ctx, true
}

func (a restTableAction) plugin(w http.ResponseWriter) (easyrest.DBPlugin, bool) {
	plugins := DbPlugins.Load()
	if plugins == nil {
		http.Error(w, "DB plugin not found", http.StatusNotFound)
		return nil, false
	}
	plug, ok := (*plugins)[a.source]
	if !ok {
		http.Error(w, "DB plugin not found", http.StatusNotFound)
		return nil, false
	}
	return plug, true
}

func restRowsOrEmpty(rows []map[string]any) []map[string]any {
	if rows == nil {
		return []map[string]any{}
	}
	return rows
}

func restListRows(rows []map[string]any) []map[string]any {
	rows = restRowsOrEmpty(rows)
	out := make([]map[string]any, len(rows))
	for i, row := range rows {
		copied := make(map[string]any, len(row))
		for key, value := range row {
			if value == nil {
				continue
			}
			copied[key] = value
		}
		out[i] = copied
	}
	return out
}

func compileRestFilters(filters map[string]config.RestFilter) []restQueryFilter {
	out := make([]restQueryFilter, 0, len(filters))
	for name, filter := range filters {
		field := filter.Field
		if field == "" {
			field = name
		}
		opCode := filter.Op
		if opCode == "" {
			opCode = "eq"
		}
		op, ok := AllowedOps[strings.ToLower(opCode)]
		if !ok {
			continue
		}
		out = append(out, restQueryFilter{name: name, field: field, op: op, not: filter.Not})
	}
	return out
}

func (a restTableAction) listWhere(r *http.Request) map[string]any {
	where := a.whereFromPath(r)
	query := r.URL.Query()
	for _, filter := range a.filters {
		values, ok := query[filter.name]
		if !ok || len(values) == 0 {
			continue
		}
		field := filter.field
		if filter.not {
			field = "NOT " + field
		}
		where[field] = map[string]any{filter.op: values[0]}
	}
	return where
}

func restListLimitOffset(r *http.Request, source string, pluginCtx map[string]any) (int, int, bool) {
	rangeHeader := r.Header.Get("Range")
	if strings.ToLower(r.Header.Get("Range-Unit")) == "items" && rangeHeader != "" {
		parts := strings.SplitN(rangeHeader, "-", 2)
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && start >= 0 && end >= start {
				return end - start + 1, start, true
			}
		}
	}
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	if limit == 0 {
		pageSize := preferPageSize(pluginCtx)
		if pageSize == 0 {
			cfg := currentConfig()
			pageSize = cfg.PluginMap[source].DefaultLimit
			if pageSize == 0 {
				pageSize = cfg.DefaultLimit
			}
		}
		limit = pageSize
	}
	return limit, offset, false
}

func restListOrdering(w http.ResponseWriter, raw string, allowed []string) ([]string, bool) {
	if raw == "" {
		return nil, true
	}
	known := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		known[field] = struct{}{}
	}
	parts := ParseCSV(raw)
	ordering := make([]string, 0, len(parts))
	for _, part := range parts {
		name := part
		desc := false
		if strings.HasPrefix(part, "-") {
			desc = true
			name = strings.TrimPrefix(part, "-")
		}
		if _, ok := known[name]; !ok {
			http.Error(w, "invalid ordering", http.StatusBadRequest)
			return nil, false
		}
		if desc {
			ordering = append(ordering, name+" DESC")
		} else {
			ordering = append(ordering, name)
		}
	}
	return ordering, true
}

func (a restTableAction) list(w http.ResponseWriter, r *http.Request) {
	userID, r, ctx, ok := a.openContext(w, r, true, "")
	if !ok {
		return
	}
	plug, ok := a.plugin(w)
	if !ok {
		return
	}
	ordering, ok := restListOrdering(w, r.URL.Query().Get("ordering"), a.selectFields)
	if !ok {
		return
	}
	pluginCtx := a.dbContext(ctx)
	limit, offset, usedHeader := restListLimitOffset(r, a.source, pluginCtx)
	where := a.listWhere(r)
	choice := a.contentChoice(r)
	serveContentRead(contentRead{
		w:            w,
		r:            r,
		dbKey:        a.source,
		pluginCtx:    pluginCtx,
		query:        r.URL.Query(),
		plug:         plug,
		renderer:     choice.Renderer,
		userID:       userID,
		table:        a.table,
		selectFields: a.selectFields,
		where:        where,
		ordering:     ordering,
		limit:        limit,
		offset:       offset,
		page:         restChunkSize(a.source, pluginCtx),
		paginate:     true,
		usedRange:    usedHeader,
		rangeHeader:  r.Header.Get("Range"),
		linkCtx:      pluginCtx,
		prepareRows: func(rows []map[string]any) error {
			return a.prepareStoredRows(r, rows)
		},
		fail: func(err error) {
			a.failRead(w, r, err)
		},
	})
}

func (a restTableAction) failRead(w http.ResponseWriter, r *http.Request, err error) {
	ctx := map[string]any{}
	for _, plug := range a.middlewareChain() {
		if _, postErr := plug.PostRequest(a.source, ctx); postErr != nil {
			stdlog.Printf("restapi post middleware: %v", postErr)
		}
	}
	choice := a.contentChoice(r)
	cw := newContentWriter(w, r, a.source, ctx, nil, choice.Renderer, true)
	_ = cw.WriteError(http.StatusInternalServerError, err.Error())
}

func (a restTableAction) contentChoice(r *http.Request) contentChoice {
	if a.contentReady {
		return negotiateContentLists(r, r.URL.Query(), a.parsers, a.renderers)
	}
	cfg := currentConfig()
	var pluginNames []string
	if plug, ok := cfg.PluginMap[a.source]; ok {
		pluginNames = plug.ContentHandlers
	}
	names := contentHandlerNames(a.endpointContent, a.appContent, pluginNames, cfg.DefaultContentHandlers)
	return negotiateContent(r, r.URL.Query(), contentRefsNamed(names))
}

func restChunkSize(source string, pluginCtx map[string]any) int {
	if n := preferPageSize(pluginCtx); n > 0 {
		return n
	}
	cfg := currentConfig()
	if plug, ok := cfg.PluginMap[source]; ok && plug.DefaultLimit > 0 {
		return plug.DefaultLimit
	}
	return cfg.DefaultLimit
}

func restPageURL(ctx map[string]any, r *http.Request, limit, offset int) string {
	query := r.URL.Query()
	query.Set("limit", strconv.Itoa(limit))
	query.Set("offset", strconv.Itoa(offset))
	path := r.URL.Path
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return easyrest.BuildAbsoluteUri(ctx, path)
}

func restListLinks(ctx map[string]any, r *http.Request, limit, offset int, total int64, hasTotal bool) (any, any) {
	var next, prev any
	if offset > 0 {
		prevOffset := max(offset-limit, 0)
		prev = restPageURL(ctx, r, limit, prevOffset)
	}
	if hasTotal && limit > 0 && int64(offset)+int64(limit) < total {
		next = restPageURL(ctx, r, limit, offset+limit)
	}
	return next, prev
}

func (a restTableAction) prepareWriteRow(w http.ResponseWriter, r *http.Request, includePath bool) (map[string]any, bool) {
	row, ok := a.parseWriteObject(w, r)
	if !ok {
		return nil, false
	}
	if a.rejectUnknownWriteKeys(w, row) {
		return nil, false
	}
	a.omitReadOnly(row)
	if includePath {
		for name, value := range a.pathValues(r) {
			row[name] = value
		}
	}
	return row, true
}

func (a restTableAction) create(w http.ResponseWriter, r *http.Request) {
	_, r, ctx, ok := a.openContext(w, r, false, "")
	if !ok {
		return
	}
	plug, ok := a.plugin(w)
	if !ok {
		return
	}
	row, ok := a.prepareWriteRow(w, r, true)
	if !ok {
		return
	}
	rows, returned, err := plug.TableCreate("", a.table, []map[string]any{row}, a.dbContext(ctx))
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{returned: returned, err: err})
		return
	}
	copied := make([]map[string]any, len(restRowsOrEmpty(rows)))
	copy(copied, restRowsOrEmpty(rows))
	if err := a.prepareStoredRows(r, copied); err != nil {
		a.finishContext(w, r, ctx, restWrite{err: err})
		return
	}
	a.finishContext(w, r, ctx, restWrite{returned: returned, status: http.StatusCreated, body: copied})
}

func (a restTableAction) callCreate(w http.ResponseWriter, r *http.Request) {
	_, r, ctx, ok := a.openContext(w, r, false, a.table)
	if !ok {
		return
	}
	plug, ok := a.plugin(w)
	if !ok {
		return
	}
	row, ok := a.prepareWriteRow(w, r, true)
	if !ok {
		return
	}
	result, returned, err := plug.CallFunction("", a.table, row, a.dbContext(ctx))
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{returned: returned, err: err})
		return
	}
	if obj, ok := result.(map[string]any); ok {
		presented, presentErr := a.presentObject(r, obj)
		if presentErr != nil {
			a.finishContext(w, r, ctx, restWrite{err: presentErr})
			return
		}
		a.finishContext(w, r, ctx, restWrite{returned: returned, status: http.StatusCreated, body: presented})
		return
	}
	a.finishContext(w, r, ctx, restWrite{returned: returned, status: http.StatusCreated, body: result})
}

func (a restTableAction) detailCall(w http.ResponseWriter, r *http.Request) {
	_, r, ctx, ok := a.openContext(w, r, false, "")
	if !ok {
		return
	}
	plug, ok := a.plugin(w)
	if !ok {
		return
	}
	row, ok := a.parseWriteObject(w, r)
	if !ok {
		return
	}
	if a.rejectUnknownWriteKeys(w, row) {
		return
	}
	a.omitReadOnly(row)
	for name, value := range a.pathValues(r) {
		row[name] = value
	}
	if a.includePK {
		pk := a.primaryKey
		if pk == "" {
			pk = "id"
		}
		row[pk] = chi.URLParam(r, "id")
	}
	result, returned, err := plug.CallFunction("", a.callFunc, row, a.dbContext(ctx))
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{returned: returned, err: err})
		return
	}
	a.writeFuncResult(w, r, ctx, returned, result)
}

func (a restTableAction) stateGet(w http.ResponseWriter, r *http.Request) {
	_, r, ctx, ok := a.openContext(w, r, true, "")
	if !ok {
		return
	}
	plug, ok := a.plugin(w)
	if !ok {
		return
	}
	if a.callFunc != "" {
		a.stateFuncGet(w, r, plug, ctx)
		return
	}
	rows, returned, err := plug.TableGet("", a.table, []string{a.sourceField}, a.detailWhere(r), nil, nil, 0, 0, a.dbContext(ctx))
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{returned: returned, err: err})
		return
	}
	if len(rows) == 0 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if len(rows) != 1 {
		http.Error(w, "expected one row", http.StatusBadRequest)
		return
	}
	body, ok := restCallResponse(a.props, rows[0][a.sourceField])
	if !ok {
		http.Error(w, "source field must be an object", http.StatusInternalServerError)
		return
	}
	presented, err := a.presentObject(r, body)
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{err: err})
		return
	}
	a.finishContext(w, r, ctx, restWrite{returned: returned, status: http.StatusOK, body: presented})
}

func (a restTableAction) stateFuncGet(w http.ResponseWriter, r *http.Request, plug easyrest.DBPlugin, ctx map[string]any) {
	data := make(map[string]any, len(a.pathParams))
	for name, value := range a.pathValues(r) {
		data[name] = value
	}
	result, returned, err := plug.CallFunction("", a.callFunc, data, a.dbContext(ctx))
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{returned: returned, err: err})
		return
	}
	a.writeFuncResult(w, r, ctx, returned, result)
}

func (a restTableAction) writeFuncResult(w http.ResponseWriter, r *http.Request, ctx, returned map[string]any, result any) {
	body, ok := restCallResponse(a.props, result)
	if !ok {
		http.Error(w, "function result must be an object", http.StatusInternalServerError)
		return
	}
	presented, err := a.presentObject(r, body)
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{err: err})
		return
	}
	a.finishContext(w, r, ctx, restWrite{returned: returned, status: http.StatusOK, body: presented})
}

func (a restTableAction) statePut(w http.ResponseWriter, r *http.Request) {
	_, r, ctx, ok := a.openContext(w, r, false, "")
	if !ok {
		return
	}
	plug, ok := a.plugin(w)
	if !ok {
		return
	}
	if a.callFunc != "" {
		row, ready := a.prepareWriteRow(w, r, true)
		if !ready {
			return
		}
		result, returned, err := plug.CallFunction("", a.callFunc, row, a.dbContext(ctx))
		if err != nil {
			a.finishContext(w, r, ctx, restWrite{returned: returned, err: err})
			return
		}
		a.writeFuncResult(w, r, ctx, returned, result)
		return
	}
	row, ok := a.prepareWriteRow(w, r, false)
	if !ok {
		return
	}
	updated, returned, err := plug.TableUpdate("", a.table, map[string]any{a.sourceField: row}, a.detailWhere(r), a.dbContext(ctx))
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{returned: returned, err: err})
		return
	}
	a.finishContext(w, r, ctx, restWrite{returned: returned, status: http.StatusOK, body: map[string]any{"updated": updated}})
}

func restCallResponse(fields map[string]any, result any) (map[string]any, bool) {
	obj, ok := result.(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for key, raw := range fields {
		prop, _ := raw.(map[string]any)
		if prop["writeOnly"] == true {
			continue
		}
		if value, exists := obj[key]; exists {
			out[key] = value
		}
	}
	return out, true
}

func (a restTableAction) retrieve(w http.ResponseWriter, r *http.Request) {
	userID, r, ctx, ok := a.openContext(w, r, true, "")
	if !ok {
		return
	}
	plug, ok := a.plugin(w)
	if !ok {
		return
	}
	stripPreferCount(ctx)
	dbCtx := a.dbContext(ctx)
	rows, returned, err := plug.TableGet(userID, a.table, a.selectFields, a.detailWhere(r), nil, nil, 2, 0, dbCtx)
	if err != nil {
		a.finishContext(w, r, dbCtx, restWrite{returned: returned, err: err})
		return
	}
	if len(rows) == 0 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if len(rows) != 1 {
		http.Error(w, "expected one row", http.StatusBadRequest)
		return
	}
	presented, err := a.presentObject(r, rows[0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.finishContext(w, r, dbCtx, restWrite{returned: returned, status: http.StatusOK, body: presented})
}

func (a restTableAction) writeContent(w http.ResponseWriter, r *http.Request, status int, v any) {
	choice := a.contentChoice(r)
	cw := newContentWriter(w, r, a.source, nil, nil, choice.Renderer, false)
	if err := cw.Write(status, v, nil); err != nil {
		stdlog.Printf("restapi write: %v", err)
	}
}

func (a restTableAction) postHeaders(w http.ResponseWriter, ctx map[string]any, status int) {
	setHandlerStatus(ctx, status)
	for _, plug := range a.middlewareChain() {
		headers, err := plug.PostRequest(a.source, ctx)
		if err != nil {
			stdlog.Printf("restapi post middleware: %v", err)
		}
		for name, value := range headers {
			if name == "" {
				continue
			}
			w.Header().Add(name, value)
		}
	}
}

func (a restTableAction) update(w http.ResponseWriter, r *http.Request) {
	_, r, ctx, ok := a.openContext(w, r, false, "")
	if !ok {
		return
	}
	plug, ok := a.plugin(w)
	if !ok {
		return
	}
	row, ok := a.prepareWriteRow(w, r, false)
	if !ok {
		return
	}
	updated, returned, err := plug.TableUpdate("", a.table, row, a.detailWhere(r), a.dbContext(ctx))
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{returned: returned, err: err})
		return
	}
	a.finishContext(w, r, ctx, restWrite{returned: returned, status: http.StatusOK, body: map[string]any{"updated": updated}})
}

func (a restTableAction) destroy(w http.ResponseWriter, r *http.Request) {
	_, _, ctx, ok := a.openContext(w, r, false, "")
	if !ok {
		return
	}
	plug, ok := a.plugin(w)
	if !ok {
		return
	}
	_, returned, err := plug.TableDelete("", a.table, a.detailWhere(r), a.dbContext(ctx))
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{returned: returned, err: err})
		return
	}
	a.finishContext(w, r, ctx, restWrite{returned: returned, status: http.StatusNoContent, noBody: true})
}

func (a restTableAction) storageKinds() map[string]storageValueKind {
	return storageFieldsOf(a.fieldProps)
}

func (a restTableAction) hasBinaryField() bool {
	for _, kind := range a.storageKinds() {
		if kind == storageValueBinary || kind == storageValueBinaryList {
			return true
		}
	}
	return false
}

func (a restTableAction) allowedContent() []contentPluginRef {
	if a.contentReady {
		return a.parsers
	}
	return contentRefsNamed(contentHandlerNames(a.endpointContent, a.appContent, a.pluginContentNames(), currentConfig().DefaultContentHandlers))
}

func (a restTableAction) readParsed(w http.ResponseWriter, r *http.Request, expectArray bool) (any, error) {
	cfg := currentConfig()
	if cfg.Server.MaxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.Server.MaxBodySize)
	}
	return readParsedBody(r, a.contentChoice(r), expectArray)
}

func (a restTableAction) pluginContentNames() []string {
	cfg := currentConfig()
	if plug, ok := cfg.PluginMap[a.source]; ok {
		return plug.ContentHandlers
	}
	return nil
}

func (a restTableAction) parseWriteObject(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	var parsed any
	var files []multipartFile
	var err error
	if a.hasBinaryField() && isMultipart(r.Header.Get("Content-Type")) {
		cfg := currentConfig()
		if cfg.Server.MaxBodySize > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.Server.MaxBodySize)
		}
		parsed, files, err = readMultipart(r, a.allowedContent())
	} else {
		parsed, err = a.readParsed(w, r, false)
	}
	if err != nil {
		http.Error(w, err.Error(), storageStatus(err))
		return nil, false
	}
	row, ok := parsed.(map[string]any)
	if !ok {
		http.Error(w, "Invalid data format", http.StatusBadRequest)
		return nil, false
	}
	if len(a.storageKinds()) == 0 {
		return row, true
	}
	ref, ok := storagePluginByName(a.storageName)
	if !ok {
		http.Error(w, fmt.Sprintf("storage plugin %q is not loaded", a.storageName), http.StatusInternalServerError)
		return nil, false
	}
	reqCtx := map[string]any{"request": requestPublic(r)}
	if err := storeObjectFields(r.Context(), row, files, a.storageKinds(), ref, a.table, reqCtx); err != nil {
		http.Error(w, err.Error(), storageStatus(err))
		return nil, false
	}
	return row, true
}

func (a restTableAction) presentObject(r *http.Request, obj map[string]any) (map[string]any, error) {
	copied := cloneRow(obj)
	if len(a.storageKinds()) == 0 {
		return copied, nil
	}
	ref, ok := storagePluginByName(a.storageName)
	if !ok {
		return nil, fmt.Errorf("storage plugin %q is not loaded", a.storageName)
	}
	if err := expandStoredObject(r, copied, a.storageKinds(), ref); err != nil {
		return nil, err
	}
	return copied, nil
}

func (a restTableAction) prepareStoredRows(r *http.Request, rows []map[string]any) error {
	for i, row := range rows {
		presented, err := a.presentObject(r, row)
		if err != nil {
			return err
		}
		rows[i] = presented
	}
	return nil
}

func restAssignStorage(action restTableAction, appStorage, endpointStorage, actionStorage, fallback string, props map[string]any) restTableAction {
	action.storageName = restStorageName(actionStorage, endpointStorage, appStorage, fallback)
	if props == nil {
		props = map[string]any{}
	}
	action.fieldProps = props
	return action
}

func restModelProps(model map[string]any) map[string]any {
	props, _ := model["properties"].(map[string]any)
	if props == nil {
		return map[string]any{}
	}
	return props
}

func restReadProperties(props map[string]any, inline bool) map[string]any {
	out := make(map[string]any, len(props))
	format := "uri"
	if inline {
		format = "base64"
	}
	for name, raw := range props {
		out[name] = restReadProperty(raw, format)
	}
	return out
}

func restReadProperty(raw any, format string) any {
	prop, ok := raw.(map[string]any)
	if !ok {
		return raw
	}
	out := maps.Clone(prop)
	if out["type"] == "array" {
		items, _ := out["items"].(map[string]any)
		if items == nil {
			return out
		}
		copied := maps.Clone(items)
		if storageScalarKind(copied) != storageValueNone {
			copied["format"] = format
		}
		out["items"] = copied
		return out
	}
	if storageScalarKind(out) != storageValueNone {
		out["format"] = format
	}
	return out
}

func restRewriteSchema(schema map[string]any, inline bool) map[string]any {
	out := maps.Clone(schema)
	props, _ := schema["properties"].(map[string]any)
	out["properties"] = restReadProperties(props, inline)
	return out
}

func restFieldsNamePK(fields map[string]any, pk string) bool {
	_, ok := fields[pk]
	return ok
}

func restPropWriteKeys(fields map[string]any) map[string]struct{} {
	if fields == nil {
		return nil
	}
	keys := make(map[string]struct{}, len(fields))
	for field := range fields {
		keys[field] = struct{}{}
	}
	return keys
}

func restFlagKeys(fields map[string]any, flag string) map[string]struct{} {
	keys := map[string]struct{}{}
	for field, raw := range fields {
		prop, _ := raw.(map[string]any)
		if prop[flag] == true {
			keys[field] = struct{}{}
		}
	}
	if len(keys) == 0 {
		return nil
	}
	return keys
}

func restReadOnlyKeys(ep config.RestEndpoint, name string) map[string]struct{} {
	act, ok := ep.Actions[name]
	if !ok {
		return nil
	}
	keys := map[string]struct{}{}
	for field, raw := range act.ExtraFields {
		prop, _ := raw.(map[string]any)
		if prop["readOnly"] == true {
			keys[field] = struct{}{}
		}
	}
	if len(keys) == 0 {
		return nil
	}
	return keys
}

func restWriteKeys(ep config.RestEndpoint, name string) map[string]struct{} {
	act, ok := ep.Actions[name]
	// Omitted fields means the table columns are not filtered here.
	// extra_fields alone must not turn that into an allowlist of only those keys.
	if !ok || act.Fields == nil {
		return nil
	}
	keys := make(map[string]struct{}, len(act.Fields)+len(act.ExtraFields))
	for _, field := range act.Fields {
		keys[field] = struct{}{}
	}
	for field := range act.ExtraFields {
		keys[field] = struct{}{}
	}
	return keys
}

func (a restTableAction) isPathParam(name string) bool {
	return slices.Contains(a.pathParams, name)
}

func (a restTableAction) omitReadOnly(row map[string]any) {
	for key := range row {
		if _, ok := a.readOnly[key]; !ok || a.isPathParam(key) {
			continue
		}
		delete(row, key)
	}
}

func (a restTableAction) rejectUnknownWriteKeys(w http.ResponseWriter, row map[string]any) bool {
	if a.writeKeys == nil {
		return false
	}
	pathSet := make(map[string]struct{}, len(a.pathParams))
	for _, name := range a.pathParams {
		pathSet[name] = struct{}{}
	}
	for key := range row {
		if _, ok := a.writeKeys[key]; ok {
			continue
		}
		if _, ok := pathSet[key]; ok {
			continue
		}
		http.Error(w, "unknown field "+key, http.StatusBadRequest)
		return true
	}
	return false
}

func (a restTableAction) cacheTable() string {
	if !a.cache {
		return ""
	}
	return a.table
}

func restExplicitTable(ep config.RestEndpoint, name string) string {
	if act, ok := ep.Actions[name]; ok && act.Table != "" && act.Type != "func" {
		return act.Table
	}
	return ep.Table
}

func restActionTable(ep config.RestEndpoint, fallback, name string) string {
	if act, ok := ep.Actions[name]; ok && act.Table != "" && act.Type != "func" {
		return act.Table
	}
	return fallback
}

func restDisplayName(name string) (singular, plural string) {
	parts := strings.Split(name, "_")
	words := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		words = append(words, strings.ToUpper(part[:1])+part[1:])
	}
	if len(words) == 0 {
		return name, name
	}
	plural = strings.Join(words, " ")
	last := words[len(words)-1]
	if len(last) > 1 && strings.HasSuffix(last, "s") && !strings.HasSuffix(last, "ss") && !strings.HasSuffix(last, "us") && !strings.HasSuffix(last, "is") {
		words[len(words)-1] = last[:len(last)-1]
	}
	singular = strings.Join(words, " ")
	return singular, plural
}

func restLabel(action, resourceName, explicit string) string {
	if explicit != "" {
		return explicit
	}
	singular, plural := restDisplayName(resourceName)
	switch action {
	case "create":
		return "New " + singular
	case "retrieve":
		return singular
	case "update":
		return "Update " + singular
	case "destroy":
		return "Delete " + singular
	default:
		return plural
	}
}

func restOperation(ep config.RestEndpoint, action, resource string) map[string]any {
	act := ep.Actions[action]
	description := ep.Description
	if act.Description != "" {
		description = act.Description
	}
	return map[string]any{
		"description": description,
		"x-label":     restLabel(action, resource, act.Label),
	}
}

func restListOperation(ep config.RestEndpoint, resource string, tables map[string]any, table string, fields []string, extra map[string]any, inline bool) map[string]any {
	op := restOperation(ep, "list", resource)
	enum := make([]string, 0, len(fields)*2)
	for _, field := range fields {
		enum = append(enum, field, "-"+field)
	}
	op["parameters"] = []Parameter{
		{Name: "limit", In: "query", Description: "Maximum number of records to return", Type: "integer"},
		{Name: "offset", In: "query", Description: "Number of records to skip", Type: "integer"},
		{
			Name:             "ordering",
			In:               "query",
			Description:      "Comma-separated ordering fields",
			Type:             "array",
			CollectionFormat: "csv",
			Items:            map[string]any{"type": "string", "enum": enum},
		},
		{Name: "Range", In: "header", Description: "Item range start-end", Type: "string"},
		{Name: "Range-Unit", In: "header", Description: "Range unit", Type: "string"},
	}
	tableSchema, _ := tables[table].(map[string]any)
	columns, _ := tableSchema["properties"].(map[string]any)
	props := map[string]any{}
	for _, field := range fields {
		if col, ok := columns[field]; ok {
			props[field] = col
			continue
		}
		props[field] = map[string]any{"type": "string"}
	}
	maps.Copy(props, extra)
	props = restReadProperties(props, inline)
	op["responses"] = map[string]any{
		"200": map[string]any{
			"description": "Successful response",
			"schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"count":    map[string]any{"type": "integer"},
					"next":     map[string]any{"type": "string"},
					"previous": map[string]any{"type": "string"},
					"results": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "object", "properties": props},
					},
				},
			},
		},
	}
	return op
}

func restCallSchemas(fields map[string]any) (map[string]any, map[string]any) {
	requestProps := map[string]any{}
	responseProps := map[string]any{}
	for key, raw := range fields {
		prop, _ := raw.(map[string]any)
		if prop["readOnly"] != true {
			requestProps[key] = raw
		}
		if prop["writeOnly"] != true {
			responseProps[key] = raw
		}
	}
	request := map[string]any{"type": "object", "properties": requestProps}
	response := map[string]any{"type": "object", "properties": responseProps}
	return request, response
}

func restCallOperation(fields map[string]any) map[string]any {
	request, response := restCallSchemas(fields)
	return map[string]any{
		"parameters": []Parameter{{
			Name:     "body",
			In:       "body",
			Required: true,
			Schema:   request,
		}},
		"responses": map[string]any{
			"200": map[string]any{
				"description": "Successful response",
				"schema":      response,
			},
		},
	}
}

func restAuthDefs() map[string]map[string]any {
	loaded := AuthSecurityDefinitions.Load()
	if loaded == nil {
		return map[string]map[string]any{}
	}
	return *loaded
}

func restSecurityDefinitions(defs map[string]map[string]any, listed *[]string) map[string]any {
	out := map[string]any{}
	for _, name := range restAuthNames(listed, defs) {
		if schema, ok := defs[name]; ok {
			out[name] = schema
		}
	}
	return out
}

func restAuthNames(listed *[]string, defs map[string]map[string]any) []string {
	if listed != nil {
		return *listed
	}
	names := make([]string, 0, len(defs))
	for name := range defs {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

type restOpAuth struct {
	auth   *[]string
	scopes []string
	read   bool
}

type restOpSecurity struct {
	public         bool
	check          bool
	endpoint       string
	read           bool
	actionAuth     *[]string
	endpointAuth   *[]string
	appAuth        *[]string
	actionScopes   []string
	endpointScopes []string
	defs           map[string]map[string]any
}

func restOperationSecurity(in restOpSecurity) []map[string]any {
	names := restEffectiveAuth(in)
	if in.public || len(names) == 0 {
		return []map[string]any{}
	}
	scopes := restEffectiveScopes(in)
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		def, ok := in.defs[name]
		if !ok {
			continue
		}
		req := []string{}
		if def["type"] == "oauth2" {
			req = scopes
		}
		out = append(out, map[string]any{name: req})
	}
	return out
}

func restEffectiveAuth(in restOpSecurity) []string {
	if in.actionAuth != nil {
		return *in.actionAuth
	}
	if in.endpointAuth != nil {
		return *in.endpointAuth
	}
	if in.appAuth != nil {
		return *in.appAuth
	}
	return restAuthNames(nil, in.defs)
}

func restEffectiveScopes(in restOpSecurity) []string {
	if in.public || !in.check {
		return []string{}
	}
	return restRequiredScopes(in.actionScopes, in.endpointScopes, in.endpoint, in.read)
}

func restRequiredScopes(action, endpoint []string, endpointName string, read bool) []string {
	if len(action) > 0 {
		return action
	}
	if len(endpoint) > 0 {
		return endpoint
	}
	suffix := "write"
	if read {
		suffix = "read"
	}
	return []string{endpointName + "-" + suffix}
}

func restJoinPath(prefix, urlPath, suffix string, noSlash bool) string {
	parts := make([]string, 0, 4)
	if trimmed := strings.Trim(prefix, "/"); trimmed != "" {
		parts = append(parts, trimmed)
	}
	if trimmed := strings.Trim(urlPath, "/"); trimmed != "" {
		parts = append(parts, trimmed)
	}
	for _, seg := range strings.Split(suffix, "/") {
		if seg != "" {
			parts = append(parts, seg)
		}
	}
	path := "/" + strings.Join(parts, "/")
	if noSlash {
		return path
	}
	return path + "/"
}

func restActionNoSlash(ep config.RestEndpoint, action string) bool {
	if ep.NoTrailingSlash {
		return true
	}
	if ep.Actions == nil {
		return false
	}
	return ep.Actions[action].NoTrailingSlash
}

func restPutOperation(paths map[string]any, path, method string, op map[string]any) {
	item, _ := paths[path].(map[string]any)
	if item == nil {
		item = map[string]any{}
		paths[path] = item
	}
	item[method] = op
}

func restEndpointInvalid(name, urlPath, source string) string {
	if !config.RestNameOK(name) {
		return "invalid name"
	}
	if !config.RestURLOK(urlPath) {
		return "invalid url"
	}
	if source == "" {
		return "missing source"
	}
	plugins := DbPlugins.Load()
	if plugins == nil {
		return "plugin not loaded"
	}
	if _, ok := (*plugins)[source]; !ok {
		return "plugin not loaded"
	}
	return ""
}

func restActionEnabled(ep config.RestEndpoint, name string) bool {
	if len(ep.Actions) == 0 {
		return true
	}
	_, ok := ep.Actions[name]
	return ok
}

func pluginTableSchemas(source string, cache map[string]map[string]any) map[string]any {
	if tables, ok := cache[source]; ok {
		return tables
	}
	tables := map[string]any{}
	cache[source] = tables
	plugins := DbPlugins.Load()
	if plugins == nil {
		return tables
	}
	plug, ok := (*plugins)[source]
	if !ok {
		return tables
	}
	raw, _, err := plug.GetSchema(nil)
	if err != nil {
		return tables
	}
	schema, _ := raw.(map[string]any)
	if got, ok := schema["tables"].(map[string]any); ok {
		maps.Copy(tables, got)
	}
	if got, ok := schema["views"].(map[string]any); ok {
		for name, def := range got {
			if _, exists := tables[name]; !exists {
				tables[name] = def
			}
		}
	}
	return tables
}

func restSelectFields(tables map[string]any, table string, fields []string) []string {
	tableSchema, _ := tables[table].(map[string]any)
	columns, _ := tableSchema["properties"].(map[string]any)
	if fields != nil {
		out := make([]string, 0, len(fields))
		for _, field := range fields {
			if _, ok := columns[field]; ok {
				out = append(out, field)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	if len(columns) == 0 {
		return nil
	}
	out := make([]string, 0, len(columns))
	for name := range columns {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func restModel(tables map[string]any, table string, act config.RestAction, isFunc bool) map[string]any {
	props := map[string]any{}
	if !isFunc {
		tableSchema, _ := tables[table].(map[string]any)
		columns, _ := tableSchema["properties"].(map[string]any)
		fields := act.Fields
		if fields == nil {
			fields = make([]string, 0, len(columns))
			for name := range columns {
				fields = append(fields, name)
			}
		}
		for _, field := range fields {
			if col, ok := columns[field]; ok {
				props[field] = col
			}
		}
	}
	maps.Copy(props, act.ExtraFields)
	model := map[string]any{"type": "object"}
	if len(props) > 0 {
		model["properties"] = props
	}
	return model
}

type restListedAPI struct {
	Name   string
	Format string
}

type restSpecSnapshot struct {
	Docs map[string]map[string]any
	APIs []restListedAPI
}

var restSpecs atomic.Pointer[restSpecSnapshot]

func bindRestContent(action restTableAction, cfg *config.Config, app config.RestAPIApp, ep config.RestEndpoint, parsers, renderers *[]string) restTableAction {
	var pluginNames, defaults []string
	var appParsers, appRenderers *[]string
	if cfg != nil {
		defaults = cfg.DefaultContentHandlers
		appParsers = cfg.Application.Parsers
		appRenderers = cfg.Application.Renderers
		if plug, ok := cfg.PluginMap[action.source]; ok {
			pluginNames = plug.ContentHandlers
		}
	}
	action.parsers, action.renderers = restContentRefs([]contentLevel{
		{parsers: parsers, renderers: renderers},
		{parsers: ep.Parsers, renderers: ep.Renderers, handlers: ep.ContentHandlers},
		{parsers: app.Parsers, renderers: app.Renderers, handlers: app.ContentHandlers},
		{parsers: appParsers, renderers: appRenderers},
	}, pluginNames, defaults)
	action.contentReady = true
	return action
}

func restContentRefs(levels []contentLevel, pluginNames, defaults []string) ([]contentPluginRef, []contentPluginRef) {
	parserNames, rendererNames := resolveContentNames(levels, pluginNames, defaults)
	return contentDirectionRefs(contentRefsNamed(parserNames), false), contentDirectionRefs(contentRefsNamed(rendererNames), true)
}

func compileRestRouter(cfg *config.Config) http.Handler {
	r := chi.NewRouter()
	snap := &restSpecSnapshot{Docs: map[string]map[string]any{}}
	if cfg == nil {
		restSpecs.Store(snap)
		return r
	}
	defaults := cfg.DefaultContentHandlers
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		names := withHTMLContent(contentHandlerNames(nil, nil, nil, defaults))
		writeSwagger(w, req, "", nil, names, false, restCatalogModel(req), swaggerPageCtx(req, easyrest.SwaggerCatalog, ""))
	})
	apiNames := make([]string, 0, len(cfg.RestAPI))
	for name := range cfg.RestAPI {
		apiNames = append(apiNames, name)
	}
	slices.Sort(apiNames)
	tableCache := map[string]map[string]any{}
	authDefs := restAuthDefs()
	for _, apiName := range apiNames {
		app := cfg.RestAPI[apiName]
		spec := map[string]any{
			"swagger":             "2.0",
			"basePath":            "/restapi/" + apiName,
			"paths":               map[string]any{},
			"definitions":         map[string]any{},
			"securityDefinitions": restSecurityDefinitions(authDefs, app.Auth),
		}
		api := apiName
		appHandlers := app.ContentHandlers
		formatNames := contentHandlerNames(nil, appHandlers, nil, defaults)
		snap.Docs[api] = spec
		snap.APIs = append(snap.APIs, restListedAPI{Name: api, Format: firstDocumentFormat(formatNames)})
		r.Get("/"+api+"/", func(w http.ResponseWriter, req *http.Request) {
			current := restSpecs.Load()
			var doc any
			if current != nil {
				doc = current.Docs[api]
			}
			names := withHTMLContent(contentHandlerNames(nil, appHandlers, nil, defaults))
			format := firstDocumentFormat(names)
			writeSwagger(w, req, "", nil, names, false, doc, swaggerPageCtx(req, easyrest.SwaggerDocument, absoluteFormatURL(req, format)))
		})
		for key, ep := range app.Endpoints {
			source := ep.Source
			if source == "" {
				source = app.Source
			}
			name := ep.Name
			if name == "" {
				name = key
			}
			urlPath := ep.URL
			if urlPath == "" {
				urlPath = name
			}
			if reason := restEndpointInvalid(name, urlPath, source); reason != "" {
				stdlog.Printf("restapi %s %s skipped: %s", apiName, key, reason)
				continue
			}
			table := ep.Table
			if table == "" {
				table = name
			}
			pk := ep.PrimaryKey
			if pk == "" {
				pk = "id"
			}
			action := restTableAction{
				source:          source,
				table:           table,
				primaryKey:      pk,
				pathParams:      restPathParamNames(urlPath),
				filters:         compileRestFilters(ep.Filters),
				endpointName:    name,
				checkScope:      cfg.CheckScope,
				public:          app.Public || ep.Public,
				globalMW:        cfg.GlobalRequestMiddlewares,
				apiMW:           app.Middlewares,
				endpointContent: ep.ContentHandlers,
				appContent:      app.ContentHandlers,
				appAuth:         app.Auth,
				appAnon:         app.AnonClaims,
				endpointAuth:    ep.Auth,
				endpointScopes:  ep.RequiredScopes,
			}
			action = bindRestContent(action, cfg, app, ep, nil, nil)
			defs := spec["definitions"].(map[string]any)
			tables := pluginTableSchemas(source, tableCache)
			if restActionEnabled(ep, "create") {
				act := ep.Actions["create"]
				modelTable := restActionTable(ep, table, "create")
				defs[name+"_create"] = restModel(tables, modelTable, act, act.Type == "func")
			}
			paths := spec["paths"].(map[string]any)
			isPublic := app.Public || ep.Public
			put := func(path, method string, op map[string]any, act restOpAuth) {
				op["security"] = restOperationSecurity(restOpSecurity{
					public:         isPublic,
					check:          cfg.CheckScope,
					endpoint:       name,
					read:           act.read,
					actionAuth:     act.auth,
					endpointAuth:   ep.Auth,
					appAuth:        app.Auth,
					actionScopes:   act.scopes,
					endpointScopes: ep.RequiredScopes,
					defs:           authDefs,
				})
				restPutOperation(paths, path, method, op)
			}
			route := func(suffix string, noSlash bool) string {
				return restJoinPath(apiName, urlPath, suffix, noSlash)
			}
			specRoute := func(suffix string, noSlash bool) string {
				return restJoinPath("", urlPath, suffix, noSlash)
			}
			if restActionEnabled(ep, "list") {
				listAct := ep.Actions["list"]
				listAction := action
				listAction.table = restActionTable(ep, table, "list")
				listAction.cache = source != "" && restExplicitTable(ep, "list") != ""
				listAction.selectFields = restSelectFields(tables, listAction.table, listAct.Fields)
				listAction = restAssignStorage(listAction, app.Storage, ep.Storage, listAct.Storage, cfg.DefaultStoragePlugin, restModelProps(restModel(tables, listAction.table, listAct, false)))
				listAction.actionAuth = listAct.Auth
				listAction.actionScopes = listAct.RequiredScopes
				listAction = bindRestContent(listAction, cfg, app, ep, listAct.Parsers, listAct.Renderers)
				noSlash := restActionNoSlash(ep, "list")
				if listAct.Handler != "" {
					listAction.handler = listAct.Handler
					r.Get(route("", noSlash), listAction.serveGo)
				} else {
					r.Get(route("", noSlash), listAction.list)
				}
				listOp := restListOperation(
					ep,
					name,
					tables,
					listAction.table,
					listAction.selectFields,
					listAct.ExtraFields,
					storageInline(listAction.storageName),
				)
				put(specRoute("", noSlash), "get", listOp, restOpAuth{
					auth:   listAct.Auth,
					scopes: listAct.RequiredScopes,
					read:   true,
				})
			}
			if restActionEnabled(ep, "create") {
				createAct := ep.Actions["create"]
				createAction := action
				createAction.table = restActionTable(ep, table, "create")
				createAction.writeKeys = restWriteKeys(ep, "create")
				createAction.readOnly = restReadOnlyKeys(ep, "create")
				createAction = restAssignStorage(createAction, app.Storage, ep.Storage, createAct.Storage, cfg.DefaultStoragePlugin, restModelProps(restModel(tables, createAction.table, createAct, createAct.Type == "func")))
				createAction.actionAuth = createAct.Auth
				createAction.actionScopes = createAct.RequiredScopes
				createAction = bindRestContent(createAction, cfg, app, ep, createAct.Parsers, createAct.Renderers)
				noSlash := restActionNoSlash(ep, "create")
				if createAct.Handler != "" {
					createAction.handler = createAct.Handler
					createAction.successStatus = http.StatusCreated
					r.Post(route("", noSlash), createAction.serveGo)
				} else if ep.Actions["create"].Type == "func" {
					r.Post(route("", noSlash), createAction.callCreate)
				} else {
					r.Post(route("", noSlash), createAction.create)
				}
				put(specRoute("", noSlash), "post", restOperation(ep, "create", name), restOpAuth{
					auth:   createAct.Auth,
					scopes: createAct.RequiredScopes,
				})
			}
			if restActionEnabled(ep, "retrieve") {
				retrieveAct := ep.Actions["retrieve"]
				retrieveAction := action
				retrieveAction.table = restActionTable(ep, table, "retrieve")
				retrieveAction.cache = source != "" && restExplicitTable(ep, "retrieve") != ""
				retrieveAction.selectFields = restSelectFields(tables, retrieveAction.table, retrieveAct.Fields)
				retrieveAction = restAssignStorage(retrieveAction, app.Storage, ep.Storage, retrieveAct.Storage, cfg.DefaultStoragePlugin, restModelProps(restModel(tables, retrieveAction.table, retrieveAct, false)))
				retrieveAction.actionAuth = retrieveAct.Auth
				retrieveAction.actionScopes = retrieveAct.RequiredScopes
				retrieveAction = bindRestContent(retrieveAction, cfg, app, ep, retrieveAct.Parsers, retrieveAct.Renderers)
				noSlash := restActionNoSlash(ep, "retrieve")
				if retrieveAct.Handler != "" {
					retrieveAction.handler = retrieveAct.Handler
					r.Get(route("{id}", noSlash), retrieveAction.serveGo)
				} else {
					r.Get(route("{id}", noSlash), retrieveAction.retrieve)
				}
				retrieveOp := restOperation(ep, "retrieve", name)
				retrieveOp["responses"] = map[string]any{
					"200": map[string]any{
						"description": "Successful response",
						"schema":      restRewriteSchema(map[string]any{"type": "object", "properties": retrieveAction.fieldProps}, storageInline(retrieveAction.storageName)),
					},
				}
				put(specRoute("{id}", noSlash), "get", retrieveOp, restOpAuth{
					auth:   retrieveAct.Auth,
					scopes: retrieveAct.RequiredScopes,
					read:   true,
				})
			}
			if restActionEnabled(ep, "update") {
				updateAct := ep.Actions["update"]
				updateAction := action
				updateAction.table = restActionTable(ep, table, "update")
				updateAction.cache = source != "" && restExplicitTable(ep, "update") != ""
				updateAction.writeKeys = restWriteKeys(ep, "update")
				updateAction.readOnly = restReadOnlyKeys(ep, "update")
				updateAction = restAssignStorage(updateAction, app.Storage, ep.Storage, updateAct.Storage, cfg.DefaultStoragePlugin, restModelProps(restModel(tables, updateAction.table, updateAct, false)))
				updateAction.actionAuth = updateAct.Auth
				updateAction.actionScopes = updateAct.RequiredScopes
				updateAction = bindRestContent(updateAction, cfg, app, ep, updateAct.Parsers, updateAct.Renderers)
				noSlash := restActionNoSlash(ep, "update")
				if updateAct.Handler != "" {
					updateAction.handler = updateAct.Handler
					r.Patch(route("{id}", noSlash), updateAction.serveGo)
				} else {
					r.Patch(route("{id}", noSlash), updateAction.update)
				}
				put(specRoute("{id}", noSlash), "patch", restOperation(ep, "update", name), restOpAuth{
					auth:   updateAct.Auth,
					scopes: updateAct.RequiredScopes,
				})
			}
			if restActionEnabled(ep, "destroy") {
				destroyAct := ep.Actions["destroy"]
				destroyAction := action
				destroyAction.table = restActionTable(ep, table, "destroy")
				destroyAction.cache = source != "" && restExplicitTable(ep, "destroy") != ""
				destroyAction.actionAuth = destroyAct.Auth
				destroyAction.actionScopes = destroyAct.RequiredScopes
				destroyAction = bindRestContent(destroyAction, cfg, app, ep, destroyAct.Parsers, destroyAct.Renderers)
				noSlash := restActionNoSlash(ep, "destroy")
				if destroyAct.Handler != "" {
					destroyAction.handler = destroyAct.Handler
					r.Delete(route("{id}", noSlash), destroyAction.serveGo)
				} else {
					r.Delete(route("{id}", noSlash), destroyAction.destroy)
				}
				put(specRoute("{id}", noSlash), "delete", restOperation(ep, "destroy", name), restOpAuth{
					auth:   destroyAct.Auth,
					scopes: destroyAct.RequiredScopes,
				})
			}
			for key, call := range ep.DetailActions {
				segment, segErr := config.RestActionSegment(key, call.URL)
				if (call.Func == "" && call.Handler == "") || segErr != nil || !config.RestNameOK(key) || restFieldsNamePK(call.Fields, pk) {
					stdlog.Printf("restapi %s %s detail action %s skipped", apiName, name, key)
					continue
				}
				detailCall := restAssignStorage(action, app.Storage, ep.Storage, call.Storage, cfg.DefaultStoragePlugin, call.Fields)
				detailCall.handler = call.Handler
				detailCall.callFunc = call.Func
				detailCall.includePK = true
				detailCall.props = call.Fields
				detailCall.writeKeys = restPropWriteKeys(call.Fields)
				detailCall.readOnly = restFlagKeys(call.Fields, "readOnly")
				detailCall.actionAuth = call.Auth
				detailCall.actionScopes = call.RequiredScopes
				detailCall = bindRestContent(detailCall, cfg, app, ep, call.Parsers, call.Renderers)
				noSlash := ep.NoTrailingSlash || call.NoTrailingSlash
				if call.Handler != "" {
					r.Post(route("{id}/"+segment, noSlash), detailCall.serveGo)
				} else {
					r.Post(route("{id}/"+segment, noSlash), detailCall.detailCall)
				}
				put(specRoute("{id}/"+segment, noSlash), "post", restCallOperation(call.Fields), restOpAuth{
					auth:   call.Auth,
					scopes: call.RequiredScopes,
				})
			}
			for key, call := range ep.ListActions {
				segment, segErr := config.RestActionSegment(key, call.URL)
				if (call.Func == "" && call.Handler == "") || segErr != nil || !config.RestNameOK(key) || restFieldsNamePK(call.Fields, pk) {
					stdlog.Printf("restapi %s %s list action %s skipped", apiName, name, key)
					continue
				}
				listCall := restAssignStorage(action, app.Storage, ep.Storage, call.Storage, cfg.DefaultStoragePlugin, call.Fields)
				listCall.handler = call.Handler
				listCall.callFunc = call.Func
				listCall.props = call.Fields
				listCall.writeKeys = restPropWriteKeys(call.Fields)
				listCall.readOnly = restFlagKeys(call.Fields, "readOnly")
				listCall.actionAuth = call.Auth
				listCall.actionScopes = call.RequiredScopes
				listCall = bindRestContent(listCall, cfg, app, ep, call.Parsers, call.Renderers)
				noSlash := ep.NoTrailingSlash || call.NoTrailingSlash
				if call.Handler != "" {
					r.Post(route(segment, noSlash), listCall.serveGo)
				} else {
					r.Post(route(segment, noSlash), listCall.detailCall)
				}
				put(specRoute(segment, noSlash), "post", restCallOperation(call.Fields), restOpAuth{
					auth:   call.Auth,
					scopes: call.RequiredScopes,
				})
			}
			for key, state := range ep.StateActions {
				segment, segErr := config.RestActionSegment(key, state.URL)
				if segErr != nil || !config.RestNameOK(key) || (state.SourceField == "" && state.Func == "" && state.Handler == "") {
					stdlog.Printf("restapi %s %s state action %s skipped", apiName, name, key)
					continue
				}
				stateAction := restAssignStorage(action, app.Storage, ep.Storage, state.Storage, cfg.DefaultStoragePlugin, state.Fields)
				if state.Table != "" {
					stateAction.table = state.Table
				}
				stateAction.sourceField = state.SourceField
				stateAction.handler = state.Handler
				stateAction.callFunc = state.Func
				stateAction.props = state.Fields
				stateAction.writeKeys = restPropWriteKeys(state.Fields)
				stateAction.readOnly = restFlagKeys(state.Fields, "readOnly")
				stateAction.actionAuth = state.Auth
				stateAction.actionScopes = state.RequiredScopes
				stateAction = bindRestContent(stateAction, cfg, app, ep, state.Parsers, state.Renderers)
				noSlash := ep.NoTrailingSlash || state.NoTrailingSlash
				suffix := "{id}/" + segment
				if state.Func != "" || state.Handler != "" {
					suffix = segment
				}
				write := r.Put
				writeMethod := "put"
				if state.Post {
					if state.Func == "" && state.Handler == "" {
						stdlog.Printf("restapi %s %s state action %s post ignored without func", apiName, name, key)
					} else {
						write = r.Post
						writeMethod = "post"
					}
				}
				if state.Handler != "" {
					r.Get(route(suffix, noSlash), stateAction.serveGo)
					write(route(suffix, noSlash), stateAction.serveGo)
				} else {
					r.Get(route(suffix, noSlash), stateAction.stateGet)
					write(route(suffix, noSlash), stateAction.statePut)
				}
				_, responseSchema := restCallSchemas(state.Fields)
				responseSchema = restRewriteSchema(responseSchema, storageInline(stateAction.storageName))
				put(specRoute(suffix, noSlash), "get", map[string]any{
					"responses": map[string]any{
						"200": map[string]any{
							"description": "Successful response",
							"schema":      responseSchema,
						},
					},
				}, restOpAuth{auth: state.Auth, scopes: state.RequiredScopes, read: true})
				put(specRoute(suffix, noSlash), writeMethod, restCallOperation(state.Fields), restOpAuth{
					auth:   state.Auth,
					scopes: state.RequiredScopes,
				})
			}
		}
	}
	restSpecs.Store(snap)
	return r
}
