package server

import (
	stdlog "log"
	"net/http"
	"time"
)

func tablePost(w http.ResponseWriter, r *http.Request) {
	bag := apiRequestFrom(r)
	dbKey := bag.dbKey
	pluginCtx := bag.pluginCtx
	queryValues := bag.query
	flatCtx, ok := tableFlatContext(w, r, bag, queryValues)
	if !ok {
		return
	}

	parsedData, err := parseRequest(w, r, true)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, err.Error(), http.StatusBadRequest)
		return
	}

	data, ok := parsedData.([]map[string]any)
	if !ok {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Invalid data format", http.StatusBadRequest)
		return
	}
	flatCtx, err = formatContextForSubst(pluginCtx, flatCtx, data)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for i, row := range data {
		data[i] = substituteValue(row, flatCtx, pluginCtx).(map[string]any)
	}
	if err := validateBodyColumns(data); err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, err.Error(), http.StatusBadRequest)
		return
	}
	if chunks := createChunks(bag, pluginCtx, data); len(chunks) > 1 {
		writeCreateChunks(w, r, bag, dbKey, pluginCtx, chunks)
		return
	}
	startTime := time.Now()
	rows, returnedCtx, err := bag.dbPlug.TableCreate(bag.userID, bag.resource, data, pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	queryTime := time.Since(startTime)
	setDBServerTiming(w, queryTime)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error in TableCreate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	middlewareMakeResponse(w, r, dbKey, pluginCtx, http.StatusCreated, rows, queryValues)
}

func createChunks(bag *apiRequest, pluginCtx map[string]any, data []map[string]any) []any {
	if bag.content.Renderer.Plugin == nil {
		return []any{data}
	}
	page := bag.pluginCfg.DefaultLimit
	if n := preferPageSize(pluginCtx); n > 0 {
		page = n
	}
	chunks := bag.content.Renderer.Plugin.PrepareCreate(data, page)
	if len(chunks) == 0 {
		return []any{data}
	}
	return chunks
}

func writeCreateChunks(w http.ResponseWriter, r *http.Request, bag *apiRequest, dbKey string, pluginCtx map[string]any, chunks []any) {
	renderer := bag.content.Renderer
	if renderer.Plugin == nil {
		renderer, _ = initContentPlugin("ndjson", builtinNDJSON(), nil)
	}
	cw := newContentWriter(w, r, dbKey, pluginCtx, bag.query, renderer, true)
	var total time.Duration
	for _, chunk := range chunks {
		rowsIn, ok := chunk.([]map[string]any)
		if !ok {
			_ = cw.WriteError(http.StatusBadRequest, "Invalid data format")
			return
		}
		start := time.Now()
		created, returned, err := bag.dbPlug.TableCreate(bag.userID, bag.resource, rowsIn, pluginCtx)
		total += time.Since(start)
		pluginCtx = applyReturnedPluginContext(pluginCtx, returned)
		cw.pluginCtx = pluginCtx
		if err != nil {
			if cw.started {
				stdlog.Printf("Error in TableCreate during content stream: %v", err)
			}
			_ = cw.WriteError(http.StatusInternalServerError, "Error in TableCreate: "+err.Error())
			return
		}
		if !cw.started {
			setDBServerTiming(w, total)
		}
		if err := cw.Write(http.StatusCreated, created, nil); err != nil {
			stdlog.Printf("Error encoding create stream: %v", err)
			return
		}
		if cw.status < 200 || cw.status > 299 {
			return
		}
	}
}

func tablePatch(w http.ResponseWriter, r *http.Request) {
	bag := apiRequestFrom(r)
	dbKey := bag.dbKey
	pluginCtx := bag.pluginCtx
	queryValues := bag.query
	flatCtx, ok := tableFlatContext(w, r, bag, queryValues)
	if !ok {
		return
	}

	parsedData, err := parseRequest(w, r, false)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, err.Error(), http.StatusBadRequest)
		return
	}

	data, ok := parsedData.(map[string]any)
	if !ok {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Invalid data format", http.StatusBadRequest)
		return
	}

	flatCtx, err = formatContextForSubst(pluginCtx, flatCtx, data)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data = substituteValue(data, flatCtx, pluginCtx).(map[string]any)
	if err := validateBodyColumns(data); err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, err.Error(), http.StatusBadRequest)
		return
	}
	where, err := ParseWhereClause(queryValues, flatCtx, pluginCtx)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
		return
	}
	startTime := time.Now()
	updated, returnedCtx, err := bag.dbPlug.TableUpdate(bag.userID, bag.resource, data, where, pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	queryTime := time.Since(startTime)
	setDBServerTiming(w, queryTime)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error in TableUpdate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	middlewareMakeResponse(w, r, dbKey, pluginCtx, http.StatusOK, map[string]any{"updated": updated}, queryValues)
}

func tableDelete(w http.ResponseWriter, r *http.Request) {
	bag := apiRequestFrom(r)
	dbKey := bag.dbKey
	pluginCtx := bag.pluginCtx
	queryValues := bag.query
	flatCtx, ok := tableFlatContext(w, r, bag, queryValues)
	if !ok {
		return
	}

	where, err := ParseWhereClause(queryValues, flatCtx, pluginCtx)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
		return
	}
	startTime := time.Now()
	_, returnedCtx, err := bag.dbPlug.TableDelete(bag.userID, bag.resource, where, pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	queryTime := time.Since(startTime)
	setDBServerTiming(w, queryTime)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Error in TableDelete: "+err.Error(), http.StatusInternalServerError)
		return
	}

	middlewareWriteHeader(w, dbKey, pluginCtx, http.StatusNoContent)
}
