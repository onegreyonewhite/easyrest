package server

import (
	"net/http"
	"time"
)

func tablePost(w http.ResponseWriter, r *http.Request) {
	bag := apiRequestFrom(r)
	dbKey := bag.dbKey
	pluginCtx := bag.pluginCtx
	queryValues := bag.query
	flatCtx, ok := tableFlatContext(w, bag, queryValues)
	if !ok {
		return
	}

	parsedData, err := parseRequest(w, r, true)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, err.Error(), http.StatusBadRequest)
		return
	}

	data, ok := parsedData.([]map[string]any)
	if !ok {
		middlewareHTTPError(w, dbKey, pluginCtx, "Invalid data format", http.StatusBadRequest)
		return
	}

	flatCtx, err = formatContextForSubst(pluginCtx, flatCtx, data)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for i, row := range data {
		data[i] = substituteValue(row, flatCtx, pluginCtx).(map[string]any)
	}
	if err := validateBodyColumns(data); err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, err.Error(), http.StatusBadRequest)
		return
	}
	startTime := time.Now()
	rows, returnedCtx, err := bag.dbPlug.TableCreate(bag.userID, bag.resource, data, pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	queryTime := time.Since(startTime)
	setDBServerTiming(w, queryTime)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error in TableCreate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	middlewareMakeResponse(w, r, dbKey, pluginCtx, http.StatusCreated, rows, queryValues)
}

func tablePatch(w http.ResponseWriter, r *http.Request) {
	bag := apiRequestFrom(r)
	dbKey := bag.dbKey
	pluginCtx := bag.pluginCtx
	queryValues := bag.query
	flatCtx, ok := tableFlatContext(w, bag, queryValues)
	if !ok {
		return
	}

	parsedData, err := parseRequest(w, r, false)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, err.Error(), http.StatusBadRequest)
		return
	}

	data, ok := parsedData.(map[string]any)
	if !ok {
		middlewareHTTPError(w, dbKey, pluginCtx, "Invalid data format", http.StatusBadRequest)
		return
	}

	flatCtx, err = formatContextForSubst(pluginCtx, flatCtx, data)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data = substituteValue(data, flatCtx, pluginCtx).(map[string]any)
	if err := validateBodyColumns(data); err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, err.Error(), http.StatusBadRequest)
		return
	}
	where, err := ParseWhereClause(queryValues, flatCtx, pluginCtx)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
		return
	}
	startTime := time.Now()
	updated, returnedCtx, err := bag.dbPlug.TableUpdate(bag.userID, bag.resource, data, where, pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	queryTime := time.Since(startTime)
	setDBServerTiming(w, queryTime)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error in TableUpdate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	middlewareMakeResponse(w, r, dbKey, pluginCtx, http.StatusOK, map[string]int{"updated": updated}, queryValues)
}

func tableDelete(w http.ResponseWriter, r *http.Request) {
	bag := apiRequestFrom(r)
	dbKey := bag.dbKey
	pluginCtx := bag.pluginCtx
	queryValues := bag.query
	flatCtx, ok := tableFlatContext(w, bag, queryValues)
	if !ok {
		return
	}

	where, err := ParseWhereClause(queryValues, flatCtx, pluginCtx)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
		return
	}
	startTime := time.Now()
	_, returnedCtx, err := bag.dbPlug.TableDelete(bag.userID, bag.resource, where, pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	queryTime := time.Since(startTime)
	setDBServerTiming(w, queryTime)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error in TableDelete: "+err.Error(), http.StatusInternalServerError)
		return
	}

	middlewareWriteHeader(w, dbKey, pluginCtx, http.StatusNoContent)
}
