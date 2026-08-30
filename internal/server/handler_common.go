package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"slices"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func resolveDBPlugin(w http.ResponseWriter, dbKey, resource string, exclude, allow, reserved []string) (easyrest.DBPlugin, *config.Config, config.PluginConfig, bool) {
	cfg := currentConfig()
	pluginCfg, hasPluginCfg := cfg.PluginMap[dbKey]
	if hasPluginCfg {
		if slices.Contains(reserved, resource) || slices.Contains(exclude, resource) {
			http.Error(w, "Not found", http.StatusNotFound)
			return nil, cfg, pluginCfg, false
		}
		if len(allow) > 0 && !slices.Contains(allow, resource) {
			http.Error(w, "Not found", http.StatusNotFound)
			return nil, cfg, pluginCfg, false
		}
	}
	currentDbPlugins := *DbPlugins.Load()
	dbPlug, ok := currentDbPlugins[dbKey]
	if !ok {
		http.Error(w, "DB plugin not found", http.StatusNotFound)
		return nil, cfg, pluginCfg, false
	}
	return dbPlug, cfg, pluginCfg, true
}

func loadDBPlugin(w http.ResponseWriter, dbKey string) (easyrest.DBPlugin, bool) {
	currentDbPlugins := *DbPlugins.Load()
	dbPlug, ok := currentDbPlugins[dbKey]
	if !ok {
		http.Error(w, "DB plugin not found", http.StatusNotFound)
		return nil, false
	}
	return dbPlug, true
}

func enforceScope(w http.ResponseWriter, r *http.Request, checkScope, isPublic bool, requiredScope string) bool {
	if !checkScope || isPublic {
		return true
	}
	w.Header().Add("Vary", "Authorization")
	if !CheckScope(getTokenClaims(r), requiredScope) {
		http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
		return false
	}
	return true
}

func setPreferenceApplied(w http.ResponseWriter, pluginCtx map[string]any) {
	applied := strings.Builder{}
	if prefer, ok := pluginCtx["prefer"].(map[string]any); ok {
		if tx, ok := prefer["tx"]; ok && tx != nil {
			if txStr, ok := tx.(string); ok && txStr != "" {
				applied.WriteString("tx=")
				applied.WriteString(txStr)
				applied.WriteString(" ")
			}
		}
	}
	applied.WriteString("timezone=")
	if tz, ok := pluginCtx["timezone"].(string); ok {
		applied.WriteString(tz)
	}
	w.Header().Set("Preference-Applied", applied.String())
}

func setDBServerTiming(w http.ResponseWriter, elapsed time.Duration) {
	w.Header().Set("Server-Timing", "db;dur="+strconv.FormatFloat(float64(elapsed.Milliseconds()), 'f', 3, 64))
}
