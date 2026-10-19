package server

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	jsoncodec "github.com/onegreyonewhite/easyrest/plugins/content/json"
	ndjsoncodec "github.com/onegreyonewhite/easyrest/plugins/content/ndjson"
)

type contentChoiceCtxKey struct{}
type contentPaginationCtxKey struct{}

func requestContentChoice(r *http.Request, query url.Values) contentChoice {
	if bag := apiRequestFrom(r); bag != nil && contentChoiceReady(bag.content) {
		return bag.content
	}
	if r != nil {
		if choice, ok := r.Context().Value(contentChoiceCtxKey{}).(contentChoice); ok && contentChoiceReady(choice) {
			return choice
		}
	}
	names := easyrest.StandardContentNames()
	if bag := apiRequestFrom(r); bag != nil {
		var defaults []string
		if bag.cfg != nil {
			defaults = bag.cfg.DefaultContentHandlers
		}
		names = contentHandlerNames(nil, nil, bag.pluginCfg.ContentHandlers, defaults)
	} else if cfg := currentConfig(); len(cfg.DefaultContentHandlers) > 0 {
		names = cfg.DefaultContentHandlers
	}
	if query == nil && r != nil {
		query = r.URL.Query()
	}
	return negotiateContent(r, query, contentRefsNamed(names))
}

func contentChoiceReady(choice contentChoice) bool {
	return choice.Renderer.Plugin != nil || choice.Parser.Plugin != nil || choice.ParseErr != nil
}

func jsonEscapeEnabled() bool {
	return !currentConfig().Server.DisableHTMLEscape
}

func builtinJSON() easyrest.ContentPlugin { return jsoncodec.New() }

func builtinNDJSON() easyrest.ContentPlugin { return ndjsoncodec.New() }

func readParsedBody(r *http.Request, choice contentChoice, expectArray bool) (any, error) {
	if choice.ParseErr != nil {
		return nil, choice.ParseErr
	}
	if choice.Parser.Plugin == nil {
		ct := ""
		if r != nil {
			ct = mediaType(r.Header.Get("Content-Type"))
		}
		if ct == "" {
			ct = easyrest.MediaTypeJSON
		}
		return nil, fmt.Errorf("unsupported Content-Type: %s", ct)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	parsed, _, err := choice.Parser.Plugin.Parse(body, map[string]any{easyrest.CtxExpectArray: expectArray})
	if err != nil {
		return nil, err
	}
	return coerceParsed(parsed, expectArray)
}

func coerceParsed(parsed any, expectArray bool) (any, error) {
	switch data := parsed.(type) {
	case map[string]any:
		if expectArray {
			return nil, fmt.Errorf("JSON parse error: expected array")
		}
		return data, nil
	case []map[string]any:
		if expectArray {
			return data, nil
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("Invalid data format")
		}
		return data[0], nil
	case []any:
		if !expectArray {
			return nil, fmt.Errorf("JSON parse error: expected object")
		}
		rows := make([]map[string]any, len(data))
		for i, item := range data {
			row, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Invalid data format")
			}
			rows[i] = row
		}
		return rows, nil
	default:
		return nil, fmt.Errorf("Invalid data format")
	}
}
