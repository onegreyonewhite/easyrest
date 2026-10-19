package server

import (
	stdlog "log"
	"net/http"
	"net/url"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// contentWriter renders one response through the negotiated content plugin.
// The first Write sends status and headers. Later writes append a page.
// It is request-scoped and does not store a context.Context.
type contentWriter struct {
	w         http.ResponseWriter
	r         *http.Request
	dbKey     string
	pluginCtx map[string]any
	plug      easyrest.ContentPlugin
	media     string
	params    map[string]string
	runPost   bool
	flush     bool
	started   bool
	prepared  bool
	status    int
	carry     map[string]any
	renderCtx map[string]any
}

func newContentWriter(w http.ResponseWriter, r *http.Request, dbKey string, pluginCtx map[string]any, query url.Values, renderer contentPluginRef, runPost bool) *contentWriter {
	plug := renderer.Plugin
	media := renderer.RenderMedia
	params := renderer.Params
	if plug == nil {
		choice := requestContentChoice(r, query)
		plug = choice.Renderer.Plugin
		media = choice.Renderer.RenderMedia
		params = choice.Renderer.Params
	}
	if plug == nil {
		plug = builtinJSON()
		media = easyrest.MediaTypeJSON
	}
	if media == "" {
		media = easyrest.MediaTypeJSON
	}
	return &contentWriter{
		w:         w,
		r:         r,
		dbKey:     dbKey,
		pluginCtx: pluginCtx,
		plug:      plug,
		media:     media,
		params:    params,
		runPost:   runPost,
	}
}

// setRenderCtx copies keys into the map passed to ContentPlugin.Render.
func (c *contentWriter) setRenderCtx(ctx map[string]any) {
	if c == nil || len(ctx) == 0 {
		return
	}
	if c.renderCtx == nil {
		c.renderCtx = make(map[string]any, len(ctx))
	}
	for k, v := range ctx {
		c.renderCtx[k] = v
	}
}

// Write renders data. The first call runs post-request middleware when runPost
// is set, then writes status, content type, and the body. Later calls append.
func (c *contentWriter) Write(status int, data any, pag map[string]any) error {
	if c.started {
		return c.append(data, pag)
	}
	if c.r != nil {
		addResponseFormatVary(c.w)
	}
	_ = c.prepare(status, true)
	return c.commit(data, pag, false)
}

// WriteError renders {"error": msg} with the content plugin.
// Before headers, that is the whole response at status.
// After headers, the rendered error is appended and the status stays as written.
// Post middleware runs for headers, and the status passed in is the one written.
func (c *contentWriter) WriteError(status int, msg string) error {
	payload := map[string]any{"error": msg}
	if c.started {
		if err := c.append(payload, nil); err != nil {
			stdlog.Printf("Error encoding response: %v", err)
			return err
		}
		return nil
	}
	if c.r != nil {
		addResponseFormatVary(c.w)
	}
	_ = c.prepare(status, false)
	return c.commit(payload, nil, false)
}

func (c *contentWriter) append(data any, pag map[string]any) error {
	return c.commit(data, pag, true)
}

// prepare runs post middleware once. honorPluginStatus lets response.status
// replace the handler status. Error responses keep the status they were given.
func (c *contentWriter) prepare(status int, honorPluginStatus bool) int {
	if c.prepared {
		return c.status
	}
	c.prepared = true
	if c.runPost && c.pluginCtx != nil {
		setHandlerStatus(c.pluginCtx, status)
		runPostRequestMiddlewares(c.w, c.dbKey, c.pluginCtx)
		applyContextResponseHeaders(c.w, c.pluginCtx)
		if honorPluginStatus {
			status = statusFromPluginContext(c.pluginCtx, status)
		}
	}
	c.status = status
	return status
}

func (c *contentWriter) commit(data any, pag map[string]any, cont bool) error {
	body, headerCtx, err := c.render(data, pag, cont)
	if err != nil {
		if c.started || cont {
			stdlog.Printf("Error encoding response: %v", err)
			return err
		}
		errBody, errCtx, err2 := c.render(map[string]any{"error": err.Error()}, nil, false)
		if err2 != nil {
			stdlog.Printf("Error encoding response: %v", err)
			http.Error(c.w, err.Error(), http.StatusInternalServerError)
			c.started = true
			return err
		}
		body, headerCtx = errBody, errCtx
		c.status = http.StatusInternalServerError
	}
	if !c.started {
		applyContextResponseHeaders(c.w, headerCtx)
		if c.media != "" && c.w.Header().Get("Content-Type") == "" {
			c.w.Header().Set("Content-Type", c.media)
		}
		c.w.WriteHeader(c.status)
		c.started = true
	}
	if len(body) > 0 {
		if _, err := c.w.Write(body); err != nil {
			stdlog.Printf("Error writing response: %v", err)
			return err
		}
	}
	if c.flush {
		_ = http.NewResponseController(c.w).Flush()
		refreshNDJSONWriteDeadline(c.w)
	}
	return nil
}

func (c *contentWriter) render(data any, pag map[string]any, cont bool) ([]byte, map[string]any, error) {
	var ctx map[string]any
	escapeOn := jsonEscapeEnabled()
	if len(c.carry) == 0 && pag == nil && !cont && escapeOn && len(c.params) == 0 && len(c.renderCtx) == 0 {
		ctx = nil
	} else {
		ctx = map[string]any{easyrest.CtxJSONEscapeHTML: escapeOn}
		for k, v := range c.renderCtx {
			ctx[k] = v
		}
		for k, v := range c.carry {
			if k == easyrest.CtxJSONEscapeHTML || k == easyrest.CtxPagination || k == easyrest.CtxContinue || k == easyrest.CtxContentParams {
				continue
			}
			ctx[k] = v
		}
		if len(c.params) > 0 {
			ctx[easyrest.CtxContentParams] = c.params
		}
		if pag != nil {
			ctx[easyrest.CtxPagination] = pag
		}
		if cont {
			ctx[easyrest.CtxContinue] = true
		}
	}
	raw, out, err := c.plug.Render(data, ctx)
	if err != nil {
		return nil, out, err
	}
	if out != nil {
		c.carry = out
	}
	body, err := easyrest.RenderedBytes(raw)
	return body, out, err
}
