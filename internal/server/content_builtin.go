package server

import (
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	csvcodec "github.com/onegreyonewhite/easyrest/plugins/content/csv"
	formcodec "github.com/onegreyonewhite/easyrest/plugins/content/form"
	jsoncodec "github.com/onegreyonewhite/easyrest/plugins/content/json"
	"github.com/onegreyonewhite/easyrest/plugins/content/ndjson"
	"github.com/onegreyonewhite/easyrest/plugins/content/swaggerui"
	xmlcodec "github.com/onegreyonewhite/easyrest/plugins/content/xml"
)

func registerBuiltinContentPlugins() {
	PreservedContentPlugins["json"] = func() easyrest.ContentPlugin { return jsoncodec.New() }
	PreservedContentPlugins["ndjson"] = func() easyrest.ContentPlugin { return ndjson.New() }
	PreservedContentPlugins["xml"] = func() easyrest.ContentPlugin { return xmlcodec.New() }
	PreservedContentPlugins["csv"] = func() easyrest.ContentPlugin { return csvcodec.New() }
	PreservedContentPlugins["form"] = func() easyrest.ContentPlugin { return formcodec.New() }
	PreservedContentPlugins["html"] = func() easyrest.ContentPlugin { return swaggerui.New() }
}
