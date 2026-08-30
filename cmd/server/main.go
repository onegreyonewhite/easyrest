package main

import (
	stdlog "log"
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/onegreyonewhite/easyrest/internal/cli"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	apikeyplugin "github.com/onegreyonewhite/easyrest/plugins/auth/apikey"
	awssigv4 "github.com/onegreyonewhite/easyrest/plugins/auth/awssigv4"
	basicplugin "github.com/onegreyonewhite/easyrest/plugins/auth/basic"
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	lruPlugin "github.com/onegreyonewhite/easyrest/plugins/data/lru"
	memcachedPlugin "github.com/onegreyonewhite/easyrest/plugins/data/memcached"
	mysqlPlugin "github.com/onegreyonewhite/easyrest/plugins/data/mysql"
	postgresPlugin "github.com/onegreyonewhite/easyrest/plugins/data/postgres"
	redisPlugin "github.com/onegreyonewhite/easyrest/plugins/data/redis"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	cachemw "github.com/onegreyonewhite/easyrest/plugins/middleware/cache"
	dbqueryhook "github.com/onegreyonewhite/easyrest/plugins/middleware/dbqueryhook"
	ratelimit "github.com/onegreyonewhite/easyrest/plugins/middleware/ratelimit"
)

func main() {
	if addr := os.Getenv("ER_PPROF_ADDR"); addr != "" {
		go func() {
			stdlog.Printf("pprof listening on %s", addr)
			stdlog.Println(http.ListenAndServe(addr, nil))
		}()
	}

	cfg, err := cli.ParseFlags()
	if err == nil {
		server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
			return sqlitePlugin.NewSqlitePlugin()
		}
		server.PreservedQueryPlugins["sqlite"] = func() easyrest.DBQueryPlugin {
			return sqlitePlugin.NewSqliteQueryPlugin()
		}
		server.PreservedDbPlugins["postgres"] = func() easyrest.DBPlugin {
			return postgresPlugin.NewPgPlugin()
		}
		server.PreservedQueryPlugins["postgres"] = func() easyrest.DBQueryPlugin {
			return postgresPlugin.NewPgQueryPlugin()
		}
		server.PreservedDbPlugins["mysql"] = func() easyrest.DBPlugin {
			return mysqlPlugin.NewMysqlPlugin()
		}
		server.PreservedQueryPlugins["mysql"] = func() easyrest.DBQueryPlugin {
			return mysqlPlugin.NewMysqlQueryPlugin()
		}
		server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
			return &jwtplugin.JWTAuthPlugin{}
		}
		server.PreservedAuthPlugins["oidc"] = func() easyrest.AuthPlugin {
			return &jwtplugin.OIDCAuthPlugin{}
		}
		server.PreservedAuthPlugins["awssigv4"] = func() easyrest.AuthPlugin {
			return &awssigv4.AWSSigV4AuthPlugin{}
		}
		server.PreservedAuthPlugins["basic"] = func() easyrest.AuthPlugin {
			return &basicplugin.BasicAuthPlugin{}
		}
		server.PreservedAuthPlugins["apikey"] = func() easyrest.AuthPlugin {
			return &apikeyplugin.APIKeyAuthPlugin{}
		}
		server.PreservedMiddlewarePlugins["ratelimit"] = func() easyrest.MiddlewarePlugin {
			return ratelimit.New()
		}
		server.PreservedMiddlewarePlugins["dbqueryhook"] = func() easyrest.MiddlewarePlugin {
			return dbqueryhook.New()
		}
		server.PreservedMiddlewarePlugins["cache-redis"] = func() easyrest.MiddlewarePlugin {
			return cachemw.New(redisPlugin.NewRedisCachePlugin())
		}
		server.PreservedMiddlewarePlugins["cache-postgres"] = func() easyrest.MiddlewarePlugin {
			return cachemw.New(postgresPlugin.NewPgCachePlugin())
		}
		server.PreservedMiddlewarePlugins["cache-mysql"] = func() easyrest.MiddlewarePlugin {
			return cachemw.New(mysqlPlugin.NewMysqlCachePlugin())
		}
		server.PreservedMiddlewarePlugins["cache-sqlite"] = func() easyrest.MiddlewarePlugin {
			return cachemw.New(sqlitePlugin.NewSqliteCachePlugin())
		}
		server.PreservedMiddlewarePlugins["cache-memcached"] = func() easyrest.MiddlewarePlugin {
			return cachemw.New(memcachedPlugin.NewMemcachedCachePlugin())
		}
		server.PreservedMiddlewarePlugins["cache-lru"] = func() easyrest.MiddlewarePlugin {
			return cachemw.New(lruPlugin.NewSimpleCachePlugin())
		}
		server.Run(cfg)
	}
}
