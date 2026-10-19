package main

import (
	stdlog "log"
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/onegreyonewhite/easyrest/cmd/content-yaml/yamlcodec"
	"github.com/onegreyonewhite/easyrest/embed"
	"github.com/onegreyonewhite/easyrest/internal/cli"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	apikeyplugin "github.com/onegreyonewhite/easyrest/plugins/auth/apikey"
	awssigv4 "github.com/onegreyonewhite/easyrest/plugins/auth/awssigv4"
	basicplugin "github.com/onegreyonewhite/easyrest/plugins/auth/basic"
	dbsession "github.com/onegreyonewhite/easyrest/plugins/auth/dbsession"
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	jwtsession "github.com/onegreyonewhite/easyrest/plugins/auth/jwtsession"
	lruPlugin "github.com/onegreyonewhite/easyrest/plugins/data/lru"
	memcachedPlugin "github.com/onegreyonewhite/easyrest/plugins/data/memcached"
	mysqlPlugin "github.com/onegreyonewhite/easyrest/plugins/data/mysql"
	postgresPlugin "github.com/onegreyonewhite/easyrest/plugins/data/postgres"
	redisPlugin "github.com/onegreyonewhite/easyrest/plugins/data/redis"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	cachemw "github.com/onegreyonewhite/easyrest/plugins/middleware/cache"
	dbqueryhook "github.com/onegreyonewhite/easyrest/plugins/middleware/dbqueryhook"
	ratelimit "github.com/onegreyonewhite/easyrest/plugins/middleware/ratelimit"
	responseheaders "github.com/onegreyonewhite/easyrest/plugins/middleware/responseheaders"
	s3storage "github.com/onegreyonewhite/easyrest/plugins/storage/s3"
)

func main() {
	if addr := os.Getenv("ER_PPROF_ADDR"); addr != "" {
		go func() {
			stdlog.Printf("pprof listening on %s", addr)
			stdlog.Println(http.ListenAndServe(addr, nil))
		}()
	}

	files, overlay, err := cli.ParseFlags()
	if err != nil {
		stdlog.Fatal(err)
	}
	if err := embed.Run(overlay, files,
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqlitePlugin.NewSqlitePlugin() }),
		embed.WithQuery("sqlite", func() easyrest.DBQueryPlugin { return sqlitePlugin.NewSqliteQueryPlugin() }),
		embed.WithDB("postgres", func() easyrest.DBPlugin { return postgresPlugin.NewPgPlugin() }),
		embed.WithQuery("postgres", func() easyrest.DBQueryPlugin { return postgresPlugin.NewPgQueryPlugin() }),
		embed.WithDB("mysql", func() easyrest.DBPlugin { return mysqlPlugin.NewMysqlPlugin() }),
		embed.WithQuery("mysql", func() easyrest.DBQueryPlugin { return mysqlPlugin.NewMysqlQueryPlugin() }),
		embed.WithAuth("jwt", func() easyrest.AuthPlugin { return &jwtplugin.JWTAuthPlugin{} }),
		embed.WithAuth("jwtsession", func() easyrest.AuthPlugin { return jwtsession.New() }),
		embed.WithAuth("oidc", func() easyrest.AuthPlugin { return &jwtplugin.OIDCAuthPlugin{} }),
		embed.WithAuth("awssigv4", func() easyrest.AuthPlugin { return &awssigv4.AWSSigV4AuthPlugin{} }),
		embed.WithAuth("basic", func() easyrest.AuthPlugin { return &basicplugin.BasicAuthPlugin{} }),
		embed.WithAuth("apikey", func() easyrest.AuthPlugin { return &apikeyplugin.APIKeyAuthPlugin{} }),
		embed.WithAuth("dbsession", func() easyrest.AuthPlugin { return dbsession.New() }),
		embed.WithMiddleware("ratelimit", func() easyrest.MiddlewarePlugin { return ratelimit.New() }),
		embed.WithMiddleware("dbqueryhook", func() easyrest.MiddlewarePlugin { return dbqueryhook.New() }),
		embed.WithMiddleware("response_headers", func() easyrest.MiddlewarePlugin { return responseheaders.New() }),
		embed.WithMiddleware("cache-redis", func() easyrest.MiddlewarePlugin { return cachemw.New(redisPlugin.NewRedisCachePlugin()) }),
		embed.WithMiddleware("cache-postgres", func() easyrest.MiddlewarePlugin { return cachemw.New(postgresPlugin.NewPgCachePlugin()) }),
		embed.WithMiddleware("cache-mysql", func() easyrest.MiddlewarePlugin { return cachemw.New(mysqlPlugin.NewMysqlCachePlugin()) }),
		embed.WithMiddleware("cache-sqlite", func() easyrest.MiddlewarePlugin { return cachemw.New(sqlitePlugin.NewSqliteCachePlugin()) }),
		embed.WithMiddleware("cache-memcached", func() easyrest.MiddlewarePlugin { return cachemw.New(memcachedPlugin.NewMemcachedCachePlugin()) }),
		embed.WithMiddleware("cache-lru", func() easyrest.MiddlewarePlugin { return cachemw.New(lruPlugin.NewSimpleCachePlugin()) }),
		embed.WithContent("yaml", func() easyrest.ContentPlugin { return yamlcodec.New() }),
		embed.WithStorage("s3", func() easyrest.StoragePlugin { return s3storage.New() }),
	); err != nil {
		stdlog.Fatal(err)
	}
}
