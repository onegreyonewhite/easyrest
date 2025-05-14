package main

import (
	"github.com/onegreyonewhite/easyrest/internal/cli"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	memcachedPlugin "github.com/onegreyonewhite/easyrest/plugins/data/memcached"
	mysqlPlugin "github.com/onegreyonewhite/easyrest/plugins/data/mysql"
	postgresPlugin "github.com/onegreyonewhite/easyrest/plugins/data/postgres"
	redisPlugin "github.com/onegreyonewhite/easyrest/plugins/data/redis"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	_ "go.uber.org/automaxprocs"
)

func main() {
	cfg, err := cli.ParseFlags()
	if err == nil {
		server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
			return sqlitePlugin.NewSqlitePlugin()
		}
		server.PreservedCachePlugins["sqlite"] = func() easyrest.CachePlugin {
			return sqlitePlugin.NewSqliteCachePlugin()
		}
		server.PreservedDbPlugins["postgres"] = func() easyrest.DBPlugin {
			return postgresPlugin.NewPgPlugin()
		}
		server.PreservedCachePlugins["postgres"] = func() easyrest.CachePlugin {
			return postgresPlugin.NewPgCachePlugin()
		}
		server.PreservedDbPlugins["mysql"] = func() easyrest.DBPlugin {
			return mysqlPlugin.NewMysqlPlugin()
		}
		server.PreservedCachePlugins["mysql"] = func() easyrest.CachePlugin {
			return mysqlPlugin.NewMysqlCachePlugin()
		}
		server.PreservedCachePlugins["redis"] = func() easyrest.CachePlugin {
			return redisPlugin.NewRedisCachePlugin()
		}
		server.PreservedCachePlugins["rediss"] = func() easyrest.CachePlugin {
			return redisPlugin.NewRedisCachePlugin()
		}
		server.PreservedCachePlugins["memcached"] = func() easyrest.CachePlugin {
			return memcachedPlugin.NewMemcachedCachePlugin()
		}
		server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
			return &jwtplugin.JWTAuthPlugin{}
		}
		server.Run(cfg)
	}
}
