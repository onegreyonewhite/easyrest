# Plugin SDK

This package is the contract between the HTTP server and a plugin process. A binary registers one or more RPC keys and serves them with `easyrest.Handshake`. `easyrest-server` registers in-process factories for the common data, auth, and middleware plugins, plus YAML and S3. The server package itself always registers the standard content plugins and the storage plugins `local`, `memory`, `dbglob`, and `static`, so `easyrest-gateway` has those too. Every other plugin is an executable.

A nil context map returned from a method means the caller keeps its existing map. A non-nil map replaces it.

## RPC keys

| Key | Interface | What it does |
| --- | --- | --- |
| `db` | `DBPlugin` | Table CRUD, functions, schema |
| `query` | `DBQueryPlugin` | One read-only SQL string |
| `auth` | `AuthPlugin` | Claims from a header or cookie |
| `middleware` | `MiddlewarePlugin` | `PreRequest` and `PostRequest` |
| `content` | `ContentPlugin` | Parse a body and render a response |
| `storage` | `StoragePlugin` | Store and serve object bytes |

A binary may register any subset of these keys. Cache backends are not a seventh key. They implement `cache.Store` and are wrapped as a middleware plugin. See [Cache store](#cache-store).

Interfaces live in [plugin.go](plugin.go), [content.go](content.go), and [storage.go](storage.go).

## How the server finds a binary

`easyrest-server` uses a preserved factory when `path` is empty and the name is registered in [cmd/server/main.go](../cmd/server/main.go) or by the server package (`json`, `ndjson`, `xml`, `csv`, `form`, `html`, `local`, `memory`, `dbglob`, `static`). A non-empty `path` always starts a subprocess, even when a factory exists. `easyrest-gateway` has those server-package factories and none of the `cmd/server` ones, so data, auth, middleware, YAML, and S3 take the subprocess path.

Search order when `path` is empty: `PATH`, the working directory, then the directory of the server executable. Each place is tried as the plain name and as `name-GOOS-GOARCH`.

| Family | Config source | Binary name |
| --- | --- | --- |
| Data | URI scheme | `easyrest-plugin-<scheme>` |
| Auth | `auth_plugins` key | `easyrest-auth-<key>` |
| Middleware | `middleware_plugins` key | `easyrest-middleware-<key>` |
| Content | `content_plugins` key | `easyrest-content-<key>` |
| Storage | `plugin`, or the key when `plugin` is empty | `easyrest-storage-<plugin>` |

Loading lives in [internal/server/plugin_load.go](../internal/server/plugin_load.go).

## Handshake

```go
var Handshake = plugin.HandshakeConfig{
    ProtocolVersion:  1,
    MagicCookieKey:   "EASYREST_PLUGIN",
    MagicCookieValue: "easyrest",
}
```

## Data and query

`InitConnection` receives the connection URI. `TableGet`, `TableCreate`, `TableUpdate`, `TableDelete`, `CallFunction`, and `GetSchema` may return an updated context. `QueryCall` returns rows only, so a query plugin cannot harvest session settings.

One process can register both keys, as [cmd/plugin-sqlite/main.go](../cmd/plugin-sqlite/main.go) does:

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "db":    &easyrest.DBPluginPlugin{Impl: sqlite.NewSqlitePlugin()},
        "query": &easyrest.DBQueryPluginPlugin{Impl: sqlite.NewSqliteQueryPlugin()},
    },
})
```

## Auth

```go
Init(settings map[string]any, host HostRPC) (AuthInfo, error)
Authenticate(headers map[string]string, method, path, query string) (map[string]any, error)
```

`AuthInfo.Schema` is the Swagger 2.0 security definition. `AuthInfo.Key` is the header or cookie name. An empty key means `Authorization`. `IsCookie` true tells the host to read that cookie and copy its value into the header map passed to `Authenticate`. The plugin does not set the cookie.

[cmd/auth-jwt/main.go](../cmd/auth-jwt/main.go):

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "auth": &easyrest.AuthPluginPlugin{Impl: &jwtAuth.JWTAuthPlugin{}},
    },
})
```

## Middleware

```go
Init(settings map[string]any, host HostRPC) (MiddlewareInfo, error)
PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error)
PostRequest(dbKey string, ctx map[string]any) (map[string]string, error)
```

A non-nil status from `PreRequest` stops the chain. `PostRequest` returns extra headers and cannot change the body. See [Request lifecycle](../README.md#request-lifecycle).

[cmd/middleware-ratelimit/main.go](../cmd/middleware-ratelimit/main.go):

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "middleware": &easyrest.MiddlewarePluginPlugin{Impl: ratelimit.New()},
    },
})
```

## Content

```go
Init(settings map[string]any) (ContentInfo, error)
Parse(body []byte, ctx map[string]any) (any, map[string]any, error)
Render(data any, ctx map[string]any) (any, map[string]any, error)
PrepareGet(limit, offset, page int) (windows []ContentWindow, repeat bool)
PrepareCreate(body any, page int) []any
```

`ContentInfo` embeds `PluginMeta`, so `Metadata` and `Ctx` are empty maps when the plugin has nothing extra to report. `RenderMedia` is the response media type. `ParserMedia` is the request body media type. An empty media field means that direction is unsupported. `Format` is the `?format=` value. `PrepareGet` plans the next `TableGet` window. `repeat` true asks the host to call `PrepareGet` again after a full page. Embed `ContentBase` for the one-shot default.

[cmd/content-yaml/main.go](../cmd/content-yaml/main.go):

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "content": &easyrest.ContentPluginPlugin{Impl: yamlcodec.New()},
    },
})
```

Name that binary `easyrest-content-yaml` for `content_plugins.yaml`.

## Storage

```go
Init(settings map[string]any, host HostRPC) (StorageInfo, error)
Put(path string, body []byte, ctx map[string]any) (rel string, ctxOut map[string]any, error)
GetUrl(paths []string, ctx map[string]any) ([]StorageURL, error)
GetMetadata(path string, ctx map[string]any) (StorageMeta, error)
GetBin(path string, ctx map[string]any) (body []byte, mime string, ctxOut map[string]any, error)
List(path string, ctx map[string]any) ([]StorageEntry, error)
Delete(path string, ctx map[string]any) error
```

`Init` returns the storage root and whether values are stored inline. A non-empty root with `inline` false mounts `GET /media/{name}/*`. The root string itself is not part of the URL. `inline` true means `Put`'s return value is the database cell and the response. That value is a data URL (`data:<media-type>;base64,<data>`). `ctx["storage.mime"]`, when it is a non-empty string, is the media type. The host does not call `GetUrl` and does not mount `/media` for that plugin.

There is no `cmd/storage-*` binary in this repo. A process that serves the memory driver looks like this:

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "storage": &easyrest.StoragePluginPlugin{Impl: memory.New()},
    },
})
```

Name it `easyrest-storage-memory`, or set `path` on the `storage_plugins` entry. The instance name is the map key. `plugin` selects the driver when it is set.

## Cache store

`cache.Store` is `InitConnection`, `Set`, and `Get`. Wrap it with `cache.New(store)` and register the result as `"middleware"`. [cmd/middleware-cache-redis/main.go](../cmd/middleware-cache-redis/main.go):

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "middleware": &easyrest.MiddlewarePluginPlugin{
            Impl: cachemw.New(redisPlugin.NewRedisCachePlugin()),
        },
    },
})
```

The binary name follows the middleware rule: `easyrest-middleware-cache-redis` for `middleware_plugins.cache-redis`.

## Host RPC

`HostRPC` is the dial target for the internal RPC server. `Network` and `Address` are what a later call dials. A zero value does not dial. Calls then fail with `host rpc is not configured`. Auth, middleware, and storage `Init` receive this value. Plugins that read or write rows (`dbsession`, table-mode `dbglob`) need a listening `internal_rpc`. See [internal RPC](../internal/config/README.md#internal-rpc).

## See also

- [Server README](../README.md)
- [HTTP API](../internal/server/README.md)
- [Configuration](../internal/config/README.md)
