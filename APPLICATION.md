# Application guide

This guide builds one HTTP application from the `application` section: a page on `GET /`, two API versions, function routes, files, and a cookie session. The logic and the row filters live in Postgres. Server fields and plugin settings stay in the references below. Every YAML, SQL, and HTML fragment here is taken from [examples/application/](examples/application/). A chapter may show part of a file.

- [Configuration reference](internal/config/README.md)
- [HTTP API](internal/server/README.md)
- [Plugin SDK](plugin/README.md)
- [Example files](examples/application/)

## 1. What you can build

`easyrest-server` can serve the page, the `/restapi` routes, and `/api/` from one process. The example puts users, todos, settings, uploads, and login in Postgres, and leaves a small SQLite connection on `/api/public/` so the generic API is still there. Start with [examples/application/README.md](examples/application/README.md).

## 2. Layout

`application` has `template`, `template_path`, `version`, `auth`, `source`, `public`, `storage`, `parsers`, `renderers`, and `api`. Each `api` key is mounted at `/restapi/<name>/`. An endpoint path is `/restapi/<api>/<url>/`, then the action suffix. An empty `name` becomes the map key. An empty `url` becomes that name. An empty `table` becomes the name. An empty `primary_key` becomes `id`. `url` may contain letters, digits, `_`, `.`, `/`, `{`, `}`, and `-`. It must not contain `{id}`, because `{id}` is reserved for the primary key.

An endpoint written as `users: {}` under `api.v1`, with `source: app`, mounts `GET` and `POST /restapi/v1/users/` plus `GET`, `PATCH`, and `DELETE /restapi/v1/users/{id}/` on table `users`. The working file fills those keys in. The shared header is:

```yaml
application:
  template_path: ./page.html
  version: v1
  auth: jwt
  source: app
  storage: media
  parsers: [json, yaml]
  renderers: [json, yaml]
```

`source`, `public`, and `storage` apply to every API. An empty `storage` becomes `default_storage_plugin`, and an empty `default_storage_plugin` becomes `local`. `static` is rejected as `application.storage` because that plugin does not accept uploads. `application.auth` is the name passed into the `GET /` template.

The routes the later chapters call are below. Paths end in `/` unless the row says otherwise.

| Method | Path | What runs |
| --- | --- | --- |
| GET, POST | `/restapi/v1/users/` | table `users` |
| GET, PATCH, DELETE | `/restapi/v1/users/{id}/` | table `users` |
| POST | `/restapi/v1/users/export/` | `app.export_users` |
| POST | `/restapi/v1/users/{id}/archive/` | `app.archive_user` |
| GET, PUT | `/restapi/v1/users/{id}/settings/` | column `settings` |
| GET, POST | `/restapi/v1/todos/` | list is the table, POST is `todos(title)` |
| GET, PATCH, DELETE | `/restapi/v1/todos/{id}/` | table `todos` |
| GET, PUT | `/restapi/v1/me/settings/` | `app.my_settings` |
| GET, PUT | `/restapi/v1/.well-known/openid-configuration` | `app.openid_configuration`, no slash |
| POST | `/restapi/v1/login/` | `app.login` |
| POST | `/restapi/v1/logout/` | `app.logout` |
| GET, POST | `/restapi/v1/photos/` | table `photos`, S3 on create |
| GET | `/restapi/v1/directory/` | view `user_directory`, CSV |
| GET | `/restapi/v1/labels/` | `todos` columns `id`, `title` |
| GET | `/restapi/v1/orgs/{org_id}/users/` | table `users`, filter `org_id` |
| GET | `/restapi/v2/todos/` | same table, JWT and `todos-read` |

`parsers` and `renderers` are optional lists. When both keys are absent, that level is skipped and `content_handlers` is considered next. When either key is present, including `[]`, that level is chosen and a missing list is copied from the one that was set. The search order is the action, the endpoint, the API, `application`, the connection `content_handlers`, `default_content_handlers`, then json, ndjson, xml, csv, and form. `yaml` is extra: [cmd/content-yaml/README.md](cmd/content-yaml/README.md). The example turns it on with `content_plugins.yaml: {}`.

## 3. Root page and static files

`GET /` renders a Go `html/template`. A non-empty `template` string wins over `template_path`. Both empty keeps the embedded Swagger page. The template receives `Title`, `Assets` (this build uses `/media/static/`), `Config`, `Standalone`, `Schema`, and `Auth`. `Config` is already the Swagger UI structure. `{{.Config}}` prints that value. A template can ignore every field.

The embedded page, shortened from [plugins/content/swaggerui/page.html.tmpl](plugins/content/swaggerui/page.html.tmpl), uses them like this:

```html
<title>{{.Title}}</title>
<link rel="stylesheet" href="{{.Assets}}swagger-ui.css">
<script>
  var config = {{.Config}};
  {{if .Schema}}
  config.spec = {{.Schema}};
  {{end}}
  {{if .Auth}}
  var easyrestAuth = "{{.Auth}}";
  {{end}}
</script>
```

`version: v1` embeds the v1 document in `Schema` and clears the catalog URL list. `/api/{db}/` and `/restapi/{name}/` keep the embedded page even when `GET /` uses yours.

Files in the `static` storage directory are served at `/media/static/`. A file with the same name as an embedded Swagger asset replaces that asset. The example points the directory here:

```yaml
storage_plugins:
  static:
    settings:
      path: ./static
```

[examples/application/static/logo.svg](examples/application/static/logo.svg) is `GET /media/static/logo.svg`. A `static/swagger-ui.css` next to it would replace the embedded stylesheet.

## 4. A frontend on GET /

[examples/application/page.html](examples/application/page.html) is the application page. It links the static script and stylesheet, and leaves Swagger UI on `/restapi/v1/?format=html`:

```html
<link rel="stylesheet" href="/media/static/app.css">
<script src="/media/static/app.js"></script>
```

Swagger for this API remains at `/restapi/v1/?format=html`. The script calls the same origin with the cookie:

```javascript
async function loadTodos() {
  const response = await fetch("/restapi/v1/todos/", { credentials: "include" });
  return response.json();
}
```

`SIGHUP` reloads the config, including `template_path`. `GET /` chooses a representation the way other documents do. A browser `Accept: text/html` renders `page.html`. `curl` without that header receives the v1 document as JSON, because `version: v1` embeds that spec. There is no fallback that serves this page for `/tasks` or any other path. Only `GET /` uses the template.

## 5. Versions and turning /api off

`v1` and `v2` are two keys under `application.api`. They share `source: app`. Each has its own middleware list and auth list.

```yaml
plugins:
  app:
    uri: postgres://app_conn:app_conn@127.0.0.1:5432/easyrest_app?sslmode=disable&search_path=app
    internal: true
    db_tx_end: commit-allow-override
  public:
    uri: sqlite://./public.db
    title: Public catalog
```

```yaml
    v1:
      auth: [dbsession, jwt]
      anon_claims:
        sub: ""
      middlewares: [dbqueryhook, cache-postgres, ratelimit]
    v2:
      auth: [jwt]
      middlewares: [dbqueryhook]
```

`internal: true` hides `app` from `/api/` and from the `GET /` catalog. `/restapi` can still use it. `public` has no `internal` flag, so `/api/public/` stays. A missing `auth` key inherits the parent. An API with no `auth` key tries every loaded plugin. `auth: []` tries no auth plugin. v1 sets `anon_claims` to `{sub: ""}`. An empty map does not survive a failed plugin: `len` zero is treated as no anonymous claims once a plugin was tried. This one-key map does continue, with an empty `sub`, which is the anonymous row owner. A scope check can still answer 403 when the endpoint is not `public`.

`/restapi` runs `global_request_middlewares` and the API `middlewares` list. A connection `request_middlewares` list is for `/api/` routes. The example hangs `dbqueryhook`, `cache-postgres`, and `ratelimit` on v1 for that reason. v2 keeps the hook and drops the cache and the limiter.

## 6. Users and todos

An empty `actions` map enables five routes: `list` `GET`, `create` `POST`, `retrieve` `GET {id}`, `update` `PATCH {id}`, `destroy` `DELETE {id}`. The file names those five on `users` and `todos` because `list` and `create` carry extra keys. Naming them is the same set of routes.

`todos` adds `filters.done` with `op: eq`. A query parameter uses `eq` when `op` is omitted, and the column defaults to the parameter name. The value is the raw query string, so `done` is `text` in `schema.sql` and `?done=false` matches the seed rows. `users` list selects and orders only `id`, `name`, and `email`.

```yaml
        users:
          table: users
          auth: [dbsession, jwt]
          required_scopes: [users-read]
          actions:
            list:
              fields: [id, name, email]
        todos:
          table: todos
          auth: [dbsession, jwt]
          public: true
          filters:
            done:
              op: eq
```

`list_actions.export` is `POST /restapi/v1/users/export/` and calls `app.export_users`. The body field is `format`. `detail_actions.archive` is `POST /restapi/v1/users/{id}/archive/` and calls `app.archive_user`. `id` is not listed under `fields`. The path supplies it, and a field with the primary-key name is rejected at startup.

```yaml
          detail_actions:
            archive:
              func: app.archive_user
              required_scopes: [users-write]
              fields:
                reason:
                  type: string
          list_actions:
            export:
              func: app.export_users
              fields:
                format:
                  type: string
                rows:
                  type: integer
                  readOnly: true
                secret:
                  type: string
                  writeOnly: true
```

`create.type: func` calls a function whose name is the endpoint table. On `todos` that name is `todos`, resolved through `search_path=app`. Arguments are the body keys in sorted order. `fields: [title]` leaves a single argument.

The tables and the two functions. They return `text` that is a JSON object. The Postgres plugin unmarshals a text column. A `json` result can arrive as a Go map, and that map is printed with `%v`, which is not JSON, so the handler cannot read the fields.

```sql
CREATE TABLE IF NOT EXISTS app.users (
  id text PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  password text NOT NULL,
  org_id text NOT NULL DEFAULT '',
  city text NOT NULL DEFAULT '',
  settings jsonb NOT NULL DEFAULT '{}'::jsonb,
  avatar text NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS app.todos (
  id text PRIMARY KEY,
  title text NOT NULL,
  done text NOT NULL DEFAULT 'false',
  owner text NOT NULL DEFAULT ''
);

CREATE OR REPLACE FUNCTION app.export_users(format text) RETURNS text
LANGUAGE plpgsql AS $$
BEGIN
  RETURN json_build_object(
    'format', coalesce(format, 'json'),
    'rows', (SELECT count(*) FROM app.users),
    'secret', 'hidden'
  )::text;
END;
$$;

CREATE OR REPLACE FUNCTION app.archive_user(id text, reason text) RETURNS text
LANGUAGE plpgsql AS $$
BEGIN
  IF app.current_sub() = '' THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'sign in required')::text;
  END IF;
  UPDATE app.users
  SET settings = settings || jsonb_build_object('archived', true, 'reason', coalesce(reason, ''))
  WHERE users.id = archive_user.id;
  PERFORM set_config('response.status', '202', true);
  PERFORM set_config('cache.invalidate', 'users,todos', true);
  RETURN json_build_object('id', id, 'reason', reason, 'accepted', true)::text;
END;
$$;
```

`archive_user(id, reason)` matches the sorted keys `id`, then `reason`. `app.current_sub()` is defined in chapter 10. The seed row `public-1` has an empty owner. With the policy in that chapter, a request with no `sub` sees that row and not `ada-1`.

```bash
curl -s 'http://127.0.0.1:8081/restapi/v1/todos/'
curl -s -X POST 'http://127.0.0.1:8081/restapi/v1/users/ada/archive/' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=THE_SESSION_ID' \
  -d '{"reason":"left the team"}'
```

The list body is a JSON object with `count`, `next`, `previous`, and `results`. `count` appears when a count was requested. The archive response uses status 202 once the function runs, because `archive_user` sets `response.status`. The HTTP body keeps declared fields, so that response is `{"reason":"left the team"}`. Chapter 8 is where that status is applied. `users` also requires the `users-read` scope, so a cookie from chapter 13 is what makes `GET /restapi/v1/users/` succeed. `todos` is `public: true`, which skips the scope check.

`export_users` returns `format`, `rows`, and `secret`. The `writeOnly` flag drops `secret` from the HTTP body. `rows` is `readOnly`, so it is not a function argument. A body of `{"format":"csv"}` calls `export_users(format)`. The response includes `format` and `rows`, and `rows` is the count of `app.users`. A body that also sends `secret` looks for `export_users(format, secret)`. This function does not have that argument, so that request is 500.

## 7. Knobs on an endpoint

These keys are all in [examples/application/config.yaml](examples/application/config.yaml).

`actions: {placeholder: {}}` turns off the five standard routes. `placeholder` is not registered. `me`, `discovery`, and `login` use it so only the state or list actions remain. On `login` the endpoint `url` is `/`, and a standard `GET` list would have occupied `/restapi/v1/`, which is the spec page.

```yaml
        me:
          actions:
            placeholder: {}
```

`directory` list accepts JSON and renders CSV. Setting either list selects that level.

```yaml
            list:
              fields: [id, name]
              parsers: [json]
              renderers: [csv]
```

`labels` list sets `parsers: []` and `renderers: [json]`. An empty list selects this level. Omitting both keys would fall through to `application.parsers`.

`discovery`, `directory`, and `login` set `auth: []`, so no auth plugin runs. They also set `public: true`. With no auth list the server still checks a scope named after the endpoint, such as `login-write`, unless `public` skips that check. `todos` sets `public: true` and still lists `dbsession` and `jwt`. `public` skips the scope check. It does not skip those plugins. A missing cookie falls through to `anon_claims`.

`users` sets `required_scopes: [users-read]` for every action on that endpoint. `create` and `archive` replace it with `[users-write]`. A non-empty action list replaces the endpoint list for that action. v1 `users` is not `public`, so the check runs. v2 `todos` is the same idea for a JWT caller:

```yaml
        todos:
          table: todos
          required_scopes: [todos-read]
```

`check_scope` is true in the example. A claim `scope` of `read` satisfies any required scope that ends in `read`. `write` works the same way. The login function stores `read write`.

`openid_configuration` sets `url: openid-configuration` and `no_trailing_slash: true`. The route is `/restapi/v1/.well-known/openid-configuration` with no final slash. The slashed form is not registered. The OpenAPI path matches the registered form.

`org_users` sets `url: orgs/{org_id}/users`. `{org_id}` is added to the row filter and to POST function arguments. `{id}` is still the primary key, so retrieve is `/restapi/v1/orgs/{org_id}/users/{id}/`.

```yaml
        org_users:
          url: orgs/{org_id}/users
          table: users
          auth: [dbsession, jwt]
```

`users` create marks `note` as `readOnly: true`. That key is removed from the write. `export` marks `secret` as `writeOnly: true`. A function response omits `writeOnly` keys. The handler strips `readOnly` keys before the plugin call. Postgres still accepts the column if some other client writes it.

## 8. Request context on every action

List, retrieve, create, update, destroy, `type: func`, detail POST, list POST, and state GET and PUT all open a plugin context, run `PreRequest`, then call the database with that context. After the call, the server applies the context the plugin returned, runs `PostRequest`, writes `response.header.*` and `response.headers`, and then applies `response.status`.

On Postgres each top-level context key is stored twice, as `request.<key>` and `erctx.<key>`, for the current transaction. Maps and slices are JSON. `request.claims` is the claim object. The subject is:

```sql
current_setting('request.claims', true)::jsonb->>'sub'
```

Keys that start with `_`, keys under `response.*` and `cache.*`, and the hook names are not copied into the session. The handler passes an empty user id on create, update, delete, and function calls. SQL that needs the caller reads `request.claims`.

A separate flat map is used when a query parameter or a JSON value is the literal `erctx.claims_sub`. The host replaces that token before the statement is built. Dots and dashes in keys become underscores. Values that contain `;` or `--` are left out of the flat map. MySQL also writes those flat names as session variables. Postgres does not create a GUC named `erctx.claims_sub` from a nested claim.

`archive_user` sets `response.status` to `202`. `todos(title text)` sets `201` and a `Location` header. The create handler already uses 201. The header is the part SQL adds. State PUT on `/me/settings/` sets `204`. A 204 response has an empty body. The function still returns the object, and Go does not send that body with status 204.

`response.headers` is a JSON array of one-key objects:

```sql
PERFORM set_config(
  'response.headers',
  json_build_array(json_build_object('Location', '/restapi/v1/todos/' || new_id || '/'))::text,
  true
);
```

Headers that share a name are joined with `, `. One response can carry one `Set-Cookie`. A context key `response.header.X-Name` is also copied to the response. The SQL that this server harvests is `response.headers`, `response.status`, other `response.*` settings Postgres will store, and `cache.invalidate`. An invalid `response.status` becomes 500.

```bash
curl -s -D - -X POST 'http://127.0.0.1:8081/restapi/v1/todos/' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=THE_SESSION_ID' \
  -d '{"title":"Buy milk"}'
```

The status is 201 and `Location` points at the new id. A POST with an empty `title` is the 422 case in the next chapter.

## 9. Errors from SQL

`RAISE EXCEPTION` aborts the statement. The Postgres plugin returns that error before it reads `response.*`, because those settings are transaction-local and the transaction is rolled back. The HTTP status is 500 and the body is the error text. A `set_config('response.status', ...)` earlier in the same transaction is discarded with it.

To answer 422, set the status and return an object:

```sql
  IF title IS NULL OR btrim(title) = '' THEN
    PERFORM set_config('response.status', '422', true);
    RETURN json_build_object('error', 'title is required')::text;
  END IF;
```

```bash
curl -s -D - -X POST 'http://127.0.0.1:8081/restapi/v1/todos/' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=THE_SESSION_ID' \
  -d '{"title":"  "}'
```

The status is 422 and the body is `{"error":"title is required"}`. If a later statement in that same function raises, the 422 is lost and the client gets 500.

## 10. Row level security and a pre-request hook

`todos` enables row security and forces it for the table owner. The connection role in the example is `app_conn`, created `NOSUPERUSER` and `NOBYPASSRLS`, and it does not own the table. A superuser still bypasses the policy, including when `FORCE ROW LEVEL SECURITY` is set. That is why the URI is not the `postgres` role.

```sql
CREATE OR REPLACE FUNCTION app.current_sub() RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT coalesce(
    CASE
      WHEN coalesce(current_setting('request.claims', true), '') = '' THEN NULL
      ELSE current_setting('request.claims', true)::jsonb ->> 'sub'
    END,
    ''
  );
$$;

ALTER TABLE app.todos ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.todos FORCE ROW LEVEL SECURITY;

CREATE POLICY todos_owner ON app.todos
  USING (owner = app.current_sub())
  WITH CHECK (owner = app.current_sub());
```

List, retrieve, update, and destroy then see only rows whose `owner` equals the claim `sub`. An anonymous request has an empty subject, so it sees the seed row `public-1` and not `ada-1`. A session for Ada sees `ada-1` only. Inserts must use the same owner or `WITH CHECK` rejects them. `todos(title)` writes `app.current_sub()`.

`dbqueryhook` runs `SELECT app.pre_request()` at the start of the transaction, before the statement. v1 and v2 both list that middleware. The function reads the claim, rejects a role outside `app_reader` and `app_writer` with status 403, and otherwise runs `SET LOCAL ROLE`. `app_conn` is a member of both roles, which is what `SET ROLE` requires. `app_reader` and `app_writer` also need `USAGE` on schema `app`. Without it, Postgres hides those tables and the request reports that the relation does not exist.

```yaml
middleware_plugins:
  dbqueryhook:
    settings:
      by_key:
        app:
          pre_request: app.pre_request
```

```sql
CREATE OR REPLACE FUNCTION app.pre_request() RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  claims jsonb;
  wanted text;
  fn text := coalesce(current_setting('request.function', true), '');
BEGIN
  IF fn IN ('app.login', 'app.logout', 'app.openid_configuration') THEN
    RETURN;
  END IF;
  IF coalesce(current_setting('request.claims', true), '') = '' THEN
    claims := '{}'::jsonb;
  ELSE
    claims := current_setting('request.claims', true)::jsonb;
  END IF;
  IF current_setting('request.method', true) IN ('POST', 'PUT', 'PATCH', 'DELETE')
     AND coalesce(claims->>'sub', '') = '' THEN
    PERFORM set_config('response.status', '403', true);
  END IF;
  wanted := claims->>'role';
  IF wanted IS NOT NULL AND wanted <> '' THEN
    IF wanted NOT IN ('app_reader', 'app_writer') THEN
      PERFORM set_config('response.status', '403', true);
      RETURN;
    END IF;
    EXECUTE format('SET LOCAL ROLE %I', wanted);
  END IF;
END;
$$;
```

The hook runs for every action that opens a context, including POST and PUT. Setting the status does not cancel the statement. The statement still runs, and the status is applied when it commits. `todos` and `archive_user` therefore return before they write when `app.current_sub()` is empty. `app.login`, `app.logout`, and `app.openid_configuration` return immediately so a signed-out caller can still log in. A `RAISE` inside the hook aborts the statement and, as in chapter 9, drops the status you just set.

## 11. State actions

A state action is GET and PUT. `post: true` is valid only with `func`, and then the write method is POST. `source_field` and `func` cannot both be set. The action name matches `[a-z0-9_]+`. `url` replaces that name in the path. It is one segment matching `[a-z0-9_.-]+`, and it is not `.` or `..`. List and detail actions use the same `url` rule.

Column settings live on `users.settings`, which is `jsonb`. The route is `GET` and `PUT /restapi/v1/users/{id}/settings/`.

```yaml
          state_actions:
            settings:
              source_field: settings
              fields:
                theme:
                  type: string
                locale:
                  type: string
```

GET reads that column. The value has to be a JSON object. PUT writes the body back into the column and responds `{"updated": n}`. The caller can address any user id the auth check allows. That fits an admin tool. It is a poor fit for "my settings", because the id is in the URL.

The signed-in user uses `me`. Standard routes are off. GET and PUT `/restapi/v1/me/settings/` call `app.my_settings`. GET passes no body, so the call is `my_settings()` with no arguments. PUT passes the body. Keys are sorted, and both `locale` and `theme` are sent, so the call is `my_settings(locale, theme)`. A body with only one of those keys would look for a different signature.

```yaml
        me:
          actions:
            placeholder: {}
          auth: [dbsession, jwt]
          state_actions:
            settings:
              func: app.my_settings
              fields:
                theme:
                  type: string
                locale:
                  type: string
```

```sql
CREATE OR REPLACE FUNCTION app.my_settings() RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  who text := app.current_sub();
  row app.user_settings%ROWTYPE;
BEGIN
  IF who = '' THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'sign in required')::text;
  END IF;
  SELECT * INTO row FROM app.user_settings WHERE sub = who;
  IF NOT FOUND THEN
    RETURN json_build_object('theme', 'light', 'locale', 'en')::text;
  END IF;
  RETURN json_build_object('theme', row.theme, 'locale', row.locale)::text;
END;
$$;

CREATE OR REPLACE FUNCTION app.my_settings(locale text, theme text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  who text := app.current_sub();
BEGIN
  IF who = '' THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'sign in required')::text;
  END IF;
  INSERT INTO app.user_settings (sub, theme, locale)
  VALUES (who, coalesce(theme, 'light'), coalesce(locale, 'en'))
  ON CONFLICT (sub) DO UPDATE
    SET theme = excluded.theme, locale = excluded.locale;
  PERFORM set_config('response.status', '204', true);
  RETURN json_build_object('theme', theme, 'locale', locale)::text;
END;
$$;
```

```bash
curl -s 'http://127.0.0.1:8081/restapi/v1/me/settings/' \
  -H 'Cookie: session=THE_SESSION_ID'
curl -s -D - -X PUT 'http://127.0.0.1:8081/restapi/v1/me/settings/' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=THE_SESSION_ID' \
  -d '{"theme":"dark","locale":"en"}'
```

GET returns the stored object, or the defaults when the user has no row. PUT returns 204 and an empty body.

The action key stays `openid_configuration` because names match `[a-z0-9_]+`. `url: openid-configuration` is the path segment. The endpoint `url` is `.well-known`, and `no_trailing_slash` is set. The path is `/restapi/v1/.well-known/openid-configuration`. It is under `/restapi/v1/`. A client that wants `https://host/.well-known/openid-configuration` needs a rewrite on the proxy. `auth: []` leaves the document unsigned-in.

```yaml
        discovery:
          url: .well-known
          auth: []
          public: true
          actions:
            placeholder: {}
          state_actions:
            openid_configuration:
              url: openid-configuration
              func: app.openid_configuration
              no_trailing_slash: true
              fields:
                issuer:
                  type: string
```

The plpgsql function reads `request.request` and builds `issuer` from `host`. That object is the public URL: scheme, host, and prefix. Header names in `request.headers` are lower case, and that map does not contain `Host`.

```sql
CREATE OR REPLACE FUNCTION app.openid_configuration() RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  req jsonb;
  host text;
BEGIN
  IF coalesce(current_setting('request.request', true), '') = '' THEN
    req := '{}'::jsonb;
  ELSE
    req := current_setting('request.request', true)::jsonb;
  END IF;
  host := coalesce(req->>'host', 'localhost');
  RETURN json_build_object(
    'issuer', 'http://' || host || '/restapi/v1'
  )::text;
END;
$$;
```

`schema.sql` also has the same function in `plpython3u` and in `plv8`, both commented. `plpython3u` is untrusted, so a superuser has to create it. `plv8` needs that extension installed first. Uncomment one block only when that language is on the server. The route in the config keeps calling `app.openid_configuration`.

```bash
curl -s 'http://127.0.0.1:8081/restapi/v1/.well-known/openid-configuration'
```

The body is `{"issuer":"http://127.0.0.1:8081/restapi/v1"}` when the public host is `127.0.0.1:8081`.

## 12. Files

A string field with `format: binary`, or an array of those strings, is a file. `users` create adds `avatar` that way and stores it with `avatars_inline`. `photos` create adds `image` and stores it with the `photos` plugin. Storage is chosen from the action, then the endpoint, then the application, then `default_storage_plugin`.

```yaml
            create:
              storage: avatars_inline
              required_scopes: [users-write]
              extra_fields:
                avatar:
                  type: string
                  format: binary
                note:
                  type: string
                  readOnly: true
```

```yaml
        photos:
          table: photos
          auth: [dbsession, jwt]
          storage: photos
```

```yaml
  avatars_inline:
    plugin: local
    settings:
      dir: ./avatars
      inline: true
  photos:
    plugin: s3
    settings:
      endpoint: http://127.0.0.1:9000
      region: us-east-1
      bucket: easyrest-photos
      access_key: minio
      secret_key: minio-secret
      path_style: true
      public_base: http://127.0.0.1:9000/easyrest-photos
```

A multipart body has one part without a filename. That part is the document, parsed with its own `Content-Type` (JSON when the part type is empty). Each file part has a filename and a name that matches the field.

```bash
curl -s -X POST 'http://127.0.0.1:8081/restapi/v1/users/' \
  -H 'Cookie: session=THE_SESSION_ID' \
  -F 'doc={"name":"Grace","email":"grace@example.com","password":"secret"};type=application/json' \
  -F 'avatar=@portrait.png;type=image/png'
```

`inline: true` stores a data URL in the column and in the response. That instance does not mount `/media`. The `photos` plugin leaves `inline` false and sets `public_base`, so GET returns `public_base` plus the object key. If `photos` cannot reach the bucket at startup, that plugin is skipped and a photo upload fails. Avatar upload uses local disk and does not need S3.

`format: base64` stays on the ordinary JSON body. The string is a data URL. The decoded bytes go to the same storage plugin. An empty string leaves the field unset. A value that is not a data URL is 400. OpenAPI GET schemas use `format: uri` for a stored file. An inline field uses `format: data-url` on the response. Request schemas keep `binary` or `base64`.

## 13. Login and logout with cookies

`login` uses `url: /` and `auth: []`, with the five standard routes disabled. `list_actions.login` is `POST /restapi/v1/login/`. `list_actions.logout` is `POST /restapi/v1/logout/`. Both set `auth: []` again. The plugin sorts `email` before `password`, and the function arguments are in that order.

```yaml
        login:
          url: /
          auth: []
          public: true
          actions:
            placeholder: {}
          list_actions:
            login:
              func: app.login
              auth: []
              fields:
                email:
                  type: string
                password:
                  type: string
                  writeOnly: true
                sub:
                  type: string
                  readOnly: true
                error:
                  type: string
                  readOnly: true
            logout:
              func: app.logout
              auth: []
              fields:
                ok:
                  type: boolean
                  readOnly: true
```

`app.login` checks `crypt()` from `pgcrypto`. The extension lives in schema `app`, because the connection `search_path` is only `app`. The row variable is named `person`. A variable named `found` would hide the `FOUND` flag, and `IF NOT FOUND` would then try to negate a row. The function inserts `sessions (id, claims jsonb, exp text)` and sets one `Set-Cookie`. `exp` is text because the Postgres plugin formats `timestamptz` as `2006-01-02 15:04:05`, and `dbsession` parses RFC3339. A `timestamptz` column would fail that parse. The value written here is `YYYY-MM-DD"T"HH24:MI:SS"Z"`.

```sql
  exp := to_char((now() AT TIME ZONE 'utc') + interval '7 days', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
  body := jsonb_build_object('sub', person.id, 'scope', 'read write', 'role', 'app_writer');
  INSERT INTO app.sessions (id, claims, exp) VALUES (sid, body, exp);
  PERFORM set_config(
    'response.headers',
    json_build_array(json_build_object(
      'Set-Cookie',
      'session=' || sid || '; HttpOnly; Secure; SameSite=Lax; Path=/'
    ))::text,
    true
  );
```

`claims` is a JSON object. `dbsession` rejects a string in that column. `app.logout` deletes the row whose id is `request.cookie.session` and sends the same cookie with `Max-Age=0`.

```yaml
auth_plugins:
  dbsession:
    settings:
      plugin: app
      table: sessions
internal_rpc:
  network: unix
  address: ./easyrest.sock
```

`dbsession` reads the session with `TableGet` over internal RPC. It does not set the cookie. The host copies the cookie into the header map before `Authenticate`. `plugin: app` still works when `app` is `internal: true`, because internal RPC does not use the HTTP auth on `/api/`. A missing `internal_rpc` listener fails those reads with `host rpc is not configured`. The cookie name defaults to `session`. A missing, unparsable, or past `exp` fails the request.

```bash
curl -s -D - -X POST 'http://127.0.0.1:8081/restapi/v1/login/' \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"secret"}'
curl -s -D - -X POST 'http://127.0.0.1:8081/restapi/v1/logout/' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=THE_SESSION_ID' \
  -d '{}'
```

The login response carries one `Set-Cookie` and `{"sub":"ada"}`. A wrong password is 401 and `{"error":"invalid email or password"}`, from `response.status` in `app.login`. Logout clears the cookie.

`jwtsession` is the other cookie plugin. The function would sign a JWT and put that token in `Set-Cookie`. The plugin only reads it. Settings are in [plugins/auth/jwtsession/README.md](plugins/auth/jwtsession/README.md). This example uses `dbsession` so the session row can be deleted on logout. Details of the table read are in [plugins/auth/dbsession/README.md](plugins/auth/dbsession/README.md).

`Secure` on the cookie means a browser will not send it on plain `http://`. Use HTTPS, or drop `Secure` from the SQL if you are on localhost without TLS. `curl` sends a `Cookie` header you pass on the command line. A cookie jar does not replay a `Secure` cookie onto `http://`.

## 14. Cache and dry runs

v1 includes `cache-postgres`. The cache URI drops `search_path`, so `schema.sql` grants `app_conn` `CREATE` on `public`, where `easyrest_cache` is created. List and retrieve on a table with an explicit `table` send an `ETag` and `Resource-Version`. The store key is `etag:<db>:<table>`. Schema and routes with no table in the context are skipped. `If-None-Match` on GET can return 304. The tag has to be quoted. `If-Match` on PATCH compares the stored revision and returns 412 when it does not match. The lost-update rules are in [plugins/middleware/cache/README.md](plugins/middleware/cache/README.md).

`archive_user` sets `cache.invalidate` to `users,todos`. After a successful call the middleware bumps those tables. The same middleware also has `invalidation_map` for the function name `app.archive_user`. Either path drops the cached revision. The map runs when the context carries that function name. `set_config` runs from the SQL you control.

```yaml
  cache-postgres:
    settings:
      uri: postgres://app_conn:app_conn@127.0.0.1:5432/easyrest_app?sslmode=disable&autoCleanup=true
      ttl: 24h
      invalidation_map:
        app:
          app.archive_user: [users, todos]
```

`plugins.app` sets `db_tx_end: commit-allow-override`. `Prefer: tx=rollback` is honored only when the value ends in `-allow-override`. The POST then returns the normal body and the transaction is rolled back, so the row is not kept. `Prefer: tx=commit` forces a commit under the same setting.

```bash
curl -s -D - 'http://127.0.0.1:8081/restapi/v1/todos/'
curl -s -D - -X POST 'http://127.0.0.1:8081/restapi/v1/todos/' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=THE_SESSION_ID' \
  -H 'Prefer: tx=rollback' \
  -d '{"title":"Dry run"}'
```

The second call can still say 201. A following GET does not include `Dry run`.

v1 also includes `ratelimit` at 100 requests per minute for a global key. Over the limit the status is 429, with `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining`. v2 does not list that middleware.

## 15. What the OpenAPI document shows

`GET /restapi/v1/?format=json` is the v1 document. `GET /restapi/v1/?format=html` is the embedded Swagger page. Each operation has a `security` array of the auth plugins that actually apply. `discovery`, `directory`, `labels`, and `login` emit `"security": []` because their auth list is empty. An `oauth2` scheme would list the effective scopes. The other schemes list no scopes.

A `binary` field stays `binary` on the request schema. On the response, a stored file is `uri`, and an inline file is `data-url`.

A JSON list is one object:

```json
{"count": 1, "next": null, "previous": null, "results": []}
```

`count` is present when a count ran. `next` is null unless a count is present and `offset+limit` is still below it. `previous` is null when `offset` is 0. Ask for a count with `Prefer: count=exact`. CSV lists put pagination in a `Link` header (`rel="prev"`, `rel="next"`, and `rel="count"; total="N"` when a count exists) and the body is the rows. The `directory` list renders CSV. An NDJSON list puts `{count?, next, previous}` on the first line and one row per following line. Later pages of that NDJSON response do not repeat `count`, `next`, or `previous`.

`directory` list fields are `id` and `name`. `ordering=email` is 400 with `invalid ordering` because `email` is not in that list. `?city=Berlin` still filters, because `filters.city` is separate from `fields`.

## 16. Combinations and MySQL

v1 tries `dbsession` and `jwt`, then `anon_claims: {}` if both fail. v2 tries only `jwt` and requires `todos-read`. v1 is the catalog the page uses. v2 is the scoped read of the same `todos` table.

`middlewares: [ratelimit]` is only on v1. A client that calls `/restapi/v2/todos/` does not consume that limit.

`directory` shows list `fields` together with `filters.city`. `ordering=email` is rejected. `users` list includes `email`, so `ordering=email` is allowed there and `ordering=city` is not.

`application.parsers` and `application.renderers` are `[json, yaml]`. Send `Accept: application/yaml` on a route that does not override renderers, such as `GET /restapi/v1/todos/`. `labels` forces JSON even if the client asks for YAML, because its renderer list is only `json`. The YAML plugin is loaded by `content_plugins.yaml: {}` inside `easyrest-server`. See [cmd/content-yaml/README.md](cmd/content-yaml/README.md).

MySQL can host the same routes if you point `plugins.app.uri` at it and accept a shorter session model. The plugin writes flat context keys as `SET @request_<key>` and `@erctx_<key>`, so `@erctx_claims_sub` exists there. A hook is `CALL name()`. A procedure can set `@response.status` and `@response.headers`. Row security and `SET LOCAL ROLE` are Postgres-only, so this example's policy and role switch have no MySQL equivalent. The URI and the hook form are in [plugins/data/mysql/README.md](plugins/data/mysql/README.md). SQLite does not receive session variables, so `set_config` and the pre-request hook do nothing useful on the `public` connection.
