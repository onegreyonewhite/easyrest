-- Apply as a superuser:
--   createdb easyrest_app
--   psql -v ON_ERROR_STOP=1 -d easyrest_app -f schema.sql
--
-- The HTTP connection is app_conn, not a superuser. Row security applies to
-- that role. A superuser still bypasses it.

CREATE SCHEMA IF NOT EXISTS app;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_extension e
    JOIN pg_namespace n ON n.oid = e.extnamespace
    WHERE e.extname = 'pgcrypto' AND n.nspname <> 'app'
  ) THEN
    ALTER EXTENSION pgcrypto SET SCHEMA app;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_reader') THEN
    CREATE ROLE app_reader NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_writer') THEN
    CREATE ROLE app_writer NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_conn') THEN
    CREATE ROLE app_conn LOGIN PASSWORD 'app_conn' NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;

GRANT app_reader TO app_conn;
GRANT app_writer TO app_conn;
GRANT USAGE, CREATE ON SCHEMA app TO app_conn;
GRANT USAGE ON SCHEMA app TO app_reader, app_writer;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app TO app_reader, app_writer, app_conn;
-- cache-postgres creates easyrest_cache in public. Its URI drops search_path.
GRANT CREATE ON SCHEMA public TO app_conn;
GRANT app_reader TO app_writer;

CREATE TABLE IF NOT EXISTS app.users (
  id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
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

CREATE TABLE IF NOT EXISTS app.user_settings (
  sub text PRIMARY KEY,
  theme text NOT NULL DEFAULT 'light',
  locale text NOT NULL DEFAULT 'en'
);

CREATE TABLE IF NOT EXISTS app.sessions (
  id text PRIMARY KEY,
  claims jsonb NOT NULL,
  exp text NOT NULL
);

CREATE TABLE IF NOT EXISTS app.photos (
  id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  image text NOT NULL DEFAULT '',
  owner text NOT NULL DEFAULT ''
);

CREATE OR REPLACE VIEW app.user_directory AS
  SELECT id, name, email, city FROM app.users;

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

DROP FUNCTION IF EXISTS app.todos(text);
DROP FUNCTION IF EXISTS app.archive_user(text, text);
DROP FUNCTION IF EXISTS app.export_users(text);
DROP FUNCTION IF EXISTS app.login(text, text);
DROP FUNCTION IF EXISTS app.logout();
DROP FUNCTION IF EXISTS app.my_settings();
DROP FUNCTION IF EXISTS app.my_settings(text, text);
DROP FUNCTION IF EXISTS app.openid_configuration();

CREATE OR REPLACE FUNCTION app.todos(title text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  new_id text := gen_random_uuid()::text;
BEGIN
  IF app.current_sub() = '' THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'sign in required')::text;
  END IF;
  IF title IS NULL OR btrim(title) = '' THEN
    PERFORM set_config('response.status', '422', true);
    RETURN json_build_object('error', 'title is required')::text;
  END IF;
  INSERT INTO app.todos (id, title, done, owner)
  VALUES (new_id, title, 'false', app.current_sub());
  PERFORM set_config('response.status', '201', true);
  PERFORM set_config(
    'response.headers',
    json_build_array(json_build_object('Location', '/restapi/v1/todos/' || new_id || '/'))::text,
    true
  );
  RETURN json_build_object('id', new_id, 'title', title, 'done', 'false', 'owner', app.current_sub())::text;
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

CREATE OR REPLACE FUNCTION app.login(email text, password text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  person app.users%ROWTYPE;
  sid text := gen_random_uuid()::text;
  exp text;
  body jsonb;
BEGIN
  SELECT * INTO person
  FROM app.users AS u
  WHERE u.email = login.email
    AND u.password = crypt(login.password, u.password);
  IF NOT FOUND THEN
    PERFORM set_config('response.status', '401', true);
    RETURN json_build_object('error', 'invalid email or password')::text;
  END IF;
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
  RETURN json_build_object('sub', person.id)::text;
END;
$$;

CREATE OR REPLACE FUNCTION app.logout() RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  sid text := coalesce(current_setting('request.cookie.session', true), '');
BEGIN
  IF sid <> '' THEN
    DELETE FROM app.sessions WHERE id = sid;
  END IF;
  PERFORM set_config(
    'response.headers',
    json_build_array(json_build_object(
      'Set-Cookie',
      'session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
    ))::text,
    true
  );
  RETURN json_build_object('ok', true)::text;
END;
$$;

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

-- PUT sends both keys. The plugin sorts them, so the signature is (locale, theme).
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

-- Optional. plpython3u is untrusted, so a superuser creates the function.
-- The body is the same document as app.openid_configuration.
--
-- CREATE EXTENSION IF NOT EXISTS plpython3u;
-- CREATE OR REPLACE FUNCTION app.openid_configuration_py() RETURNS text
-- LANGUAGE plpython3u AS $$
-- import json
-- raw = plpy.execute("SELECT current_setting('request.request', true) AS h")[0]["h"] or "{}"
-- req = json.loads(raw)
-- host = req.get("host") or "localhost"
-- return {"issuer": "http://%s/restapi/v1" % host}
-- $$;

-- Optional. Requires the plv8 extension.
--
-- CREATE EXTENSION IF NOT EXISTS plv8;
-- CREATE OR REPLACE FUNCTION app.openid_configuration_js() RETURNS text
-- LANGUAGE plv8 AS $$
--   var rows = plv8.execute("SELECT current_setting('request.request', true) AS h");
--   var req = JSON.parse((rows[0] && rows[0].h) || "{}");
--   var host = req.host || "localhost";
--   return { issuer: "http://" + host + "/restapi/v1" };
-- $$;

INSERT INTO app.users (id, name, email, password, org_id, city, settings)
VALUES (
  'ada',
  'Ada',
  'ada@example.com',
  app.crypt('secret', app.gen_salt('bf')),
  'acme',
  'Berlin',
  '{"theme":"light","locale":"en"}'::jsonb
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO app.todos (id, title, done, owner)
VALUES ('public-1', 'Read the guide', 'false', '')
ON CONFLICT (id) DO NOTHING;

INSERT INTO app.todos (id, title, done, owner)
VALUES ('ada-1', 'Ship the API', 'false', 'ada')
ON CONFLICT (id) DO NOTHING;

ALTER TABLE app.todos ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.todos FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS todos_owner ON app.todos;
CREATE POLICY todos_owner ON app.todos
  USING (owner = app.current_sub())
  WITH CHECK (owner = app.current_sub());

ALTER TABLE app.users ALTER COLUMN id SET DEFAULT gen_random_uuid()::text;
ALTER TABLE app.photos ALTER COLUMN id SET DEFAULT gen_random_uuid()::text;

GRANT SELECT ON app.users, app.todos, app.user_settings, app.sessions, app.photos, app.user_directory TO app_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.users, app.todos, app.user_settings, app.sessions, app.photos TO app_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.users, app.todos, app.user_settings, app.sessions, app.photos TO app_conn;
GRANT SELECT ON app.user_directory TO app_conn;
