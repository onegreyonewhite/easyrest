CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS plpython3u;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_owner') THEN
    CREATE ROLE auth_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_conn') THEN
    CREATE ROLE auth_conn LOGIN PASSWORD 'auth_conn' NOSUPERUSER NOBYPASSRLS;
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION auth_owner;
GRANT USAGE ON SCHEMA auth TO auth_conn;
GRANT CONNECT ON DATABASE auth TO auth_conn;
ALTER ROLE auth_conn IN DATABASE auth SET search_path = auth, public;

CREATE TABLE auth.settings (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  issuer text NOT NULL
);

CREATE TABLE auth.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text NOT NULL,
  password text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_username_lower ON auth.users (lower(username));

CREATE TABLE auth.profiles (
  user_id uuid PRIMARY KEY REFERENCES auth.users (id),
  given_name text,
  family_name text,
  middle_name text,
  nickname text,
  email text NOT NULL,
  email_verified boolean NOT NULL DEFAULT false,
  picture text,
  locale text,
  zoneinfo text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX profiles_email_lower ON auth.profiles (lower(email));

CREATE TABLE auth.security_groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  description text
);

CREATE TABLE auth.group_scopes (
  id text PRIMARY KEY,
  group_id uuid NOT NULL REFERENCES auth.security_groups (id),
  scope text NOT NULL,
  UNIQUE (group_id, scope)
);

CREATE TABLE auth.group_members (
  id text PRIMARY KEY,
  group_id uuid NOT NULL REFERENCES auth.security_groups (id),
  user_id uuid NOT NULL REFERENCES auth.users (id),
  UNIQUE (group_id, user_id)
);

CREATE TABLE auth.oauth_clients (
  client_id text PRIMARY KEY,
  name text NOT NULL,
  client_secret text,
  require_consent boolean NOT NULL DEFAULT true
);

CREATE TABLE auth.oauth_client_redirects (
  id text PRIMARY KEY,
  client_id text NOT NULL REFERENCES auth.oauth_clients (client_id),
  redirect_uri text NOT NULL,
  UNIQUE (client_id, redirect_uri)
);

CREATE TABLE auth.oauth_consents (
  id text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users (id),
  client_id text NOT NULL REFERENCES auth.oauth_clients (client_id),
  scope text NOT NULL,
  UNIQUE (user_id, client_id)
);

CREATE TABLE auth.authorization_codes (
  code_hash text PRIMARY KEY,
  client_id text NOT NULL REFERENCES auth.oauth_clients (client_id),
  user_id uuid NOT NULL REFERENCES auth.users (id),
  redirect_uri text NOT NULL,
  scope text NOT NULL,
  nonce text,
  code_challenge text NOT NULL,
  auth_time bigint NOT NULL,
  requested_scope text NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);

CREATE TABLE auth.refresh_tokens (
  token_hash text PRIMARY KEY,
  client_id text NOT NULL REFERENCES auth.oauth_clients (client_id),
  user_id uuid NOT NULL REFERENCES auth.users (id),
  scope text NOT NULL,
  auth_time bigint NOT NULL,
  expires_at timestamptz NOT NULL,
  replaced_by text
);

CREATE TABLE auth.sessions (
  id text PRIMARY KEY,
  claims jsonb NOT NULL,
  exp text NOT NULL
);

CREATE TABLE auth.login_attempts (
  client_ip text NOT NULL,
  email text NOT NULL,
  failures integer NOT NULL,
  window_start timestamptz NOT NULL,
  PRIMARY KEY (client_ip, email)
);

CREATE TABLE auth.signing_keys (
  id text PRIMARY KEY,
  alg text NOT NULL,
  pem text NOT NULL
);

CREATE OR REPLACE FUNCTION auth.hash_secret() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'users' THEN
    IF NEW.password IS NOT NULL AND NEW.password NOT LIKE '$2%' THEN
      NEW.password := public.crypt(NEW.password, public.gen_salt('bf'));
    END IF;
  ELSIF TG_TABLE_NAME = 'oauth_clients' THEN
    IF NEW.client_secret IS NOT NULL AND NEW.client_secret NOT LIKE '$2%' THEN
      NEW.client_secret := public.crypt(NEW.client_secret, public.gen_salt('bf'));
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER users_hash_secret
  BEFORE INSERT OR UPDATE OF password ON auth.users
  FOR EACH ROW EXECUTE FUNCTION auth.hash_secret();

CREATE TRIGGER clients_hash_secret
  BEFORE INSERT OR UPDATE OF client_secret ON auth.oauth_clients
  FOR EACH ROW EXECUTE FUNCTION auth.hash_secret();

CREATE OR REPLACE FUNCTION auth.set_scope_id() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id IS NULL OR NEW.id = '' THEN
    NEW.id := NEW.group_id::text || ':' || NEW.scope;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER group_scopes_id
  BEFORE INSERT ON auth.group_scopes
  FOR EACH ROW EXECUTE FUNCTION auth.set_scope_id();

CREATE OR REPLACE FUNCTION auth.set_member_id() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id IS NULL OR NEW.id = '' THEN
    NEW.id := NEW.group_id::text || ':' || NEW.user_id::text;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER group_members_id
  BEFORE INSERT ON auth.group_members
  FOR EACH ROW EXECUTE FUNCTION auth.set_member_id();

CREATE OR REPLACE FUNCTION auth.set_consent_id() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id IS NULL OR NEW.id = '' THEN
    NEW.id := NEW.user_id::text || ':' || NEW.client_id;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER oauth_consents_id
  BEFORE INSERT ON auth.oauth_consents
  FOR EACH ROW EXECUTE FUNCTION auth.set_consent_id();

CREATE OR REPLACE FUNCTION auth.set_redirect_id() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id IS NULL OR NEW.id = '' THEN
    NEW.id := NEW.client_id || ':' || NEW.redirect_uri;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER oauth_client_redirects_id
  BEFORE INSERT ON auth.oauth_client_redirects
  FOR EACH ROW EXECUTE FUNCTION auth.set_redirect_id();

CREATE OR REPLACE FUNCTION auth.current_sub() RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN coalesce(current_setting('request.claims', true), '') = '' THEN ''
    ELSE coalesce(current_setting('request.claims', true)::jsonb ->> 'sub', '')
  END;
$$;

CREATE OR REPLACE FUNCTION auth.has_scope(wanted text) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1
    FROM regexp_split_to_table(
      CASE
        WHEN coalesce(current_setting('request.claims', true), '') = '' THEN ''
        ELSE coalesce(current_setting('request.claims', true)::jsonb ->> 'scope', '')
      END,
      '\s+'
    ) AS s(scope)
    WHERE s.scope <> '' AND s.scope = wanted
  );
$$;

CREATE OR REPLACE FUNCTION auth.pre_request() RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  fn text := coalesce(current_setting('request.function', true), '');
  claims jsonb := '{}'::jsonb;
BEGIN
  IF fn IN (
    'auth.login', 'auth.logout', 'auth.authorize', 'auth.consent', 'auth.token',
    'auth.openid_configuration', 'auth.jwks'
  ) THEN
    RETURN;
  END IF;
  IF coalesce(current_setting('request.claims', true), '') <> '' THEN
    claims := current_setting('request.claims', true)::jsonb;
  END IF;
  IF current_setting('request.method', true) IN ('POST', 'PUT', 'PATCH', 'DELETE')
     AND coalesce(claims ->> 'sub', '') = '' THEN
    PERFORM set_config('response.status', '403', true);
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION auth.safe_next(target text) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  prefix constant text := 'https://localhost:8443/restapi/v1/authorize/start';
BEGIN
  IF target IS NULL OR target = '' THEN
    RETURN NULL;
  END IF;
  IF target = prefix OR target LIKE prefix || '?%' THEN
    IF position('#' IN target) = 0 THEN
      RETURN target;
    END IF;
  END IF;
  IF target IN (
    'https://localhost:8443/',
    'https://localhost:8443/?format=html',
    'https://localhost:8443/media/static/password.html',
    'https://localhost:8443/media/static/callback.html'
  ) THEN
    RETURN target;
  END IF;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION auth.login(p_email text, p_next text, p_password text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  person auth.users%ROWTYPE;
  ip text := coalesce(current_setting('request.client_ip', true), '');
  mail text := lower(coalesce(p_email, ''));
  attempt auth.login_attempts%ROWTYPE;
  sid text := gen_random_uuid()::text;
  exp text;
  auth_time bigint;
  retry integer;
  dest text;
BEGIN
  SELECT * INTO attempt
  FROM auth.login_attempts
  WHERE client_ip = ip AND email = mail;
  IF FOUND AND attempt.failures >= 10 AND attempt.window_start > now() - interval '15 minutes' THEN
    retry := ceil(extract(epoch FROM (attempt.window_start + interval '15 minutes' - now())))::int;
    IF retry < 1 THEN
      retry := 1;
    END IF;
    PERFORM set_config('response.status', '429', true);
    PERFORM set_config(
      'response.headers',
      json_build_array(json_build_object('Retry-After', retry::text))::text,
      true
    );
    RETURN json_build_object('error', 'too many attempts')::text;
  END IF;

  SELECT u.* INTO person
  FROM auth.users AS u
  LEFT JOIN auth.profiles AS p ON p.user_id = u.id
  WHERE (lower(p.email) = mail OR lower(u.username) = mail)
    AND u.status = 'active'
    AND u.password = public.crypt(p_password, u.password);
  IF NOT FOUND THEN
    INSERT INTO auth.login_attempts (client_ip, email, failures, window_start)
    VALUES (ip, mail, 1, now())
    ON CONFLICT (client_ip, email) DO UPDATE
      SET failures = CASE
            WHEN auth.login_attempts.window_start <= now() - interval '15 minutes' THEN 1
            ELSE auth.login_attempts.failures + 1
          END,
          window_start = CASE
            WHEN auth.login_attempts.window_start <= now() - interval '15 minutes' THEN now()
            ELSE auth.login_attempts.window_start
          END;
    PERFORM set_config('response.status', '401', true);
    RETURN json_build_object('error', 'invalid email or password')::text;
  END IF;

  dest := auth.safe_next(p_next);
  IF dest IS NULL AND (p_next IS NULL OR p_next = '') THEN
    dest := 'https://localhost:8443/';
  END IF;
  IF dest IS NULL THEN
    PERFORM set_config('response.status', '400', true);
    RETURN json_build_object('error', 'invalid next')::text;
  END IF;

  DELETE FROM auth.login_attempts
  WHERE client_ip = ip AND email = mail;

  auth_time := extract(epoch FROM now())::bigint;
  exp := to_char((now() AT TIME ZONE 'utc') + interval '12 hours', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
  INSERT INTO auth.sessions (id, claims, exp)
  VALUES (sid, jsonb_build_object('sub', person.id::text, 'auth_time', auth_time), exp);
  PERFORM set_config('response.status', '302', true);
  PERFORM set_config(
    'response.headers',
    json_build_array(
      json_build_object('Set-Cookie', 'session=' || sid || '; HttpOnly; Secure; SameSite=Lax; Path=/'),
      json_build_object('Location', dest)
    )::text,
    true
  );
  RETURN json_build_object('sub', person.id::text)::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.logout() RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  sid text := coalesce(current_setting('request.cookie.session', true), '');
BEGIN
  IF sid <> '' THEN
    DELETE FROM auth.sessions WHERE id = sid;
  END IF;
  PERFORM set_config('response.status', '204', true);
  PERFORM set_config(
    'response.headers',
    json_build_array(json_build_object(
      'Set-Cookie',
      'session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
    ))::text,
    true
  );
  RETURN '{}'::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.rsa_pem() RETURNS text
LANGUAGE plpython3u
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $fn$
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

plpy.execute("SELECT pg_advisory_xact_lock(hashtext('auth.rs256'))")
rows = plpy.execute("SELECT pem FROM auth.signing_keys WHERE alg = 'RS256' ORDER BY id LIMIT 1")
if len(rows) > 0:
    return rows[0]["pem"]
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("ascii")
plpy.execute(
    plpy.prepare(
        "INSERT INTO auth.signing_keys (id, alg, pem) VALUES ($1, 'RS256', $2)",
        ["text", "text"],
    ),
    ["rs256-1", pem],
)
return pem
$fn$;

CREATE OR REPLACE FUNCTION auth.sign_jwt(payload jsonb, alg text) RETURNS text
LANGUAGE plpython3u
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $fn$
import base64
import hashlib
import hmac
import json
from decimal import Decimal
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def plain(value):
    if isinstance(value, dict):
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    if isinstance(value, Decimal):
        integral = value.to_integral_value()
        if value == integral:
            return int(integral)
        return float(value)
    return value

def signing_input(header, body):
    head = b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_part = b64url(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return head + "." + payload_part

body_in = payload
if isinstance(body_in, str):
    body_in = json.loads(body_in)
body = plain(body_in)
header = {"alg": alg, "typ": "JWT"}
if alg == "HS256":
    rows = plpy.execute("SELECT id, pem FROM auth.signing_keys WHERE alg = 'HS256' ORDER BY id LIMIT 1")
    if len(rows) == 0:
        plpy.error("hs256 key missing")
    header["kid"] = rows[0]["id"]
    signed = signing_input(header, body)
    sig = hmac.new(rows[0]["pem"].encode("utf-8"), signed.encode("ascii"), hashlib.sha256).digest()
    return signed + "." + b64url(sig)
if alg == "RS256":
    pem = plpy.execute("SELECT auth.rsa_pem() AS pem")[0]["pem"]
    header["kid"] = "rs256-1"
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    signed = signing_input(header, body)
    sig = key.sign(signed.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return signed + "." + b64url(sig)
plpy.error("unsupported alg " + str(alg))
$fn$;

CREATE OR REPLACE FUNCTION auth.jwks() RETURNS text
LANGUAGE plpython3u
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $fn$
import base64
import json
from cryptography.hazmat.primitives import serialization

def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def b64uint(number):
    length = max((number.bit_length() + 7) // 8, 1)
    return b64url(number.to_bytes(length, "big"))

pem = plpy.execute("SELECT auth.rsa_pem() AS pem")[0]["pem"]
key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
numbers = key.public_key().public_numbers()
return json.dumps({
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "rs256-1",
        "n": b64uint(numbers.n),
        "e": b64uint(numbers.e),
    }]
})
$fn$;

CREATE OR REPLACE FUNCTION auth.openid_configuration() RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $$
DECLARE
  iss text;
BEGIN
  SELECT settings.issuer INTO iss FROM auth.settings LIMIT 1;
  RETURN json_build_object(
    'issuer', iss,
    'authorization_endpoint', iss || '/authorize/start',
    'token_endpoint', iss || '/token',
    'userinfo_endpoint', iss || '/userinfo/claims',
    'jwks_uri', iss || '/jwks/public',
    'scopes_supported', json_build_array(
      'openid', 'profile', 'email', 'groups', 'offline_access',
      'users-read', 'users-write',
      'profiles-read', 'profiles-write',
      'security-groups-read', 'security-groups-write',
      'group-scopes-read', 'group-scopes-write',
      'group-members-read', 'group-members-write',
      'clients-read', 'clients-write',
      'client-redirects-read', 'client-redirects-write',
      'consents-read', 'consents-write'
    ),
    'response_types_supported', json_build_array('code'),
    'subject_types_supported', json_build_array('public'),
    'id_token_signing_alg_values_supported', json_build_array('RS256'),
    'code_challenge_methods_supported', json_build_array('S256'),
    'token_endpoint_auth_methods_supported', json_build_array('client_secret_basic', 'none'),
    'grant_types_supported', json_build_array('authorization_code', 'refresh_token')
  )::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.urldecode(s text) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  src text := replace(coalesce(s, ''), '+', ' ');
  raw bytea := ''::bytea;
  i integer := 1;
  hex text;
BEGIN
  WHILE i <= char_length(src) LOOP
    IF substring(src FROM i FOR 1) = '%' AND substring(src FROM i + 1 FOR 2) ~ '^[0-9A-Fa-f]{2}$' THEN
      hex := substring(src FROM i + 1 FOR 2);
      raw := raw || decode(hex, 'hex');
      i := i + 3;
    ELSE
      raw := raw || convert_to(substring(src FROM i FOR 1), 'utf8');
      i := i + 1;
    END IF;
  END LOOP;
  RETURN convert_from(raw, 'utf8');
END;
$$;

CREATE OR REPLACE FUNCTION auth.urlencode(s text) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  out text := '';
  i integer;
  ch text;
  raw bytea;
BEGIN
  IF s IS NULL THEN
    RETURN '';
  END IF;
  FOR i IN 1..char_length(s) LOOP
    ch := substring(s FROM i FOR 1);
    IF ch ~ '^[A-Za-z0-9_.~-]$' THEN
      out := out || ch;
    ELSE
      raw := convert_to(ch, 'utf8');
      out := out || regexp_replace(upper(encode(raw, 'hex')), '(..)', '%\1', 'g');
    END IF;
  END LOOP;
  RETURN out;
END;
$$;

CREATE OR REPLACE FUNCTION auth.query_param(q text, key text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT auth.urldecode(substring(pair FROM char_length(key) + 2))
  FROM unnest(string_to_array(coalesce(q, ''), '&')) AS pair
  WHERE pair = key OR pair LIKE key || '=%'
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION auth.user_scopes(uid uuid) RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT coalesce(string_agg(DISTINCT gs.scope, ' ' ORDER BY gs.scope), '')
  FROM auth.group_members AS gm
  JOIN auth.group_scopes AS gs ON gs.group_id = gm.group_id
  WHERE gm.user_id = uid;
$$;

CREATE OR REPLACE FUNCTION auth.intersect_scope(requested text, allowed text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(string_agg(req.scope, ' ' ORDER BY req.scope), '')
  FROM regexp_split_to_table(coalesce(requested, ''), '\s+') AS req(scope)
  WHERE req.scope <> ''
    AND req.scope IN (
      SELECT granted.scope
      FROM regexp_split_to_table(coalesce(allowed, ''), '\s+') AS granted(scope)
    );
$$;

CREATE OR REPLACE FUNCTION auth.scope_covers(granted text, requested text) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT NOT EXISTS (
    SELECT 1
    FROM regexp_split_to_table(coalesce(requested, ''), '\s+') AS req(scope)
    WHERE req.scope <> ''
      AND req.scope NOT IN (
        SELECT have.scope
        FROM regexp_split_to_table(coalesce(granted, ''), '\s+') AS have(scope)
      )
  );
$$;

CREATE OR REPLACE FUNCTION auth.sha256_hex(value text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(public.digest(convert_to(coalesce(value, ''), 'utf8'), 'sha256'), 'hex');
$$;

CREATE OR REPLACE FUNCTION auth.pkce_s256(verifier text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT rtrim(translate(encode(public.digest(convert_to(coalesce(verifier, ''), 'utf8'), 'sha256'), 'base64'), '+/', '-_'), '=');
$$;

CREATE OR REPLACE FUNCTION auth.http_result(status integer, headers jsonb, body jsonb) RETURNS text
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM set_config('response.status', status::text, true);
  IF headers IS NOT NULL THEN
    PERFORM set_config('response.headers', headers::text, true);
  END IF;
  RETURN body::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.redirect_to(location text, body jsonb) RETURNS text
LANGUAGE sql AS $$
  SELECT auth.http_result(
    302,
    json_build_array(json_build_object('Location', location))::jsonb,
    body
  );
$$;

CREATE OR REPLACE FUNCTION auth.error_redirect(redirect text, err text, state text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  loc text;
BEGIN
  loc := redirect || CASE WHEN position('?' IN redirect) > 0 THEN '&' ELSE '?' END || 'error=' || auth.urlencode(err);
  IF state IS NOT NULL AND state <> '' THEN
    loc := loc || '&state=' || auth.urlencode(state);
  END IF;
  RETURN auth.redirect_to(loc, jsonb_build_object('error', err));
END;
$$;

CREATE OR REPLACE FUNCTION auth.session_subject(force_login boolean)
RETURNS TABLE (user_id uuid, auth_time bigint)
LANGUAGE plpgsql STABLE AS $$
DECLARE
  sid text := coalesce(current_setting('request.cookie.session', true), '');
  sess auth.sessions%ROWTYPE;
  status text;
BEGIN
  IF force_login OR sid = '' THEN
    RETURN;
  END IF;
  SELECT * INTO sess FROM auth.sessions WHERE id = sid;
  IF NOT FOUND OR sess.exp::timestamptz <= now() THEN
    RETURN;
  END IF;
  user_id := (sess.claims ->> 'sub')::uuid;
  auth_time := (sess.claims ->> 'auth_time')::bigint;
  SELECT users.status INTO status FROM auth.users WHERE id = user_id;
  IF status IS DISTINCT FROM 'active' THEN
    RETURN;
  END IF;
  RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION auth.authorize() RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  q text := coalesce(current_setting('request.query', true), '');
  iss text;
  cid text;
  redirect text;
  response_type text;
  state text;
  nonce text;
  scope text;
  challenge text;
  method text;
  prompt text;
  max_age text;
  client auth.oauth_clients%ROWTYPE;
  person record;
  allowed text;
  requested text;
  granted text;
  stored text;
  raw_code text;
  target text;
BEGIN
  SELECT settings.issuer INTO iss FROM auth.settings LIMIT 1;
  cid := auth.query_param(q, 'client_id');
  redirect := auth.query_param(q, 'redirect_uri');
  response_type := auth.query_param(q, 'response_type');
  state := auth.query_param(q, 'state');
  nonce := auth.query_param(q, 'nonce');
  scope := auth.query_param(q, 'scope');
  challenge := auth.query_param(q, 'code_challenge');
  method := auth.query_param(q, 'code_challenge_method');
  prompt := auth.query_param(q, 'prompt');
  max_age := auth.query_param(q, 'max_age');

  SELECT * INTO client FROM auth.oauth_clients WHERE client_id = cid;
  IF NOT FOUND OR NOT EXISTS (
    SELECT 1 FROM auth.oauth_client_redirects
    WHERE client_id = cid AND redirect_uri = redirect
  ) THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_request', 'error_description', 'unknown client or redirect'));
  END IF;
  IF response_type IS DISTINCT FROM 'code' THEN
    RETURN auth.error_redirect(redirect, 'unsupported_response_type', state);
  END IF;
  IF method IS DISTINCT FROM 'S256' OR challenge IS NULL OR challenge = '' THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_request', 'error_description', 'PKCE S256 is required'));
  END IF;

  SELECT * INTO person
  FROM auth.session_subject(prompt = 'login' OR max_age = '0');
  IF NOT FOUND THEN
    IF prompt = 'none' THEN
      RETURN auth.error_redirect(redirect, 'login_required', state);
    END IF;
    target := iss || '/authorize/start' || CASE WHEN q = '' THEN '' ELSE '?' || q END;
    RETURN auth.redirect_to('/media/static/login.html?next=' || auth.urlencode(target), '{}'::jsonb);
  END IF;

  allowed := auth.user_scopes(person.user_id);
  requested := CASE WHEN scope IS NULL OR scope = '' THEN allowed ELSE scope END;
  granted := auth.intersect_scope(requested, allowed);
  IF granted = '' THEN
    RETURN auth.error_redirect(redirect, 'invalid_scope', state);
  END IF;
  SELECT consents.scope INTO stored
  FROM auth.oauth_consents AS consents
  WHERE consents.user_id = person.user_id AND consents.client_id = cid;
  IF client.require_consent AND NOT auth.scope_covers(stored, requested) THEN
    target := iss || '/authorize/start' || CASE WHEN q = '' THEN '' ELSE '?' || q END;
    RETURN auth.redirect_to('/media/static/consent.html?next=' || auth.urlencode(target), '{}'::jsonb);
  END IF;

  raw_code := encode(public.gen_random_bytes(32), 'hex');
  INSERT INTO auth.authorization_codes (
    code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge,
    auth_time, requested_scope, expires_at
  ) VALUES (
    auth.sha256_hex(raw_code), cid, person.user_id, redirect, granted, nonce, challenge,
    person.auth_time, requested, now() + interval '10 minutes'
  );
  target := redirect || CASE WHEN position('?' IN redirect) > 0 THEN '&' ELSE '?' END || 'code=' || auth.urlencode(raw_code);
  IF state IS NOT NULL AND state <> '' THEN
    target := target || '&state=' || auth.urlencode(state);
  END IF;
  RETURN auth.redirect_to(target, '{}'::jsonb);
END;
$$;

CREATE OR REPLACE FUNCTION auth.consent(p_decision text, p_next text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  target text := auth.safe_next(p_next);
  q text;
  cid text;
  redirect text;
  state text;
  scope text;
  person record;
  allowed text;
  requested text;
BEGIN
  IF target IS NULL THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_request', 'error_description', 'invalid next'));
  END IF;
  SELECT * INTO person FROM auth.session_subject(false);
  IF NOT FOUND THEN
    RETURN auth.http_result(401, NULL, jsonb_build_object('error', 'login_required'));
  END IF;
  IF position('?' IN target) = 0 THEN
    q := '';
  ELSE
    q := substring(target FROM position('?' IN target) + 1);
  END IF;
  cid := auth.query_param(q, 'client_id');
  redirect := auth.query_param(q, 'redirect_uri');
  state := auth.query_param(q, 'state');
  scope := auth.query_param(q, 'scope');
  IF NOT EXISTS (
    SELECT 1 FROM auth.oauth_client_redirects
    WHERE client_id = cid AND redirect_uri = redirect
  ) THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_request'));
  END IF;
  IF p_decision = 'deny' THEN
    RETURN auth.error_redirect(redirect, 'access_denied', state);
  END IF;
  IF p_decision IS DISTINCT FROM 'allow' THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_request'));
  END IF;
  allowed := auth.user_scopes(person.user_id);
  requested := CASE WHEN scope IS NULL OR scope = '' THEN allowed ELSE scope END;
  INSERT INTO auth.oauth_consents (user_id, client_id, scope)
  VALUES (person.user_id, cid, requested)
  ON CONFLICT (user_id, client_id) DO UPDATE SET scope = EXCLUDED.scope;
  RETURN auth.redirect_to(target, '{}'::jsonb);
END;
$$;

CREATE OR REPLACE FUNCTION auth.issue_tokens(
  p_client_id text,
  p_user_id uuid,
  p_scope text,
  p_nonce text,
  p_auth_time bigint,
  p_requested text,
  p_refresh text
) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  iss text;
  now_epoch bigint := extract(epoch FROM now())::bigint;
  access text;
  id_token text;
  id_payload jsonb;
  raw_refresh text;
  body jsonb;
BEGIN
  SELECT settings.issuer INTO iss FROM auth.settings LIMIT 1;
  access := auth.sign_jwt(jsonb_build_object(
    'iss', iss,
    'sub', p_user_id::text,
    'aud', p_client_id,
    'iat', now_epoch,
    'exp', now_epoch + 900,
    'scope', p_scope
  ), 'HS256');
  IF auth.scope_covers(p_scope, 'openid') THEN
    id_payload := jsonb_build_object(
      'iss', iss,
      'sub', p_user_id::text,
      'aud', p_client_id,
      'iat', now_epoch,
      'exp', now_epoch + 900,
      'auth_time', p_auth_time
    );
    IF p_nonce IS NOT NULL AND p_nonce <> '' THEN
      id_payload := id_payload || jsonb_build_object('nonce', p_nonce);
    END IF;
    id_token := auth.sign_jwt(id_payload, 'RS256');
  END IF;
  body := jsonb_build_object(
    'access_token', access,
    'token_type', 'Bearer',
    'expires_in', 900
  );
  IF id_token IS NOT NULL THEN
    body := body || jsonb_build_object('id_token', id_token);
  END IF;
  IF p_refresh IS NOT NULL THEN
    body := body || jsonb_build_object('refresh_token', p_refresh);
  ELSIF auth.scope_covers(p_scope, 'offline_access') THEN
    raw_refresh := encode(public.gen_random_bytes(32), 'hex');
    INSERT INTO auth.refresh_tokens (token_hash, client_id, user_id, scope, auth_time, expires_at)
    VALUES (auth.sha256_hex(raw_refresh), p_client_id, p_user_id, p_scope, p_auth_time, now() + interval '14 days');
    body := body || jsonb_build_object('refresh_token', raw_refresh);
  END IF;
  IF NOT (auth.scope_covers(p_scope, coalesce(p_requested, p_scope)) AND auth.scope_covers(coalesce(p_requested, p_scope), p_scope)) THEN
    body := body || jsonb_build_object('scope', p_scope);
  END IF;
  RETURN auth.http_result(200, json_build_array(json_build_object('Cache-Control', 'no-store'))::jsonb, body);
END;
$$;

CREATE OR REPLACE FUNCTION auth.token(
  p_client_id text,
  p_code text,
  p_code_verifier text,
  p_grant_type text,
  p_redirect_uri text,
  p_refresh_token text,
  p_scope text
) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  hdr jsonb := CASE
    WHEN coalesce(current_setting('request.headers', true), '') = '' THEN '{}'::jsonb
    ELSE current_setting('request.headers', true)::jsonb
  END;
  authz text;
  decoded text;
  basic_id text;
  basic_secret text;
  bad_basic boolean := false;
  cid text;
  client auth.oauth_clients%ROWTYPE;
  code_row auth.authorization_codes%ROWTYPE;
  refresh_row auth.refresh_tokens%ROWTYPE;
  person_status text;
  allowed text;
  narrowed text;
  granted text;
  raw_refresh text;
  new_hash text;
  challenge text;
BEGIN
  IF p_grant_type IS DISTINCT FROM 'authorization_code' AND p_grant_type IS DISTINCT FROM 'refresh_token' THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'unsupported_grant_type'));
  END IF;

  authz := hdr ->> 'authorization';
  IF authz ILIKE 'basic %' THEN
    BEGIN
      decoded := convert_from(decode(split_part(authz, ' ', 2), 'base64'), 'utf8');
      basic_id := split_part(decoded, ':', 1);
      basic_secret := substring(decoded FROM position(':' IN decoded) + 1);
    EXCEPTION WHEN OTHERS THEN
      bad_basic := true;
    END;
  END IF;
  cid := coalesce(nullif(p_client_id, ''), basic_id);
  SELECT * INTO client FROM auth.oauth_clients WHERE client_id = cid;
  IF bad_basic OR NOT FOUND THEN
    RETURN auth.http_result(
      401,
      json_build_array(json_build_object('WWW-Authenticate', 'Basic realm="token"'))::jsonb,
      jsonb_build_object('error', 'invalid_client')
    );
  END IF;
  IF client.client_secret IS NOT NULL THEN
    IF basic_id IS DISTINCT FROM client.client_id
       OR basic_secret IS NULL
       OR client.client_secret IS DISTINCT FROM public.crypt(basic_secret, client.client_secret) THEN
      RETURN auth.http_result(
        401,
        json_build_array(json_build_object('WWW-Authenticate', 'Basic realm="token"'))::jsonb,
        jsonb_build_object('error', 'invalid_client')
      );
    END IF;
  ELSIF basic_id IS NOT NULL THEN
    RETURN auth.http_result(
      401,
      json_build_array(json_build_object('WWW-Authenticate', 'Basic realm="token"'))::jsonb,
      jsonb_build_object('error', 'invalid_client')
    );
  END IF;

  IF p_grant_type = 'authorization_code' THEN
    SELECT * INTO code_row FROM auth.authorization_codes WHERE code_hash = auth.sha256_hex(p_code);
    IF NOT FOUND
       OR code_row.used_at IS NOT NULL
       OR code_row.expires_at <= now()
       OR code_row.client_id IS DISTINCT FROM client.client_id
       OR code_row.redirect_uri IS DISTINCT FROM p_redirect_uri THEN
      RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_grant'));
    END IF;
    challenge := auth.pkce_s256(p_code_verifier);
    IF p_code_verifier IS NULL OR p_code_verifier = '' OR challenge IS DISTINCT FROM code_row.code_challenge THEN
      UPDATE auth.authorization_codes SET used_at = now() WHERE code_hash = code_row.code_hash;
      RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_grant'));
    END IF;
    UPDATE auth.authorization_codes SET used_at = now() WHERE code_hash = code_row.code_hash AND used_at IS NULL;
    IF NOT FOUND THEN
      RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_grant'));
    END IF;
    RETURN auth.issue_tokens(
      client.client_id, code_row.user_id, code_row.scope, code_row.nonce,
      code_row.auth_time, code_row.requested_scope, NULL
    );
  END IF;

  SELECT * INTO refresh_row FROM auth.refresh_tokens WHERE token_hash = auth.sha256_hex(p_refresh_token);
  IF NOT FOUND
     OR refresh_row.replaced_by IS NOT NULL
     OR refresh_row.expires_at <= now()
     OR refresh_row.client_id IS DISTINCT FROM client.client_id THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_grant'));
  END IF;
  SELECT users.status INTO person_status FROM auth.users WHERE id = refresh_row.user_id;
  IF person_status IS DISTINCT FROM 'active' THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_grant'));
  END IF;
  allowed := auth.user_scopes(refresh_row.user_id);
  narrowed := CASE
    WHEN p_scope IS NULL OR p_scope = '' THEN refresh_row.scope
    ELSE auth.intersect_scope(p_scope, refresh_row.scope)
  END;
  granted := auth.intersect_scope(narrowed, allowed);
  IF granted = '' THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_grant'));
  END IF;
  raw_refresh := NULL;
  IF auth.scope_covers(granted, 'offline_access') THEN
    raw_refresh := encode(public.gen_random_bytes(32), 'hex');
    new_hash := auth.sha256_hex(raw_refresh);
  ELSE
    new_hash := 'revoked';
  END IF;
  UPDATE auth.refresh_tokens
  SET replaced_by = new_hash
  WHERE token_hash = refresh_row.token_hash AND replaced_by IS NULL;
  IF NOT FOUND THEN
    RETURN auth.http_result(400, NULL, jsonb_build_object('error', 'invalid_grant'));
  END IF;
  IF raw_refresh IS NOT NULL THEN
    INSERT INTO auth.refresh_tokens (token_hash, client_id, user_id, scope, auth_time, expires_at)
    VALUES (new_hash, client.client_id, refresh_row.user_id, granted, refresh_row.auth_time, now() + interval '14 days');
  END IF;
  RETURN auth.issue_tokens(
    client.client_id, refresh_row.user_id, granted, NULL, refresh_row.auth_time,
    CASE WHEN p_scope IS NULL OR p_scope = '' THEN refresh_row.scope ELSE p_scope END,
    raw_refresh
  );
END;
$$;

CREATE OR REPLACE FUNCTION auth.create_user(p_password text, p_username text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  person auth.users%ROWTYPE;
BEGIN
  INSERT INTO auth.users (username, password)
  VALUES (p_username, p_password)
  RETURNING * INTO person;
  RETURN json_build_object('id', person.id, 'username', person.username, 'status', person.status)::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.set_password(p_password text, p_user_id uuid) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  person auth.users%ROWTYPE;
BEGIN
  UPDATE auth.users
  SET password = p_password, updated_at = now()
  WHERE id = p_user_id
  RETURNING * INTO person;
  IF NOT FOUND THEN
    RETURN auth.http_result(404, NULL, jsonb_build_object('error', 'not found'));
  END IF;
  RETURN json_build_object('id', person.id, 'username', person.username, 'status', person.status)::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.userinfo() RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  who text := auth.current_sub();
  scope text := '';
  profile auth.profiles%ROWTYPE;
  body jsonb;
  group_names jsonb;
BEGIN
  IF who = '' THEN
    RETURN auth.http_result(401, NULL, jsonb_build_object('error', 'invalid_token'));
  END IF;
  IF coalesce(current_setting('request.claims', true), '') <> '' THEN
    scope := coalesce(current_setting('request.claims', true)::jsonb ->> 'scope', '');
  END IF;
  body := jsonb_build_object('sub', who);
  IF auth.scope_covers(scope, 'profile') OR auth.scope_covers(scope, 'email') THEN
    SELECT * INTO profile FROM auth.profiles WHERE user_id = who::uuid;
  END IF;
  IF auth.scope_covers(scope, 'profile') THEN
    body := body || jsonb_strip_nulls(jsonb_build_object(
      'given_name', profile.given_name,
      'family_name', profile.family_name,
      'middle_name', profile.middle_name,
      'nickname', profile.nickname,
      'picture', profile.picture,
      'locale', profile.locale,
      'zoneinfo', profile.zoneinfo
    ));
  END IF;
  IF auth.scope_covers(scope, 'email') THEN
    body := body || jsonb_build_object(
      'email', profile.email,
      'email_verified', profile.email_verified
    );
  END IF;
  IF auth.scope_covers(scope, 'groups') THEN
    SELECT coalesce(jsonb_agg(groups.name ORDER BY groups.name), '[]'::jsonb)
    INTO group_names
    FROM auth.group_members AS members
    JOIN auth.security_groups AS groups ON groups.id = members.group_id
    WHERE members.user_id = who::uuid;
    body := body || jsonb_build_object('groups', group_names);
  END IF;
  RETURN body::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.profile() RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  who text := auth.current_sub();
  profile auth.profiles%ROWTYPE;
BEGIN
  IF who = '' THEN
    RETURN auth.http_result(401, NULL, jsonb_build_object('error', 'login_required'));
  END IF;
  SELECT * INTO profile FROM auth.profiles WHERE user_id = who::uuid;
  IF NOT FOUND THEN
    RETURN auth.http_result(404, NULL, jsonb_build_object('error', 'not found'));
  END IF;
  RETURN json_build_object(
    'given_name', profile.given_name,
    'family_name', profile.family_name,
    'middle_name', profile.middle_name,
    'nickname', profile.nickname,
    'picture', profile.picture,
    'locale', profile.locale,
    'zoneinfo', profile.zoneinfo,
    'email', profile.email,
    'email_verified', profile.email_verified
  )::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.profile(
  p_family_name text,
  p_given_name text,
  p_locale text,
  p_middle_name text,
  p_nickname text,
  p_picture text,
  p_zoneinfo text
) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  who text := auth.current_sub();
  profile auth.profiles%ROWTYPE;
BEGIN
  IF who = '' THEN
    RETURN auth.http_result(401, NULL, jsonb_build_object('error', 'login_required'));
  END IF;
  UPDATE auth.profiles
  SET family_name = p_family_name,
      given_name = p_given_name,
      locale = p_locale,
      middle_name = p_middle_name,
      nickname = p_nickname,
      picture = p_picture,
      zoneinfo = p_zoneinfo,
      updated_at = now()
  WHERE user_id = who::uuid
  RETURNING * INTO profile;
  IF NOT FOUND THEN
    RETURN auth.http_result(404, NULL, jsonb_build_object('error', 'not found'));
  END IF;
  RETURN json_build_object(
    'given_name', profile.given_name,
    'family_name', profile.family_name,
    'middle_name', profile.middle_name,
    'nickname', profile.nickname,
    'picture', profile.picture,
    'locale', profile.locale,
    'zoneinfo', profile.zoneinfo,
    'email', profile.email,
    'email_verified', profile.email_verified
  )::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.change_password(p_current_password text, p_new_password text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  who text := auth.current_sub();
  hash text;
BEGIN
  IF who = '' THEN
    RETURN auth.http_result(401, NULL, jsonb_build_object('error', 'login_required'));
  END IF;
  SELECT users.password INTO hash FROM auth.users WHERE id = who::uuid;
  IF hash IS NULL OR hash IS DISTINCT FROM public.crypt(p_current_password, hash) THEN
    RETURN auth.http_result(401, NULL, jsonb_build_object('error', 'invalid password'));
  END IF;
  UPDATE auth.users
  SET password = p_new_password, updated_at = now()
  WHERE id = who::uuid;
  DELETE FROM auth.refresh_tokens WHERE user_id = who::uuid;
  RETURN auth.http_result(204, NULL, '{}'::jsonb);
END;
$$;

ALTER TABLE auth.settings OWNER TO auth_owner;
ALTER TABLE auth.users OWNER TO auth_owner;
ALTER TABLE auth.profiles OWNER TO auth_owner;
ALTER TABLE auth.security_groups OWNER TO auth_owner;
ALTER TABLE auth.group_scopes OWNER TO auth_owner;
ALTER TABLE auth.group_members OWNER TO auth_owner;
ALTER TABLE auth.oauth_clients OWNER TO auth_owner;
ALTER TABLE auth.oauth_client_redirects OWNER TO auth_owner;
ALTER TABLE auth.oauth_consents OWNER TO auth_owner;
ALTER TABLE auth.authorization_codes OWNER TO auth_owner;
ALTER TABLE auth.refresh_tokens OWNER TO auth_owner;
ALTER TABLE auth.sessions OWNER TO auth_owner;
ALTER TABLE auth.login_attempts OWNER TO auth_owner;
ALTER TABLE auth.signing_keys OWNER TO auth_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO auth_conn;
REVOKE ALL ON auth.signing_keys FROM auth_conn;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA auth TO auth_conn;
REVOKE ALL ON FUNCTION auth.rsa_pem() FROM PUBLIC;
REVOKE ALL ON FUNCTION auth.rsa_pem() FROM auth_conn;

ALTER TABLE auth.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY profiles_select ON auth.profiles
  FOR SELECT
  USING (
    user_id::text = auth.current_sub()
    OR auth.has_scope('profiles-read')
    OR current_setting('request.function', true) = 'auth.login'
  );
CREATE POLICY profiles_update ON auth.profiles
  FOR UPDATE
  USING (user_id::text = auth.current_sub() OR auth.has_scope('profiles-write'))
  WITH CHECK (user_id::text = auth.current_sub() OR auth.has_scope('profiles-write'));
CREATE POLICY profiles_insert ON auth.profiles
  FOR INSERT
  WITH CHECK (user_id::text = auth.current_sub() OR auth.has_scope('profiles-write'));
