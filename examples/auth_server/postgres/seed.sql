INSERT INTO auth.settings (issuer) VALUES ('https://localhost:8443/restapi/v1');

INSERT INTO auth.signing_keys (id, alg, pem) VALUES ('hs256-1', 'HS256', 'dev-only-change-me');

INSERT INTO auth.security_groups (id, name, description) VALUES
  ('11111111-1111-1111-1111-111111111111', 'administrators', 'Operators'),
  ('22222222-2222-2222-2222-222222222222', 'members', 'People');

INSERT INTO auth.group_scopes (group_id, scope)
SELECT '22222222-2222-2222-2222-222222222222', scope
FROM unnest(ARRAY['openid', 'profile', 'email', 'groups', 'offline_access']) AS scope;

INSERT INTO auth.group_scopes (group_id, scope)
SELECT '11111111-1111-1111-1111-111111111111', scope
FROM unnest(ARRAY[
  'openid', 'profile', 'email', 'groups', 'offline_access',
  'users-read', 'users-write',
  'profiles-read', 'profiles-write',
  'security-groups-read', 'security-groups-write',
  'group-scopes-read', 'group-scopes-write',
  'group-members-read', 'group-members-write',
  'clients-read', 'clients-write',
  'client-redirects-read', 'client-redirects-write',
  'consents-read', 'consents-write'
]) AS scope;

INSERT INTO auth.users (id, username, password, status) VALUES
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'admin', 'admin', 'active'),
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2', 'alice', 'alice', 'active'),
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3', 'bob', 'bob', 'disabled');

INSERT INTO auth.profiles (user_id, given_name, family_name, email, email_verified) VALUES
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'Admin', 'User', 'admin@example.com', true),
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2', 'Alice', 'Able', 'alice@example.com', true),
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3', 'Bob', 'Brown', 'bob@example.com', false);

INSERT INTO auth.group_members (group_id, user_id) VALUES
  ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1'),
  ('22222222-2222-2222-2222-222222222222', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2'),
  ('22222222-2222-2222-2222-222222222222', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3');

INSERT INTO auth.oauth_clients (client_id, name, client_secret, require_consent) VALUES
  ('spa', 'SPA', NULL, true),
  ('service', 'Service', 'dev-service-secret', false);

INSERT INTO auth.oauth_client_redirects (client_id, redirect_uri) VALUES
  ('spa', 'http://127.0.0.1:9876/callback'),
  ('spa', 'https://localhost:8443/media/static/callback.html'),
  ('service', 'https://service.local/callback');
