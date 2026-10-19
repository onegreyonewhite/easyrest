# Auth server example

OpenID Provider built as an EasyREST configuration application. Postgres stores users, groups, authorization codes, and token signing. `easyrest-server` serves the HTTP routes, the session cookie, and the bearer check. A form content plugin in this directory gives each SQL function a fixed argument list.

The issuer is fixed at `https://localhost:8443/restapi/v1`.

## Run

```bash
./gen-dev-cert.sh
docker compose up --build
```

`https://localhost:8443/health` returns `OK`. `GET /restapi/v1/?format=html` is the API document. Sign in from the home page; an empty `next` returns there. **Sign in to the demo app** runs the authorization-code flow and finishes on `/media/static/callback.html`. The password page uses the session cookie.

`PUT /restapi/v1/authorize/start` is registered with the authorize read, and it is not part of the protocol. Authorization is `GET`.

## Dev accounts

| Username | Password | Email | Notes |
| --- | --- | --- | --- |
| admin | admin | admin@example.com | administrators group |
| alice | alice | alice@example.com | members group |
| bob | bob | bob@example.com | disabled |

| Client id | Kind | Secret | Redirect |
| --- | --- | --- | --- |
| spa | public | none | `http://127.0.0.1:9876/callback` |
| service | confidential | `dev-service-secret` | `https://service.local/callback` |

The HS256 access-token secret is `dev-only-change-me`. ID tokens are RS256. The private key is created on first use and is not granted to the API role.

## Tests

HTTP tests run only when `AUTH_SERVER_URL` is `https://localhost:8443`. `AUTH_SERVER_CA` is the absolute path of `tls/cert.pem`.

```bash
AUTH_SERVER_URL=https://localhost:8443 \
AUTH_SERVER_CA=$PWD/tls/cert.pem \
go test ./examples/auth_server/... -count=1
```
