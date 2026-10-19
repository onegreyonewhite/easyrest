# Shop API

A store API on EasyREST. Categories and products live in MySQL. Carts, inventory, and orders live in Postgres. Product images live in MinIO (`alpine/minio`, because Docker Hub no longer serves `minio/minio`). Traefik terminates HTTPS and serves the images at `https://localhost/cdn/`.

There is no login server in this example. Tokens are HMAC JWTs checked with the shared secret `dev-only-change-me`. The Swagger security definition points at `https://idp.example`, which stands for an external provider such as Keycloak or Auth0. This process never calls that host and does not check RS256 signatures.

`products.stock` in MySQL is display stock. Checkout does not change it. The number that is reserved is `inventory.available` in Postgres, seeded with the same product ids. EasyREST runs each request against one database, so the client copies `sku`, `title`, and `price_cents` from the catalog into the cart line.

Changing the SQL requires `docker compose down -v`. Init scripts run only on a new data directory.

## Start

```bash
./gen-dev-cert.sh
docker compose up --build -d
```

Wait until `minio-init` has exited 0. The API is `https://localhost`. Use the dev CA for curl:

```bash
curl --cacert tls/cert.pem https://localhost/health
```

`GET /` and `GET /restapi/catalog/?format=html` are the public catalog document. `GET /restapi/v1/?format=html` is the shop. `/media/static/` is Swagger UI, not the image CDN.

## Tokens

```bash
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
mint() {
  h=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)
  p=$(printf '%s' "$1" | b64url)
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac 'dev-only-change-me' -binary | b64url)
  printf '%s' "$h.$p.$s"
}

customer=$(mint '{"sub":"customer-1","scope":"carts-read carts-write orders-read orders-write inventory-read"}')
customer2=$(mint '{"sub":"customer-2","scope":"carts-read carts-write orders-read orders-write inventory-read"}')
staff=$(mint '{"sub":"staff-1","scope":"carts-read carts-write orders-read orders-write inventory-read products-write categories-write inventory-write orders-manage"}')
```

Do not put the scopes `read` or `write` in a token. Those match every read or write scope.

## Catalog

No `Authorization` header. The response includes `Cache-Control: public, max-age=60`.

```bash
curl --cacert tls/cert.pem -D - https://localhost/restapi/catalog/categories/
curl --cacert tls/cert.pem -D - 'https://localhost/restapi/catalog/products/?q=%25assam%25&min_price=1000&max_price=1400&ordering=-price_cents' \
  -H 'Prefer: count=exact'
curl --cacert tls/cert.pem -D - https://localhost/restapi/catalog/categories/tea/products/
curl --cacert tls/cert.pem -H 'Accept: text/csv' https://localhost/restapi/catalog/products/
curl --cacert tls/cert.pem -H 'Accept: application/yaml' https://localhost/restapi/catalog/products/
curl --cacert tls/cert.pem https://localhost/restapi/catalog/products/assam/
```

Seeded rows:

| id | category | sku | price_cents | stock |
| --- | --- | --- | --- | --- |
| assam | tea | ASSAM | 1299 | 20 |
| ceylon | tea | CEYLON | 1499 | 15 |
| espresso | coffee | ESPRESSO | 999 | 30 |

`beverages` is the parent of `tea` and `coffee`.

## Image

A staff token uploads a PNG onto `assam`. The PATCH body is `{"updated":1}`. Read the product again for the CDN URL.

```bash
printf '%s' 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==' | base64 -d > /tmp/assam.png
curl --cacert tls/cert.pem -D - -X PATCH https://localhost/restapi/v1/manage-products/assam/ \
  -H "Authorization: Bearer $staff" \
  -F 'doc={};type=application/json' \
  -F 'image=@/tmp/assam.png;type=image/png'
curl --cacert tls/cert.pem https://localhost/restapi/catalog/products/assam/
```

`image` is `https://localhost/cdn/products/...`. Fetch that URL. Traefik adds `Cache-Control: public, max-age=86400`.

```bash
image=$(curl --cacert tls/cert.pem -s https://localhost/restapi/catalog/products/assam/ | python3 -c 'import json,sys; print(json.load(sys.stdin)["image"])')
curl --cacert tls/cert.pem -D - -o /tmp/assam-out.png "$image"
```

## Cart and order

Without a token the cart is 401. `Cache-Control` on shop responses is `private, no-store`.

```bash
curl --cacert tls/cert.pem -D - -X POST https://localhost/restapi/v1/me/cart/ \
  -H 'Content-Type: application/json' -d '{}'
```

Create the cart, then a dry run that does not keep the line, then the real line. The price is the catalog price, not a value Postgres looks up.

```bash
curl --cacert tls/cert.pem -D - -X POST https://localhost/restapi/v1/me/cart/ \
  -H "Authorization: Bearer $customer" -H 'Content-Type: application/json' -d '{}'
cart=$(curl --cacert tls/cert.pem -s https://localhost/restapi/v1/me/cart/ \
  -H "Authorization: Bearer $customer" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl --cacert tls/cert.pem -D - -X POST "https://localhost/restapi/v1/carts/$cart/items/" \
  -H "Authorization: Bearer $customer" -H 'Content-Type: application/json' \
  -H 'Prefer: tx=rollback' \
  -d '{"product_id":"assam","quantity":1,"sku":"ASSAM","title":"Assam","unit_price":1299}'
curl --cacert tls/cert.pem "https://localhost/restapi/v1/carts/$cart/items/" \
  -H "Authorization: Bearer $customer"

curl --cacert tls/cert.pem -D - -X POST "https://localhost/restapi/v1/carts/$cart/items/" \
  -H "Authorization: Bearer $customer" -H 'Content-Type: application/json' \
  -d '{"product_id":"assam","quantity":1,"sku":"ASSAM","title":"Assam","unit_price":1299}'
curl --cacert tls/cert.pem -D - -X POST "https://localhost/restapi/v1/carts/$cart/checkout/" \
  -H "Authorization: Bearer $customer" -H 'Content-Type: application/json' -d '{}'
```

Checkout answers 201 with `Location`, `order_id`, and `total_cents` 1299. Assam inventory goes from 20 to 19. A second checkout of the same cart is 409.

```bash
order=$(curl --cacert tls/cert.pem -s https://localhost/restapi/v1/orders/ \
  -H "Authorization: Bearer $customer" | python3 -c 'import json,sys; print(json.load(sys.stdin)["results"][0]["id"])')
curl --cacert tls/cert.pem https://localhost/restapi/v1/inventory/assam/ \
  -H "Authorization: Bearer $customer"
curl --cacert tls/cert.pem -D - "https://localhost/restapi/v1/orders/$order/" \
  -H "Authorization: Bearer $customer2"
```

The second shopper gets 404. Pay, then ship. Shipping again is 409. The shopper cannot ship.

```bash
curl --cacert tls/cert.pem -D - -X POST "https://localhost/restapi/v1/orders/$order/pay/" \
  -H "Authorization: Bearer $customer" -H 'Content-Type: application/json' -d '{}'
curl --cacert tls/cert.pem -D - -X POST "https://localhost/restapi/v1/orders/$order/ship/" \
  -H "Authorization: Bearer $staff" -H 'Content-Type: application/json' -d '{}'
curl --cacert tls/cert.pem -D - -X POST "https://localhost/restapi/v1/orders/$order/ship/" \
  -H "Authorization: Bearer $staff" -H 'Content-Type: application/json' -d '{}'
curl --cacert tls/cert.pem -D - -X POST "https://localhost/restapi/v1/orders/$order/ship/" \
  -H "Authorization: Bearer $customer" -H 'Content-Type: application/json' -d '{}'
curl --cacert tls/cert.pem -D - "https://localhost/restapi/v1/orders/$order/" \
  -H "Authorization: Bearer $customer"
```
