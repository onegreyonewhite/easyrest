# EasyREST

EasyREST is a lightweight, extensible REST service that provides a unified API for performing CRUD and aggregating queries on relational databases. Its key innovation is the use of a plugin system that allows you to connect to virtually any database or data source simply by writing a plugin that conforms to the EasyREST interface.

EasyREST handles authentication via JWT, validates and sanitizes request parameters at the controller level, and then passes safe SQL expressions or commands to the plugins. The service supports complex queries including aggregations, aliasing, advanced WHERE conditions, and the use of context variables that allow you to influence query behavior dynamically.

---

## Table of Contents

- [Architecture](#architecture)
  - [Overall Architecture Diagram](#overall-architecture-diagram)
  - [Plugin Communication and Loading](#plugin-communication-and-loading)
  - [Authentication and Authorization](#authentication-and-authorization)
- [EasyREST Distributions](#easyrest-distributions)
  - [`easyrest-gateway`](#easyrest-gateway)
  - [`easyrest-server`](#easyrest-server)
  - [`easyrest-plugin-*`](#easyrest-plugin-)
- [Query Capabilities](#query-capabilities)
  - [Selecting Fields and Aliasing](#selecting-fields-and-aliasing)
  - [Aggregating Queries](#aggregating-queries)
  - [WHERE Conditions](#where-conditions)
  - [Context Variables](#context-variables)
  - [Data Insertion, Updates, and Deletion](#data-insertion-updates-and-deletion)
- [Supported Databases and Caches](#supported-databases-and-caches)
  - [SQLite](#sqlite)
  - [MySQL](#mysql)
    - [Key Features](#mysql-key-features)
    - [Performance and Connection Parameters](#mysql-performance-and-connection-parameters)
    - [Context Handling](#mysql-context-handling)
    - [Schema and Stored Procedures](#mysql-schema-and-stored-procedures)
    - [MySQL Setup using Docker](#mysql-setup-using-docker)
  - [PostgreSQL](#postgresql)
    - [Key Features](#postgresql-key-features)
    - [Performance and Connection Parameters](#postgresql-performance-and-connection-parameters)
    - [Context Handling](#postgresql-context-handling)
    - [Schema and Functions](#postgresql-schema-and-functions)
    - [PostgreSQL Setup using Docker](#postgresql-setup-using-docker)
  - [Redis (Cache)](#redis-cache)
    - [Key Features](#redis-key-features)
    - [Configuration Parameters](#redis-configuration-parameters)
    - [Redis Setup using Docker](#redis-setup-using-docker)
  - [LRU (Cache)](#lru-cache)
- [Configuration Parameters](#configuration-parameters)
  - [Main Configuration](#main-configuration)
- [Examples](#examples)
  - [Multiple SQLite Databases with Different Structures](#multiple-sqlite-databases-with-different-structures)
- [Developing External Plugins](#developing-external-plugins)
- [API Documentation](#api-documentation)
- [License](#license)

---

## Architecture

EasyREST's design emphasizes simplicity, extensibility, and security. It follows a modular architecture where the core server is responsible for:

- **Authentication & Authorization:** Validates JWT tokens and verifies scopes.
- **Parameter Validation:** Ensures that all parameters (select, where, ordering, etc.) are safe before forwarding to the plugins.
- **Plugin Orchestration:** Loads and manages DB and Cache plugins based on YAML configuration.
- **Context Propagation:** Extracts contextual information (e.g., timezone, HTTP headers, JWT claims) from each request and passes them to plugins.

### Overall Architecture Diagram

```mermaid
flowchart TD
    A[HTTP Request] -->|REST API| B[EasyREST Server]
    B --> C{Authentication & Validation}
    C -- Valid --> D[Process Request]
    C -- Invalid --> E[401/400 Response]
    E --> N[HTTP Response]
    D --> X{Apply Context?}
    X -- Yes --> Y[Replace request.* and erctx.* values]
    X -- No --> Z[Send as is]
    Y --> J[Plugin Client RPC Call]
    Z --> J[Plugin Client RPC Call]
    J --> K["DB Plugin (e.g., SQLite, Postgres, MySQL, etc)"]
    K --> F[Build SQL Query]
    F --> L[Database]
    L --> M[Return Results to DB Plugin]
    M --> J2[Return Results to Plugin Client RPC Call]
    J2 --> B2[Return to EasyREST Server]
    B2 --> N[HTTP Response]
```

### Plugin Communication and Loading

- **RPC Communication:** EasyREST uses Hashicorp's [go-plugin](https://github.com/hashicorp/go-plugin) system to load and communicate with plugins. The server launches plugin processes based on the `plugins` section in the YAML configuration file and establishes an RPC connection.
- **Plugin Loading:**
    - **`easyrest-gateway`**: This binary does not bundle any plugins. It discovers and launches plugin executables (e.g., `easyrest-plugin-sqlite`, `easyrest-plugin-mysql`) based on the URI scheme in the configuration and the `path` setting, or by searching standard system locations.
    - **`easyrest-server`**: This binary comes with built-in support for SQLite, MySQL, PostgreSQL (DB plugins), and Redis, LRU (Cache plugins). If a configured plugin matches one of these built-in types, it's used directly. For other plugin types or if an explicit `path` is provided, it behaves like `easyrest-gateway` and attempts to load an external plugin executable.
    - **`easyrest-plugin-*`**: These are standalone executables, each providing a specific DB or Cache implementation.
- **Data Exchange:** The server sends validated and sanitized SQL expressions (for DB plugins) or commands (for Cache plugins) and additional context data to the plugin. Context variables are directly substituted into the query or made available to the plugin.
- **Type Registration:** For secure and reliable encoding/decoding over RPC, custom types (e.g., `time.Time` and flattened JWT claims) are registered with the gob package.

### Authentication and Authorization

- **JWT Authentication:** Requests must include a Bearer token. The server verifies the token signature (using a secret from configuration) and extracts claims.
- **Scope-based Authorization:** The service verifies that the token's claims include the required scope (e.g., `users-read` for GET operations, `users-write` for modifications or wide `read` and `write` for all table names).
- **Token Claims:** The claims are flattened and passed to plugins (under the key `claims` in the context map) so that plugins can leverage user-specific information if needed.

---

## EasyREST Distributions

EasyREST is available in different binary forms to suit various deployment needs:

### `easyrest-gateway`

- A lean, minimal server binary that **contains no built-in plugins**.
- It relies entirely on external `easyrest-plugin-*` executables.
- For each plugin defined in the configuration, `easyrest-gateway` will search for the corresponding plugin binary (e.g., `easyrest-plugin-mysql` for a `mysql://` URI) in standard system `PATH` directories or at the explicit `path` specified in the plugin's configuration.
- Ideal for environments where you want to manage plugin binaries separately or use custom-built plugins.

### `easyrest-server`

- A comprehensive server binary that **includes built-in support for common plugins**:
  - **Database Plugins:** MySQL, SQLite, PostgreSQL.
  - **Cache Plugins:** Redis, LRU (in-memory).
- If a plugin configured in `plugins` matches one of these built-in types (e.g., `uri: "sqlite://..."`), the embedded plugin is used by default.
- If a plugin type is not among the built-ins, or if an explicit `path` is provided in its configuration, `easyrest-server` will attempt to load it as an external plugin executable, similar to `easyrest-gateway`.
- Suitable for most common use cases, providing out-of-the-box support for popular databases and caches.

### `easyrest-plugin-*`

- These are individual, standalone plugin executables (e.g., `easyrest-plugin-mysql`, `easyrest-plugin-postgres`, `easyrest-plugin-redis`).
- They are used by `easyrest-gateway` for all plugin needs and by `easyrest-server` for plugins not built into it or when an external version is preferred.
- You can build these plugins from their respective source code or use pre-compiled versions if available.
- Currently supported standalone plugins include: MySQL, SQLite, PostgreSQL, and Redis.

---

## Query Capabilities

EasyREST supports a wide range of SQL query features by converting URL query parameters into SQL expressions after performing strict validation.

### Selecting Fields and Aliasing

- **Basic Selection:**
  Use the `select` parameter to specify one or more columns. For example:
  ```
  /api/test/users/?select=id,name
  ```
- **Field Aliasing:**
  To alias a column, use the syntax `alias:field`.
  For example,
  ```
  /api/test/users/?select=username:name
  ```
  becomes
  ```sql
  SELECT name AS username FROM users
  ```
- **SQL Functions:**
  Aggregation functions are supported. For instance,
  ```
  /api/test/users/?select=count()
  ```
  results in:
  ```sql
  SELECT COUNT(*) AS count FROM users
  ```
  You can also use functions with aliasing:
  ```
  /api/test/orders/?select=total:amount.sum(),order_date
  ```
  which translates to:
  ```sql
  SELECT SUM(amount) AS total, order_date FROM orders GROUP BY order_date
  ```

### Aggregating Queries

- EasyREST supports common SQL aggregate functions such as `COUNT()`, `SUM()`, `AVG()`, `MIN()`, and `MAX()`.
- Aggregated fields are automatically excluded from the GROUP BY clause.
- Non-aggregated fields that appear in the `select` parameter are added to a GROUP BY clause automatically.

### WHERE Conditions

- **Syntax:**
  Conditions are specified using parameters prefixed with `where.`. For example:
  ```
  /api/test/users/?where.eq.name=Alice
  ```
  This generates:
  ```sql
  WHERE name = 'Alice'
  ```
- **Operators:**  
  Supported operators include:
  - `eq` (equals)
  - `neq` (not equals)
  - `lt` (less than)
  - `lte` (less than or equals)
  - `gt` (greater than)
  - `gte` (greater than or equals)
  - `like` (LIKE)
  - `ilike` (ILIKE)
  - `is` (IS)
  - `in` (IN)

### Context Variables

EasyREST provides two ways to access context variables in queries:

1. **`erctx` Format:** Uses underscore notation: `erctx.claims_sub`
2. **`request` Format:** Uses JSON path notation: `request.claims.sub`

Available context variables: `timezone`, `headers`, `claims`, `method`, `path`, `query`, `prefer`.
The `Prefer` header can pass plugin-specific context or influence server behavior (e.g., `Prefer: timezone=UTC tx=rollback`). Standard keys `timezone` and `tx` are recognized. Plugins can access other `Prefer` key-value pairs via `ctx["prefer"]`.

Database plugins handle these context variables differently:

- **MySQL Plugin:** Sets session variables (e.g., `@erctx_claims_sub`, `@request_claims_sub`) for the current connection.
- **PostgreSQL Plugin:** Uses `set_config()` to set session-local configuration parameters (e.g., `current_setting(\'erctx.claims_sub\', true)`).

### Data Insertion, Updates, and Deletion

- **Insertion (POST):** JSON body. Context variables can be used in values.
- **Update (PATCH):** JSON body and optional `where` conditions. Context variables can be used in data and conditions.
- **Deletion (DELETE):** Based on `where` parameters. Context variables can be used in conditions.

---

## Supported Databases and Caches

EasyREST can connect to various data stores through its plugin system.

### SQLite

- **Plugin Type:** `sqlite` (e.g., `uri: "sqlite://./test.db"`)
- Built-in with `easyrest-server`. Can be used as `easyrest-plugin-sqlite` with `easyrest-gateway`.
- A simple, file-based relational database. Good for development, testing, or small applications.
- Schema is introspected from the database file.

### MySQL

- **Plugin Type:** `mysql` (e.g., `uri: "mysql://user:pass@host:port/dbname"`)
- Built-in with `easyrest-server`. Can be used as `easyrest-plugin-mysql` with `easyrest-gateway`.

#### MySQL Key Features

- **Context Injection:** Injects `erctx.` and `request.` context variables as MySQL session variables (e.g., `@erctx_claims_sub`).
- **Stored Procedure Calls:** Executes stored procedures within a transaction.
- **Connection Pooling:** Uses a MySQL connection pool for performance.
- **UTF8MB4 Support:** Operates with `utf8mb4` and `utf8mb4_general_ci`.

#### MySQL Performance and Connection Parameters

These parameters can be appended to the MySQL URI query string (e.g., `?maxOpenConns=50&parseTime=true`):

- `maxOpenConns`: Max open connections (default: 100).
- `maxIdleConns`: Max idle connections (default: 20).
- `connMaxLifetime`: Connection reuse time in minutes (default: 5).
- `connMaxIdleTime`: Connection idle time in minutes (default: 10).
- `timeout`: Query timeout in seconds (default: 30).
- `parseTime`: Parse MySQL TIME/TIMESTAMP/DATETIME as `time.Time` (recommended: `true`).

Example URI: `mysql://root:root@localhost:3307/easyrestdb?maxOpenConns=100&maxIdleConns=20&connMaxLifetime=5&connMaxIdleTime=10&timeout=30&parseTime=true`

#### MySQL Context Handling

The plugin sets session variables before executing SQL. For a context variable like `claims.sub` (value `user123`), it would be:

```sql
SET @erctx_claims_sub = \'user123\', @request_claims_sub = \'user123\';
```

These can be used in triggers, stored procedures, or queries:

```sql
-- In a trigger or stored procedure
IF OLD.created_by != @request_claims_sub AND @request_claims_role != \'admin\' THEN ...
```

```sql
-- In a query via API
/api/mydb/products/?where.eq.created_by=erctx.claims_sub
```

#### MySQL Schema and Stored Procedures

- The plugin introspects table and view schemas.
- An example schema, including tables and a stored function (`doSomething`), is available in `schemas/mysql.sql`. This file demonstrates table creation and how to define functions that can be called via the RPC endpoint. It also shows how to use session variables (set from context) in triggers (`before_product_update`) and functions (`getMyProducts`).
- **Note on Functions vs. Views for Row-Level Security:** MySQL does not allow session variables directly in `CREATE VIEW`. Use stored functions for dynamic, user-context-aware data filtering, as they *can* access session variables.

#### MySQL Setup using Docker

To run MySQL in Docker for development (e.g., on port 3307):

```bash
docker run --name mysql-easyrest -p 3307:3306 \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=easyrestdb \
  -d mysql:8
```

Apply your schema (e.g., contents of `schemas/mysql.sql`):

```bash
docker exec -i mysql-easyrest mysql -uroot -proot easyrestdb < schemas/mysql.sql
```

### PostgreSQL

- **Plugin Type:** `postgres` (e.g., `uri: "postgres://user:pass@host:port/dbname"`)
- Built-in with `easyrest-server`. Can be used as `easyrest-plugin-postgres` with `easyrest-gateway`.

#### PostgreSQL Key Features

- **Context Injection:** Uses `set_config()` to make `erctx.` and `request.` context variables available via `current_setting()`.
- **Function Calls:** Executes PostgreSQL functions within a transaction.
- **Connection Pooling:** Efficient connection management.
- **COPY Support:** Uses `COPY FROM` for bulk inserts (threshold configurable).

#### PostgreSQL Performance and Connection Parameters

Append to the PostgreSQL URI query string (e.g., `?maxOpenConns=50&sslmode=disable`):

- `maxOpenConns`: Max open connections (default by pgx driver, typically ~100). `maxConns` is an alias used by the plugin.
- `minConns`: Minimum connections in pool (default by pgx driver). `maxIdleConns` is an alias.
- `connMaxLifetime`: Connection lifetime (e.g., `5m`).
- `connMaxIdleTime`: Connection idle time (e.g., `10m`).
- `timeout`: Query timeout (e.g., `30s`).
- `bulkThreshold`: Row count to trigger `COPY` for inserts (default: 100).
- `autoCleanup`: For the cache feature if pg is used as cache; enables periodic cleanup of expired items (`true` or `1`).
- Standard PostgreSQL parameters like `sslmode`, `search_path` are also supported.

Example URI: `postgres://user:pass@host:5433/dbname?sslmode=disable&maxConns=100&minConns=25&connMaxLifetime=5m&timeout=30s&bulkThreshold=100`

#### PostgreSQL Context Handling

The plugin uses `SELECT set_config('request.claims_sub', 'user123', true);` for context variables.
Access them in SQL:

```sql
-- In a function or query
WHERE created_by = current_setting(\'request.claims_sub\', TRUE);
```

```sql
-- In a query via API
/api/pgdb/products/?where.eq.created_by=request.claims.sub
```

#### PostgreSQL Schema and Functions

- The plugin introspects schemas for tables, views, and functions/procedures from `information_schema` and `pg_catalog`.
- It determines column types, nullability, defaults, function parameters, and return types to build the API schema.
- The logic for schema discovery is implemented in the plugin itself (see `GetSchema` and related functions in `plugins/postgres/postgres.go`). It maps PostgreSQL types (e.g., `INTEGER`, `VARCHAR`, `TIMESTAMP`) to JSON schema types (`integer`, `string`).
- Example SQL for defining tables, functions (like `doSomething`, `getMyProducts`), and triggers (like `before_product_update`) that can leverage context variables via `current_setting()` can be found by inspecting the test schemas used with the plugin or adapting generic PostgreSQL examples.

#### PostgreSQL Setup using Docker

To run PostgreSQL in Docker (e.g., on port 5433):

```bash
docker run --name pg-easyrest -p 5433:5432 \
  -e POSTGRES_PASSWORD=root \
  -e POSTGRES_DB=easyrestdb \
  -d postgres:15
```

Apply your schema:

```bash
docker exec -i pg-easyrest psql -U postgres -d easyrestdb < your_schema.sql
```

### Redis (Cache)

- **Plugin Type:** `redis` (e.g., `uri: "redis://host:port/0"`)
- Built-in with `easyrest-server` (as a cache plugin). Can be used as `easyrest-plugin-redis` with `easyrest-gateway`.

#### Redis Key Features

- **Cache Operations:** Supports `SET` (with TTL) and `GET`.
- **Connection Pooling:** Uses `go-redis/redis` library's pooling.
- **Flexible Configuration:** Via Redis URI.

#### Redis Configuration Parameters

The URI can include standard Redis parameters and `go-redis` specific options:

- Scheme: `redis://` or `rediss://` (for TLS)
- User/Password: `user:password@`
- Host and Port: `host:port`
- Database Number: `/db_number`
- Query Parameters: `protocol`, `client_name`, `max_retries`, `min_retry_backoff`, `max_retry_backoff`, `dial_timeout`, `read_timeout`, `write_timeout`, `pool_fifo`, `pool_size`, `pool_timeout`, `min_idle_conns`, `max_idle_conns`, `conn_max_idle_time`, `conn_max_lifetime`, `skip_verify` (for TLS).

Example URI: `redis://user:password@myredishost:6379/1?dialTimeout=5s&readTimeout=2s&poolSize=100&minIdleConns=10`

#### Redis Setup using Docker

To run Redis in Docker:

```bash
docker run --name redis-easyrest -p 6379:6379 -d valkey/valkey:8
```

### LRU (Cache)

- **Plugin Type:** `lru` (e.g., `uri: "lru://?size=1000&ttl=5m"`)
- Built-in with `easyrest-server` (as a cache plugin).
- A simple in-memory Least Recently Used (LRU) cache.
- **Configuration via URI query parameters:**
  - `size`: Maximum number of items in the cache (default: 1000).
  - `ttl`: Default time-to-live for cache entries (e.g., `5m`, `1h`, default: 0 - no TTL).

---

## Configuration Parameters

EasyREST is configured via a YAML file or environment variables.
Command-line: `./easyrest-server -config /path/to/custom-config.yaml`
Environment: `ER_CONFIG_FILE`

### Main Configuration

```yaml
# Server settings
port: 8080 # Default: 8080
default_timezone: "GMT" # Default: "GMT" or system timezone
access_log: false # Enable access logging (default: false)

# Authentication & Authorization
check_scope: true # Enable JWT scope checking (default: true)
token_secret: "your-jwt-secret" # REQUIRED: Secret for JWT verification
token_user_search: "sub" # JWT claim for user ID (default: "sub")
token_url: "" # Optional: URL for external token validation/retrieval
auth_flow: "password" # Optional: OAuth flow type (default: "password")

# CORS settings (optional)
cors:
  enabled: true # Enable CORS headers (default: false)
  origins: ["*"] # List of allowed origins
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] # Allowed HTTP methods
  headers: ["Content-Type", "Authorization", "X-Requested-With"] # Allowed headers
  max_age: 86400 # Cache duration for preflight requests

# TLS settings (optional)
tls_enabled: false
tls_cert_file: "/path/to/cert.pem"
tls_key_file: "/path/to/key.pem"

# Plugin settings
plugin_log: true # Enable logging from plugins (default: false). Set to false to disable.

# --- Plugin Definitions ---

# Option 1: Include external YAML files containing plugin definitions
plugin_configs:
  - ./plugins/database1.yaml
  - /etc/easyrest/shared_plugins.yaml

# Option 2: Define plugins directly in the main config file
plugins:
  # The key ('test', 'orders', 'inventory') becomes the API path segment (/api/test/, /api/orders/, /api/inventory)
  test:
    # URI format: <plugin_type>://<connection_details>
    # The plugin_type (e.g., 'sqlite') determines the executable name (easyrest-plugin-sqlite)
    uri: "sqlite://./test.db"
    title: "Main Test Database API" # Optional: Custom title for this API in Swagger
    enable_cache: true # Enable ETag caching for this connection
    cache_name: test
    db_tx_end: commit-allow-override # Explicitly set default behavior
    # Define tables/functions accessible without authentication
    public:
      table:
        - public_info
      func:
        - get_server_status
    # Define tables/functions to hide completely from the API schema
    exclude:
      table:
        - internal_metadata
        - migration_history
      func:
        - internal_cleanup_job
    cache_invalidation_map:
      process_order:
        - orders
        - order_items
  orders:
    uri: "sqlite:///data/orders.db"
    enable_cache: true
    cache_name: orders
    # Example: Invalidate 'orders' and 'order_items' ETags when 'process_order' RPC is called
    cache_invalidation_map:
      process_order:
        - orders
        - order_items
  inventory:
    uri: "sqlite:///data/inventory.db"
    # enable_cache defaults to false if not specified

  # Example for a postgres plugin:
  # postgres_db:
  #   uri: "postgres://user:password@host:port/database?sslmode=disable"
  #   enable_cache: true

# --- Example External Plugin File (e.g., ./plugins/database1.yaml) --- Structure:
# - name: plugin_name # Name used in API path
#   uri: "plugin_type://connection_string"
#   path: "/path/to/plugin/binary" # Optional: Explicit path to plugin binary
#   title: "Custom API Title" # Optional: Override the default API title in Swagger
#   enable_cache: true # Optional: Enable ETag caching (default: false)
#   public: # Optional: Define tables/functions accessible without JWT authentication
#     table:
#       - public_table1
#       - public_table2
#     func:
#       - public_rpc1
#   exclude: # Optional: Define tables/functions to hide from the API schema
#     table:
#       - hidden_table1
#     func:
#       - hidden_rpc1
#   cache_invalidation_map: # Optional: Map RPC function names to tables whose ETags should be invalidated
#     rpc_function_name:
#       - table1_to_invalidate
#       - table2_to_invalidate
```

**Key Configuration Sections:**

- **Server Settings**: Basic server parameters like `port`, `default_timezone`.
- **Authentication & Authorization**: JWT settings (`token_secret` is mandatory), scope checking.
- **CORS**: Cross-Origin Resource Sharing settings.
- **TLS**: Enable HTTPS by providing certificate and key files.
- **Plugin Settings**:
  - `plugin_log`: Controls whether plugin logs are captured by the server.
  - `plugin_configs`: A list of paths to external YAML files. Each file can define one or more plugins using the structure shown in the example.
  - `plugins`: A map for defining plugins directly. The map key (e.g., `test`) is used as the database identifier in API requests (`/api/test/`).
  - **Plugin Definition Attributes**:
    - `name`: (Required in external files, derived from map key in inline definitions) The identifier used in the API path (`/api/<name>/`).
    - `uri`: (Required) Specifies the plugin type and connection details. The type (e.g., `sqlite`) maps to the executable name (`easyrest-plugin-sqlite`).
    - `path`: (Optional) Explicit path to the plugin executable. If omitted, EasyREST searches standard locations.
    - `title`: (Optional) A custom title for this specific plugin's API documentation (Swagger schema). If omitted, the default title "EasyRest API" is used.
    - `enable_cache`: (Optional, defaults to `false`) If `true`, enables ETag generation and checking (`If-Match`, `If-None-Match`) for **requests to this DB plugin's tables**. Requires at least one Cache plugin to be configured and loaded. This setting itself **does not affect** Cache plugins directly but enables the caching mechanism for operations related to this specific DB plugin.
    - `cache_name`: (Optional) Specifies the name (key from `plugins` map or `name` from an external file) of the **Cache plugin** that should be used for ETag caching for **this DB plugin**. If omitted, EasyREST first looks for a Cache plugin with the same name as this DB plugin (e.g., if the DB plugin name is `test`, it looks for Cache plugin `test`). If not found, it falls back to the first available Cache plugin. This setting allows flexible linking between DB and Cache plugins.
    - `cache_invalidation_map`: (Optional) A map where keys are RPC function names (used via `/api/<name>/rpc/<function_name>`) and values are lists of table names. When a listed RPC function is successfully executed for **this DB plugin** (`<name>`), the ETags for the specified tables associated with **this same DB plugin** are invalidated in the **corresponding Cache plugin**. This is useful if an RPC call modifies data in related tables.
    - `db_tx_end`: (Optional, defaults to `commit-allow-override`) Defines the default transaction handling behavior for write operations (POST, PATCH, DELETE) and RPC calls handled by this DB plugin, and whether the `Prefer: tx=` header can override it.
            - `commit`: Always commit the transaction upon successful completion of the operation. Ignore `Prefer: tx=rollback`.
            - `commit-allow-override`: Commit by default, but allow `Prefer: tx=rollback` to force a rollback even on success. **(Default behavior)**
            - `rollback`: Always roll back the transaction, even upon successful completion. Ignore `Prefer: tx=commit`. Useful for read-only simulations or dry runs.
            - `rollback-allow-override`: Roll back by default, but allow `Prefer: tx=commit` to force a commit on success.
    - `public`: (Optional) Defines tables and RPC functions within this plugin that are accessible **without any authentication** (no JWT required).
            - `table`: A list of table names that can be accessed publicly.
            - `func`: A list of RPC function names that can be called publicly.
            Scope checks (`check_scope`) are skipped for these public resources.
    - `exclude`: (Optional) Defines tables and RPC functions within this plugin that should be completely **hidden** from the API. They will not appear in the generated Swagger schema.
            - `table`: A list of table names to exclude.
            - `func`: A list of RPC function names to exclude.

- The server merges plugin definitions from `plugin_configs` files and the inline `plugins` map. Definitions in the inline map take precedence if names conflict.

---

## Examples

### Multiple SQLite Databases with Different Structures

Imagine you have two SQLite databases:

1. **Test Database (`ER_DB_TEST`):**  
   - **Path:** `./test.db`
   - **Table:** `users`  
     Structure: `id` (auto-increment), `name` (text), `update_field` (text)

2. **Orders Database (`ER_DB_ORDERS`):**  
   - **Path:** `./orders.db`
   - **Table:** `orders`  
     Structure: `id` (auto-increment), `items` (integer), `order_date` (date), `amount` (real)

Create a `config.yaml` file (or specify a different one with `-config`):

```yaml
port: 8080
token_secret: "your-secret"
token_user_search: "sub"
default_timezone: "America/Los_Angeles"
plugins:
  test:
    uri: "sqlite://./test.db"
  orders:
    uri: "sqlite://./orders.db"
```

**Query Examples:**

- **Using Context Variables:**
  ```
  GET /api/test/users/?select=id,name&where.eq.name=request.claims.sub
  ```
  or
  ```
  GET /api/test/users/?select=id,name&where.eq.name=erctx.claims_sub
  ```

- **Aggregating Queries:**
  ```
  GET /api/orders/?select=total:amount.sum(),order_date
  ```
  →  
  ```sql
  SELECT SUM(amount) AS total, order_date FROM orders GROUP BY order_date;
  ```

- **Data Insertion with Context:**
  ```
  POST /api/test/users/
  Body: [{"name": "request.claims.sub", "update_field": "new"}]
  ```

## API Documentation

Each plugin endpoint (`/api/<plugin-name>/`) provides a Swagger 2.0 JSON schema describing available tables and their structure. This documentation can be used to understand the database schema and build client applications.

For example:
```
GET /api/test/
```

Returns a Swagger 2.0 JSON schema for all tables in the test database.

---

## Developing External Plugins

External plugins allow you to extend EasyREST with support for different database backends or caching systems. A single plugin binary can provide implementations for either the `DBPlugin` interface, the `CachePlugin` interface, or both.

To create an external plugin (e.g., for MySQL DB and Redis Cache):

1.  **Create a New Repository:**
    For instance, create a repository named `easyrest-plugin-mysql-redis`.

2.  **Import Required Modules:**
    In your plugin's `go.mod`, add the necessary EasyREST and go-plugin dependencies:
    ```go
    require (
        github.com/onegreyonewhite/easyrest v0.x.x // Use the appropriate version
        github.com/hashicorp/go-plugin v1.x.x   // Use the appropriate version
    )
    ```
    Then, import the required packages in your Go files:
    ```go
    import (
        "context" // Often needed for context handling in implementations
        "time"    // Often needed for cache TTLs

        easyrest "github.com/onegreyonewhite/easyrest/plugin"
        hplugin "github.com/hashicorp/go-plugin"

        // Your specific DB/Cache driver imports, e.g.:
        // _ "github.com/go-sql-driver/mysql"
        // "github.com/redis/go-redis/v9"
    )
    ```

3.  **Implement the Interface(s):**
    Create a struct (or structs) that implements the methods defined in the `easyrest.DBPlugin` and/or `easyrest.CachePlugin` interfaces from `github.com/onegreyonewhite/easyrest/plugin`.

    ```go
    // Example structure implementing both interfaces
    type MyPlugin struct {
        // Add fields for DB connections, cache clients, etc.
        // e.g., db *sql.DB
        // e.g., redisClient *redis.Client
    }

    // --- DBPlugin Implementation ---

    func (p *MyPlugin) InitConnection(uri string) error {
        // Parse URI, establish DB connection (e.g., MySQL)
        // Store connection in p.db
        return nil
    }

    func (p *MyPlugin) TableGet(userID, table string, selectFields []string, where map[string]any, ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error) {
        // Implement logic to SELECT data from the database
        return nil, nil
    }

    func (p *MyPlugin) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
        // Implement logic to INSERT data into the database
        return nil, nil
    }

    func (p *MyPlugin) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error) {
        // Implement logic to UPDATE data in the database
        return 0, nil
    }

    func (p *MyPlugin) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, error) {
        // Implement logic to DELETE data from the database
        return 0, nil
    }

    func (p *MyPlugin) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
        // Implement logic for custom RPC functions (stored procedures, etc.)
        return nil, nil
    }

    func (p *MyPlugin) GetSchema(ctx map[string]any) (any, error) {
        // Implement logic to return the database schema in the expected format
        return nil, nil
    }

    // --- CachePlugin Implementation ---

    func (p *MyPlugin) InitConnection(uri string) error { // Can reuse or have separate logic from DB init
         // Parse URI, establish Cache connection (e.g., Redis)
         // Store connection in p.redisClient
         return nil
    }

    func (p *MyPlugin) Get(key string) (string, error) {
        // Implement logic to GET value from cache
        return "", nil
    }

    func (p *MyPlugin) Set(key string, value string, ttl time.Duration) error {
        // Implement logic to SET value in cache with TTL
        return nil
    }

    func (p *MyPlugin) Delete(keys []string) error {
        // Implement logic to DELETE keys from cache
        return nil
    }

    // Note: A plugin doesn't *have* to implement both interfaces.
    // If it only implements DBPlugin, only register "db".
    // If it only implements CachePlugin, only register "cache".
    ```

4.  **Register and Serve the Plugin:**
    In your plugin's `main` package (`main.go`), register your implementation(s) and start the plugin server. Use the `easyrest.Handshake` configuration.

    ```go
    func main() {
        // Create an instance of your plugin implementation
        impl := &MyPlugin{}

        // Define the plugins provided by this binary
        pluginMap := map[string]hplugin.Plugin{}

        // Register DBPlugin implementation if provided
        // Make sure 'impl' actually implements easyrest.DBPlugin
        pluginMap["db"] = &easyrest.DBPluginPlugin{Impl: impl}

        // Register CachePlugin implementation if provided
        // Make sure 'impl' actually implements easyrest.CachePlugin
        pluginMap["cache"] = &easyrest.CachePluginPlugin{Impl: impl}

        // Serve the plugin(s)
        hplugin.Serve(&hplugin.ServeConfig{
            HandshakeConfig: easyrest.Handshake,
            Plugins:         pluginMap,
        })
    }
    ```
    *Important:* Ensure your struct `impl` actually implements the methods for the interfaces you are registering (`DBPlugin` for `"db"`, `CachePlugin` for `"cache"`).

5.  **Build and Deploy:**
    Build the plugin binary (e.g., `go build -o easyrest-plugin-mysql-redis`). The binary name should ideally follow the convention `easyrest-plugin-<type>` (e.g., `easyrest-plugin-mysql`, `easyrest-plugin-redis`). EasyREST will look for these binaries:
    *   In the directories listed in your system's `PATH` environment variable.
    *   In the current working directory where EasyREST is run.
    *   In the same directory as the EasyREST executable itself.
    *   It also checks for OS/Arch specific names like `easyrest-plugin-mysql-linux-amd64`.

    Alternatively, you can specify the exact path to the plugin binary in the EasyREST configuration file (`ER_DB_<NAME>_PATH` or `ER_CACHE_<NAME>_PATH`).

6.  **Configure EasyREST:**
    Update your EasyREST configuration (environment variables or config file) to use your new plugin, referencing the connection name you used in `main.go` (e.g., `mysql` if the binary is `easyrest-plugin-mysql`).
    ```bash
    export ER_DB_PRIMARY="mysql://user:password@tcp(host:port)/database"
    # If the binary name doesn't match the type hint in the URI, or isn't in PATH:
    # export ER_DB_PRIMARY_PATH="/path/to/your/easyrest-plugin-mysql-redis"

    export ER_CACHE_PRIMARY="redis://host:port/0"
    # export ER_CACHE_PRIMARY_PATH="/path/to/your/easyrest-plugin-mysql-redis"
    ```

---

## License

EasyREST is licensed under the terms of the Apache License 2.0.
See the file "LICENSE" for more information.

Copyright 2025 Sergei Kliuikov
