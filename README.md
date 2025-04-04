# EasyREST

EasyREST is a lightweight, extensible REST service that provides a unified API for performing CRUD and aggregating queries on relational databases. Its key innovation is the use of a plugin system that allows you to connect to virtually any database (or data source) simply by writing a plugin that conforms to the EasyREST interface. Out of the box, an SQLite plugin is provided, but you can easily add plugins for MySQL, PostgreSQL, Oracle, or any other database.

EasyREST handles authentication via JWT, validates and sanitizes request parameters at the controller level, and then passes 100% safe SQL expressions to the plugins. The service supports complex queries including aggregations, aliasing, advanced WHERE conditions, and even the use of context variables that allow you to influence query behavior dynamically.

---

## Table of Contents

- [Architecture](#architecture)
  - [Overall Architecture Diagram](#overall-architecture-diagram)
  - [Plugin Communication](#plugin-communication)
  - [Authentication and Authorization](#authentication-and-authorization)
- [Query Capabilities](#query-capabilities)
  - [Selecting Fields and Aliasing](#selecting-fields-and-aliasing)
  - [Aggregating Queries](#aggregating-queries)
  - [WHERE Conditions](#where-conditions)
  - [Context Variables](#context-variables)
  - [Data Insertion, Updates, and Deletion](#data-insertion-updates-and-deletion)
- [Configuration Parameters](#configuration-parameters)
- [Examples](#examples)
  - [Multiple SQLite Databases with Different Structures](#multiple-sqlite-databases-with-different-structures)
- [Building and Running](#building-and-running)
  - [Building the Server](#building-the-server)
  - [Building a Plugin (SQLite)](#building-a-plugin-sqlite)
  - [Running Tests and Benchmarks](#running-tests-and-benchmarks)
- [License](#license)

---

## Architecture

EasyREST's design emphasizes simplicity, extensibility, and security. It follows a modular architecture where the core server is responsible for:

- **Authentication & Authorization:** Validates JWT tokens and verifies scopes.
- **Parameter Validation:** Ensures that all parameters (select, where, ordering, etc.) are safe before forwarding to the plugins.
- **Plugin Orchestration:** Loads and manages DB plugins based on YAML configuration.
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
    J --> K["DB Plugin (e.g., SQLite)"]
    K --> F[Build SQL Query]
    F --> L[Database]
    L --> M[Return Results to DB Plugin]
    M --> J2[Return Results to Plugin Client RPC Call]
    J2 --> B2[Return to EasyREST Server]
    B2 --> N[HTTP Response]
```

### Plugin Communication

- **RPC Communication:** EasyREST uses Hashicorp's [go-plugin](https://github.com/hashicorp/go-plugin) system to load and communicate with plugins. The server launches plugin processes based on the `plugins` section in the YAML configuration file and establishes an RPC connection.
- **Data Exchange:** The server sends validated and sanitized SQL expressions and additional context data to the plugin. Context variables are directly substituted into the query.
- **Type Registration:** For secure and reliable encoding/decoding over RPC, custom types (e.g., `time.Time` and flattened JWT claims) are registered with the gob package.

### Authentication and Authorization

- **JWT Authentication:** Requests must include a Bearer token. The server verifies the token signature (using a secret from configuration) and extracts claims.
- **Scope-based Authorization:** The service verifies that the token's claims include the required scope (e.g., `users-read` for GET operations, `users-write` for modifications or wide `read` and `write` for all table names).  
- **Token Claims:** The claims are flattened and passed to plugins (under the key `claims` in the context map) so that plugins can leverage user-specific information if needed.

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

1. **erctx Format:**
   Uses underscore notation to access context variables:
   ```
   /api/test/users/?where.eq.name=erctx.claims_sub
   ```

2. **request Format:**
   Uses JSON path notation with dots:
   ```
   /api/test/users/?where.eq.name=request.claims.sub
   ```

Available context variables:

- **timezone:** Current timezone from Prefer header or default
- **headers:** All HTTP request headers (lowercase keys)
- **claims:** JWT token claims (lowercase keys)
- **method:** HTTP request method
- **path:** Request URL path
- **query:** Raw query string
- **prefer:** Key-value pairs from Prefer header

The `Prefer` header can be used to pass plugin-specific context parameters:
```
Prefer: timezone=UTC param1=value1 param2=value2
```

### Data Insertion, Updates, and Deletion

- **Insertion (POST):**  
  Data is passed as JSON in the request body. The server builds an `INSERT INTO` statement after validating the column names. Context variables can be used in values using either `erctx.` or `request.` notation.
- **Update (PATCH):**  
  The update request requires a JSON object in the request body (with columns to update) and optional where conditions in the query string. Context variables can be used in both the update data and where conditions.
- **Deletion (DELETE):**  
  Deletion is based solely on the where parameters. Context variables can be used in where conditions.

---

## Configuration Parameters

EasyREST is configured primarily using a YAML file or environment variables. You can specify a different path using the `-config` command-line flag:

```bash
./easyrest-server -config /path/to/your/custom-config.yaml
```

Alternatively, the path can be set using the `ER_CONFIG_FILE` environment variable. Environment variables (`ER_*`) can also be used to override specific settings, but the YAML file is the recommended approach.

**YAML Configuration Structure:**

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
  # The key ('test', 'orders') becomes the API path segment (/api/test/, /api/orders/)
  test:
    # URI format: <plugin_type>://<connection_details>
    # The plugin_type (e.g., 'sqlite') determines the executable name (easyrest-plugin-sqlite)
    uri: "sqlite://./test.db"
  orders:
    uri: "sqlite:///data/orders.db"
  # Example for a postgres plugin:
  # postgres_db:
  #   uri: "postgres://user:password@host:port/database?sslmode=disable"

# --- Example External Plugin File (e.g., ./plugins/database1.yaml) ---
# - name: test # Must match the key used in the API path
#   uri: "sqlite://./test.db"
#   path: "/usr/local/bin/easyrest-plugin-sqlite" # Optional: Explicit path to plugin binary
```

**Key Configuration Sections:**

- **Server Settings**: Basic server parameters like `port`, `default_timezone`.
- **Authentication & Authorization**: JWT settings (`token_secret` is mandatory), scope checking.
- **CORS**: Cross-Origin Resource Sharing settings.
- **TLS**: Enable HTTPS by providing certificate and key files.
- **Plugin Settings**:
    - `plugin_log`: Controls whether plugin logs are captured by the server.
    - `plugin_configs`: A list of paths to external YAML files. Each file can define one or more plugins using the structure shown in the example (with `name`, `uri`, and optional `path`).
    - `plugins`: A map for defining plugins directly. The map key (e.g., `test`) is used as the database identifier in API requests (`/api/test/`). The value must contain a `uri` field.
    - **Plugin URI**: The `uri` specifies both the plugin type (which maps to the executable name, e.g., `sqlite` -> `easyrest-plugin-sqlite`) and the connection details (DSN) for that plugin.
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

To create an external plugin (e.g., a MySQL plugin):

1. **Create a New Repository:**  
   For instance, create a repository named `easyrest-plugin-mysql`.

2. **Import Required Modules:**  
   In your plugin's `go.mod`, add:
   ```go
   require (
       github.com/onegreyonewhite/easyrest v0.1.0
       github.com/hashicorp/go-plugin v1.6.3
   )
   ```
   Then, import the required packages:
   ```go
   import (
       easyrest "github.com/onegreyonewhite/easyrest/plugin"
       hplugin "github.com/hashicorp/go-plugin"
   )
   ```

3. **Implement the Interface:**  
   Implement the `DBPlugin` interface defined in `easyrest/plugin`. Use the same handshake configuration (accessible as `easyrest.Handshake`).

4. **Structure Your Repository:**  
   - Have a main package (e.g.,  `main.go`) that registers your plugin using:
     ```go
     func main() {
         impl := &mysqlPlugin{}
         hplugin.Serve(&hplugin.ServeConfig{
             HandshakeConfig: easyrest.Handshake,
             Plugins: map[string]hplugin.Plugin{
                 "db": &easyrest.DBPluginPlugin{Impl: impl},
             },
         })
     }
     ```
   - Organize your code so that the core logic is in packages that can be independently tested.

5. **Build and Deploy:**  
   Build the plugin binary with `go build` and ensure it is discoverable by EasyREST (via naming conventions and PATH configuration).

### Changes in EasyREST Repository

In the EasyREST core, nothing changes except that you now reference plugins by their binary names (e.g., `easyrest-plugin-mysql`) using `exec.LookPath`. Document the expected naming convention so that external plugins can be built and integrated independently.

---

## License

EasyREST is licensed under the terms of the Apache License 2.0.
See the file "LICENSE" for more information.

Copyright 2025 Sergei Kliuikov
