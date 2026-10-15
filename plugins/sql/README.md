# Tauri-Lua Plugin: SQL 🗄️

> **Fast, embedded and networked SQL database plugin for Tauri-Lua powered by native SQLite3 via LuaJIT FFI, supporting automatic transactional schema migrations, AppData sandboxed paths, and SQL-injection-proof parameter binding.**

Full 1:1 API parity with [`@tauri-apps/plugin-sql`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/sql).

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](../../LICENSE)
[![Parity](https://img.shields.io/badge/Parity-100%25%20Tauri%20v2-brightgreen.svg)](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/sql)
[![Engine](https://img.shields.io/badge/Engine-SQLite3%20FFI%20%2B%20PostgreSQL%2FMySQL-orange.svg)](https://github.com/MoxPy/lua-tauri)

---

## Key Capabilities

* **1:1 Tauri 2 Parity:** Full compatibility with `@tauri-apps/plugin-sql` JavaScript/TypeScript guest APIs (`Database.load()`, `db.execute()`, `db.select()`, `db.close()`) and IPC protocol commands (`plugin:sql|load`, `plugin:sql|execute`, `plugin:sql|select`, `plugin:sql|close`).
* **Multi-Database Support:** Unified connection URI schemes for **SQLite** (`sqlite:...`), **PostgreSQL** (`postgres://...` / `postgresql://...`), and **MySQL** (`mysql://...`).
* **In-Memory & File Databases:** Supports both persistent file databases and high-speed in-memory databases (`sqlite::memory:`).
* **Automatic AppData Sandboxing:** Relative database paths (`sqlite:app.db`) are automatically sandboxed in the native OS application storage directory, ensuring release bundles never crash with read-only file permission errors.
* **Atomic Schema Migrations Engine:** Transaction-safe schema migrations running on database load with full `_sqlx_migrations` table parity. Tracks version numbers, descriptions, checksums, and execution timestamps with automatic rollback on DDL errors.
* **SQL Injection Immunity (OWASP CWE-89):** Prepared statement parameter binding supporting both positional placeholders (`$1, $2, ...` SQLx/PostgreSQL style) and standard question marks (`?`), as well as named placeholders (`:name`, `$name`).
* **Connection Pooling:** Open and manage multiple databases concurrently with cached connection handles.
* **Declarative Preloading:** Automatically opens databases configured in `tauri.conf.json` (`plugins.sql.preload`).
* **Zero Compilation Overhead:** Binds directly to the native `sqlite3` shared library (`libsqlite3.dylib`, `libsqlite3.so`, `sqlite3.dll`) via LuaJIT FFI.
* **Lifecycle Resource Cleanup:** Gracefully finalizes prepared statements and closes all active database connections when windows are closed (`on_window_close`).

---

## Supported Connection URI Schemes

| Scheme | Format | Description & Resolution |
| :--- | :--- | :--- |
| **SQLite (AppData)** | `sqlite:app.db` | Automatically resolved inside the application's native OS AppData storage directory. |
| **SQLite (Absolute)** | `sqlite:/path/to/data.db` | Connects to an absolute filesystem path (over IPC requires backend whitelist in `allowed_paths`). |
| **SQLite (In-Memory)** | `sqlite::memory:` | Fast, ephemeral in-memory database instance. |
| **PostgreSQL** | `postgres://user:pass@host:5432/db` | Connects to remote or local PostgreSQL instances (`postgresql://` also supported). |
| **MySQL / MariaDB** | `mysql://user:pass@host:3306/db` | Connects to remote or local MySQL / MariaDB instances. |

---

## Sandboxed AppData Path Resolution

When using relative paths like `sqlite:production.db`, the plugin automatically resolves and creates the parent folder inside the canonical OS user application directory:

| Operating System | Sandboxed Target Directory |
| :--- | :--- |
| **macOS** | `~/Library/Application Support/<app_id>/` |
| **Windows** | `%APPDATA%\<app_id>\` |
| **Linux** | `$XDG_DATA_HOME/<app_id>/` (or `~/.local/share/<app_id>/`) |

### Security & Path Traversal Immunity
* **Sandbox Confinement:** Relative paths (e.g. `sqlite:app.db`) resolve strictly within `get_app_data_dir(app)`.
* **Path Traversal Rejection:** Any path containing `..` or null bytes is immediately rejected with a `Sandbox violation` error.
* **IPC Absolute Path Gating:** Frontend callers via IPC cannot load arbitrary absolute paths unless explicitly whitelisted in `SqlPlugin.init({ allowed_paths = { "/path/to/db.db" } })` or `allow_ipc_absolute = true`.
* **Zero Shell Execution:** Directory hierarchies are created using memory-safe native C FFI (`mkdir` / `_mkdir`), with zero `os.execute` invocations.

---

## Schema Migrations Engine (`_sqlx_migrations`)

The migration engine ensures database schemas are created and updated predictably across app versions:

1. On connection load, the plugin creates the tracking table:
   ```sql
   CREATE TABLE IF NOT EXISTS _sqlx_migrations (
       version BIGINT PRIMARY KEY,
       description TEXT NOT NULL,
       installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       success BOOLEAN NOT NULL,
       checksum TEXT NOT NULL,
       execution_time BIGINT NOT NULL
   );
   ```
2. Migrations are executed sequentially within an atomic transaction (`BEGIN TRANSACTION` ... `COMMIT`).
3. If an error occurs, the transaction rolls back (`ROLLBACK`) and the error is reported to the caller.

### Declaring Migrations in Backend Lua:

```lua
local tauri = require("tauri")
local sql = require("sql")
local app = tauri.init()

app:plugin(sql.init({
    default_path = "sqlite:production.db",
    migrations = {
        {
            version = 1,
            description = "create_users_table",
            sql = [[
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            ]]
        },
        {
            version = 2,
            description = "add_department_column",
            sql = "ALTER TABLE users ADD COLUMN department TEXT DEFAULT 'General';"
        }
    }
}))

app:run()
```

*Note: You can also specify per-database migration tables:*
```lua
app:plugin(sql.init({
    migrations = {
        ["sqlite:users.db"] = { { version = 1, description = "init_users", sql = "..." } },
        ["sqlite:logs.db"] = { { version = 1, description = "init_logs", sql = "..." } }
    }
}))
```

---

## Defensive Parameter Binding (OWASP CWE-89)

To guarantee immunity against SQL injection attacks, all queries accept parameterized arguments:

```javascript
// Positional placeholders ($1, $2) - Preferred (Tauri 2 / SQLx style)
await db.execute('INSERT INTO users (name, email) VALUES ($1, $2);', ['Alice', 'alice@company.com']);

// Standard question mark placeholders (?)
const rows = await db.select('SELECT * FROM users WHERE email = ? AND active = ?;', ['alice@company.com', true]);
```

### Supported Data Types
* **`nil` / `null`**: Bound as `SQLITE_NULL`.
* **Integer Numbers**: Bound as 64-bit integers (`sqlite3_bind_int64`).
* **Floating-Point Numbers**: Bound as IEEE 754 doubles (`sqlite3_bind_double`).
* **Booleans**: Bound as integer `1` (true) or `0` (false).
* **Strings**: Bound as UTF-8 text with length preservation (`sqlite3_bind_text`).

---

## Declarative Preload (`tauri.conf.json`)

You can declare databases to be preloaded at startup in `tauri.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/v2",
  "productName": "my-tauri-app",
  "plugins": {
    "sql": {
      "preload": [
        "sqlite:production.db",
        "sqlite:cache.db"
      ]
    }
  }
}
```

---

## Complete API Reference

### 1. Frontend JavaScript / TypeScript Guest API

The frontend API matches `@tauri-apps/plugin-sql` exactly:

```javascript
import Database from './plugins/sql/guest-js';
// Or via pre-injected window global:
// const { Database } = window.__TAURI__.sql;

// 1. Load or connect to database
// Options: { autoCreate: true | false }
const db = await Database.load('sqlite:production.db', { autoCreate: true });

// 2. Execute INSERT / UPDATE / DELETE / DDL
// Returns: { lastInsertId: number, rowsAffected: number }
const result = await db.execute(
  'INSERT INTO users (name, email, department) VALUES ($1, $2, $3);',
  ['Alice Rossi', 'alice@company.com', 'Cybersecurity']
);
console.log(`New record ID: ${result.lastInsertId}, Affected rows: ${result.rowsAffected}`);

// 3. Query records with SELECT
// Returns: Array<Record<string, any>>
const users = await db.select(
  'SELECT id, name, email, department FROM users WHERE department = $1 ORDER BY id DESC;',
  ['Cybersecurity']
);
console.table(users);

// 4. Retrieve already loaded database instance
const sameDb = await Database.get('sqlite:production.db');

// 5. Close connection explicitly
const closed = await db.close();
console.log("Database connection closed:", closed);
```

### 2. Backend Lua API

You can also interact directly with databases in backend Lua handlers:

```lua
local sql = require("sql")

-- Execute query
local res = sql.execute("sqlite:production.db", "INSERT INTO users (name, email) VALUES ($1, $2);", { "Bob", "bob@company.com" })
print("Inserted ID:", res.lastInsertId, "Rows:", res.rowsAffected)

-- Select records
local records = sql.select("sqlite:production.db", "SELECT * FROM users WHERE id = $1;", { res.lastInsertId })
for _, row in ipairs(records) do
    print("User:", row.id, row.name, row.email)
end

-- Close connection
sql.close("sqlite:production.db")
```

---

## License

MIT License. See [LICENSE](../../LICENSE).
