# Tauri-Lua Plugin: SQL 🗄️

> **Fast, embedded SQL database plugin for Tauri-Lua powered by native SQLite3 via LuaJIT FFI with automatic schema migrations, AppData path resolution, and parameter binding.**

Full 1:1 API parity with [`@tauri-apps/plugin-sql`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/sql).

---

## Features
* **100% Tauri 2 Parity:** Fully compatible with `@tauri-apps/plugin-sql` JavaScript API and IPC protocols.
* **Schema Migrations Engine:** Automatic, transaction-safe schema migrations (`_sqlx_migrations` table parity) running on database connect.
* **AppData Sandboxed Paths:** `sqlite:myapp.db` automatically resolves inside the OS application support directory (`~/Library/Application Support/<app>` on macOS, `%APPDATA%` on Windows, `~/.local/share` on Linux) so packaged applications never fail with read-only file errors.
* **Universal Parameter Syntax:** Supports `$1, $2, ...` (sqlx/Postgres standard), `?` positional parameters, and named parameters (`:name`, `$name`).
* **Connection Pooling:** Manage multiple databases simultaneously.
* **Preload Configuration:** Automatically preloads databases declared in `tauri.conf.json`.
* **Zero Compilation Needed:** Binds directly to the native `sqlite3` shared library (`libsqlite3.dylib`, `libsqlite3.so`, `sqlite3.dll`) via LuaJIT FFI.

---

## Backend Usage (`Lua`)

```lua
local tauri = require("tauri")
local sql = require("sql")

local app = tauri.init()

-- 1. Configure Plugin with Automatic Migrations
app:plugin(sql.init({
    default_path = "sqlite:app.db",
    migrations = {
        {
            version = 1,
            description = "create_users_table",
            sql = "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL);"
        },
        {
            version = 2,
            description = "add_email_column",
            sql = "ALTER TABLE users ADD COLUMN email TEXT;"
        }
    }
}))

-- 2. Direct Lua API (optional)
local res = sql.execute("sqlite:app.db", "INSERT INTO users (name, email) VALUES ($1, $2);", { "Alice", "alice@example.com" })
print("Inserted row ID:", res.lastInsertId)

local users = sql.select("sqlite:app.db", "SELECT * FROM users WHERE id = $1;", { res.lastInsertId })
for _, u in ipairs(users) do
    print("User:", u.name, u.email)
end

app:run()
```

---

## Frontend Usage (`JavaScript / TypeScript`)

```javascript
import Database from './plugins/sql/guest-js';
// Or use the pre-injected global:
// const { Database } = window.__TAURI__.sql;

// 1. Connect to database (runs migrations automatically)
const db = await Database.load('sqlite:app.db');

// 2. Insert records using $1, $2 or ?
const result = await db.execute(
  'INSERT INTO users (name, email) VALUES ($1, $2);',
  ['Bob', 'bob@example.com']
);
console.log(`Inserted ID: ${result.lastInsertId}, Rows affected: ${result.rowsAffected}`);

// 3. Query records
const users = await db.select('SELECT * FROM users WHERE name = $1;', ['Bob']);
console.table(users);

// 4. Close connection
await db.close();
```

---

## Declarative Preload (`tauri.conf.json`)

```json
{
  "plugins": {
    "sql": {
      "preload": [
        "sqlite:app.db"
      ]
    }
  }
}
```
