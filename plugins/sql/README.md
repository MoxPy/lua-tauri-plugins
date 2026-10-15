# Tauri-Lua Plugin: SQL (SQLite) 🗄️

> **Fast, embedded SQL database plugin for Tauri-Lua powered by native SQLite3 via LuaJIT FFI.**

Full API parity with [`@tauri-apps/plugin-sql`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/sql).

---

## Features
* **Zero Compilation Needed:** Binds directly to the host operating system's native `sqlite3` library (`libsqlite3.dylib` on macOS, `libsqlite3.so` on Linux, `sqlite3.dll` on Windows) with zero C boilerplate.
* **Prepared Statements & Parameter Binding:** Protects against SQL injections with automatic typing (`nil`, `boolean`, `integer`, `float`, `text`).
* **Connection Pool:** Manage multiple distinct database files simultaneously.
* **Guest JavaScript SDK:** Pre-injected `window.__TAURI__.sql.Database` and modular JS client.

---

## Backend Usage (`Lua`)

```lua
local tauri = require("tauri")
local sql = require("sql")

local app = tauri.init()

-- Register plugin
app:plugin(sql.init({ default_path = "myapp.db" }))

-- Direct Lua access (optional)
local res = sql.execute("myapp.db", "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, text TEXT);")
sql.execute("myapp.db", "INSERT INTO notes (text) VALUES (?);", { "Hello from Lua backend!" })

local rows = sql.select("myapp.db", "SELECT * FROM notes;")
for _, row in ipairs(rows) do
    print("Note:", row.id, row.text)
end

app:run()
```

---

## Frontend Usage (`JavaScript / TypeScript`)

```javascript
import Database from './plugins/sql/guest-js';
// Or use the automatically injected global:
// const { Database } = window.__TAURI__.sql;

// 1. Open or create database
const db = await Database.load('sqlite:myapp.db');

// 2. Create table
await db.execute(`
  CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    done INTEGER DEFAULT 0
  );
`);

// 3. Insert records with parameterized queries
const result = await db.execute(
  'INSERT INTO todos (title, done) VALUES (?, ?);',
  ['Buy milk', 0]
);
console.log(`Inserted row ID: ${result.lastInsertId}`);

// 4. Query records
const todos = await db.select('SELECT * FROM todos WHERE done = ?;', [0]);
console.table(todos);

// 5. Close database
await db.close();
```
