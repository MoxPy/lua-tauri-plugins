# Tauri-Lua Plugins Workspace 🔌

> **Official modular plugins for the [Tauri-Lua](https://github.com/MoxPy/lua-tauri) desktop framework.**

This monorepo hosts plug-and-play extensions for Tauri-Lua, modeled directly after the official [Tauri 2 plugins workspace](https://github.com/tauri-apps/plugins-workspace).

---

## Available Plugins

| Plugin | Description | Status |
| :--- | :--- | :---: |
| [**`sql`**](./plugins/sql) | Embedded **SQLite** database client powered by native C SQLite3 via LuaJIT FFI | ✅ Production |
| [**`window-state`**](./plugins/window-state) | Persist and restore window dimensions, coordinates, and maximize states | ✅ Production |
| **`http`** | Native non-CORS HTTP client with streaming download support | 🚧 Planned |
| **`autostart`** | Launch application automatically on user OS login | 🚧 Planned |
| **`log`** | Structured file and console logging with automatic log rotation | 🚧 Planned |

---

## How Plugins Work in Tauri-Lua

Tauri-Lua features automatic module resolution. If this repository is cloned alongside `lua-tauri`, the runtime detects all plugins inside `plugins/` automatically:

```lua
local tauri = require("tauri")
local app = tauri.init()

-- Load plugins directly by name
local sql = require("sql")
local window_state = require("window-state")

app:plugin(sql.init({ default_path = "app.db" }))
app:plugin(window_state.init())

app:run()
```

---

## License

MIT License. See [LICENSE](./LICENSE).
