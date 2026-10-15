# Tauri-Lua Plugins Workspace 🔌

> **Official modular plugins for the [Tauri-Lua](https://github.com/MoxPy/lua-tauri) desktop framework.**

This monorepo hosts plug-and-play extensions for Tauri-Lua, modeled directly after the official [Tauri 2 plugins workspace](https://github.com/tauri-apps/plugins-workspace).

---

## Available Plugins

| Plugin | Description | Status |
| :--- | :--- | :---: |
| [**`sql`**](./plugins/sql) | Embedded **SQLite** database client powered by native C SQLite3 via LuaJIT FFI, with automatic schema migrations and AppData sandboxing | ✅ Production |
| [**`http`**](./plugins/http) | High-performance HTTP/HTTPS client powered by native **libcurl** via LuaJIT FFI with CORS bypass and security scopes | ✅ Production |
| [**`autostart`**](./plugins/autostart) | Launch application automatically on user OS login (macOS LaunchAgent, Linux XDG, Windows Registry) | ✅ Production |
| [**`window-state`**](./plugins/window-state) | Persist and restore window dimensions, coordinates, and maximize states | ✅ Production |
| **`websocket`** | Native client WebSockets with binary streaming | 🚧 Planned |
| **`log`** | Structured file and console logging with automatic log rotation | 🚧 Planned |

---

## How Plugins Work in Tauri-Lua

Tauri-Lua features automatic module resolution. When this repository is placed alongside `lua-tauri`, the runtime detects all plugins inside `plugins/` automatically:

```lua
local tauri = require("tauri")
local app = tauri.init()

-- Load plugins directly by name
local sql = require("sql")
local http = require("http")
local autostart = require("autostart")
local window_state = require("window-state")

app:plugin(sql.init({
    default_path = "sqlite:app.db",
    migrations = {
        { version = 1, description = "create_users", sql = "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);" }
    }
}))
app:plugin(http.init({
    scopes = { allow = { "https://*.example.com/*" } }
}))
app:plugin(autostart.init())
app:plugin(window_state.init())

app:run()
```

---

## License

MIT License. See [LICENSE](./LICENSE).
