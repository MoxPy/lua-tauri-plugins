# Tauri-Lua Plugin: Window State 🪟

> **Automatically remember, persist, and restore window positions, dimensions, and maximize states across application restarts.**

Full API parity with [`@tauri-apps/plugin-window-state`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/window-state).

---

## Features
* **Auto-Persist on Close:** Saves coordinates and dimensions when windows close.
* **Declarative Storage:** Saves to `$APPDATA/<app-name>/window-state.json` or custom path.
* **Multi-Window Support:** Tracks each window independently by its `label`.
* **Guest JS Bindings:** Pre-injected `window.__TAURI_WINDOW_STATE__` and ESM module.

---

## Backend Usage (`Lua`)

```lua
local tauri = require("tauri")
local window_state = require("window-state")

local app = tauri.init()

-- Register plugin
app:plugin(window_state.init({
    filename = "window-state.json" -- optional custom path
}))

app:run()
```

---

## Frontend Usage (`JavaScript / TypeScript`)

```javascript
// Using global injected helper
await window.__TAURI_WINDOW_STATE__.save('main');

const state = await window.__TAURI_WINDOW_STATE__.restore('main');
console.log("Restored size:", state.width, state.height);
```
