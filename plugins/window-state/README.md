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
// Using standard @tauri-apps/plugin-window-state parity:
await window.__TAURI__.windowState.save('main');

const state = await window.__TAURI__.windowState.restore('main');
console.log("Restored size:", state.width, state.height);

// window.__TAURI_WINDOW_STATE__ is also available as a direct alias
```

---

## Security Hardening
* **Zero Command Injection:** Storage directories are created using native C FFI (`mkdir` / `_mkdir`), with zero shell or `os.execute` execution.
* **Label Sanitization:** Window labels are validated against `^[%w%-_%.]+$`, preventing prototype pollution or illegal storage identifiers.
