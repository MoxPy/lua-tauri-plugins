# Tauri-Lua Plugin: Autostart 🚀

> **Automatically launch your desktop application on user OS login/startup.**

Full 1:1 API parity with [`@tauri-apps/plugin-autostart`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/autostart).

---

## Features
* **Cross-Platform:**
  * **macOS:** Native LaunchAgent `.plist` in `~/Library/LaunchAgents` (Apple recommended).
  * **Linux:** Standard XDG Autostart `.desktop` specification in `~/.config/autostart`.
  * **Windows:** User Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
* **Zero Boilerplate:** Resolves executable or `.app` bundle path automatically via native OS APIs.
* **Full Parity:** Exposes `enable()`, `disable()`, and `isEnabled()`.

---

## Backend Usage (`Lua`)

```lua
local tauri = require("tauri")
local autostart = require("autostart")

local app = tauri.init()

app:plugin(autostart.init())

-- Direct Lua API
if not autostart.is_enabled() then
    autostart.enable()
end

app:run()
```

---

## Frontend Usage (`JavaScript / TypeScript`)

```javascript
import { isEnabled, enable, disable } from './plugins/autostart/guest-js';
// Or via pre-injected global:
// const { isEnabled, enable, disable } = window.__TAURI__.autostart;

// Check status
const active = await isEnabled();
console.log("Autostart is active:", active);

// Enable launch at login
await enable();

// Disable launch at login
await disable();
```


---

## Security Hardening
* **Zero Command Injection:** Windows Registry operations use direct Win32 `advapi32.dll` FFI calls (`RegOpenKeyExA`, `RegQueryValueExA`, `RegSetValueExA`, `RegDeleteValueA`). Shell processes (`reg.exe`, `cmd.exe`, `os.execute`) are completely eliminated.
* **Safe Directory Creation:** macOS LaunchAgent and Linux XDG autostart directories are created using native C FFI (`mkdir` / `_mkdir`).
* **Identifier Sanitization:** App identifiers are sanitized and validated against `^[%w%-_%.]+$`, preventing path traversal (`..`) or injection metacharacters.
