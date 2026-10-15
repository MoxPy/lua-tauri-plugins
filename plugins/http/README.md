# Tauri-Lua Plugin: HTTP 🌐

> **High-performance, native HTTP/HTTPS client powered by `libcurl` via LuaJIT FFI with CORS bypass, SSL/TLS certificate verification, and URL scope gating.**

Full 1:1 API parity with [`@tauri-apps/plugin-http`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/http).

---

## Features
* **Zero CORS Restrictions:** Performed natively by the backend runtime, not constrained by browser origin policies.
* **Powered by `libcurl`:** Near-zero overhead, streaming, connection pooling, and HTTP/1.1 & HTTP/2 support.
* **Strict Cybersecurity Scopes:** Configure `allow` and `deny` glob patterns to restrict outgoing requests.
* **Web Standard `fetch` Interface:** Identical to standard browser `fetch()`, returning `Response` with `.text()` and `.json()`.

---

## Backend Usage (`Lua`)

```lua
local tauri = require("tauri")
local http = require("http")

local app = tauri.init()

-- Optional: Restrict network destinations
app:plugin(http.init({
    scopes = {
        allow = { "https://api.github.com/*", "https://*.example.com/*" },
        deny = { "https://api.github.com/admin/*" }
    }
}))

-- Direct Lua API
local res = http.get("https://api.github.com/zen")
if res.ok then
    print("GitHub Zen:", res.data)
end

app:run()
```

---

## Frontend Usage (`JavaScript / TypeScript`)

```javascript
import { fetch } from './plugins/http/guest-js';
// Or via pre-injected global:
// const { fetch } = window.__TAURI__.http;

// 1. GET Request (Bypassing CORS completely!)
const res = await fetch('https://api.github.com/users/octocat');
if (res.ok) {
  const user = await res.json();
  console.log("GitHub User:", user.login, user.name);
}

// 2. POST Request with JSON Body and Custom Headers
const postRes = await fetch('https://httpbin.org/post', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer my_token'
  },
  body: JSON.stringify({ message: "Hello from Tauri-Lua!" })
});
console.log("Response:", await postRes.json());
```
