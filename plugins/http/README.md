# Tauri-Lua Plugin: HTTP 🌐

> **High-performance, native HTTP/HTTPS client powered by `libcurl` via LuaJIT FFI with CORS bypass, SSL/TLS certificate verification, and URL scope gating.**

Full 1:1 API parity with [`@tauri-apps/plugin-http`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/http).

---

## Features
* **Zero CORS Restrictions:** Performed natively by the backend runtime, not constrained by browser origin policies.
* **Powered by `libcurl`:** Near-zero overhead, streaming, connection pooling, and HTTP/1.1 & HTTP/2 support.
* **Strict Cybersecurity Scopes & SSRF Protection:** Configure `allow` and `deny` glob patterns. Redirects are re-validated on every hop to eliminate SSRF bypasses.
* **Protocol Allowlist:** Strictly permits `http://` and `https://` protocols only; non-HTTP schemes like `file://` or `gopher://` are blocked.
* **TLS Hardening:** Frontend callers cannot disable TLS verification unless explicitly authorized by backend configuration (`allow_insecure_tls = true`).
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


---

## Security Architecture & Hardening

1. **Protocol Gating:** Requests to non-HTTP/HTTPS URLs (`file:///etc/passwd`, `gopher://`, `dict://`) are rejected at the native boundary and locked via `CURLOPT_PROTOCOLS`.
2. **Per-Hop Redirect Validation (CWE-601 / SSRF):** Libcurl does not follow redirects blindly. An internal loop inspects the `Location` header and re-evaluates `assert_url_in_scope` before making subsequent requests.
3. **TLS Verification Protection:** Insecure TLS (`danger.acceptInvalidCerts = true`) requested by frontend callers is rejected with a `Security violation` error unless explicitly enabled in `HttpPlugin.init({ allow_insecure_tls = true })` on the backend.
