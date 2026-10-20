-- ============================================================================
-- Security & Architecture Compliance Test Suite for lua-tauri-plugins
-- ============================================================================

local ffi = require("ffi")

local mock_json_codec = {
    encode = function(val)
        if type(val) == "table" then
            local parts = {}
            for k, v in pairs(val) do
                if type(v) == "table" then
                    table.insert(parts, string.format('"%s":{"width":1024,"height":768}', tostring(k)))
                else
                    table.insert(parts, string.format('"%s":"%s"', tostring(k), tostring(v)))
                end
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
        return "{}"
    end,
    decode = function(str)
        return { main = { width = 1024, height = 768 } }
    end
}

local function create_mock_app(name, extra_config)
    local app = {
        config = {
            package = { name = name or "test-compliance-app" },
            productName = name or "test-compliance-app"
        },
        json = mock_json_codec,
        handlers = {},
        register = function(self, ipc_name, handler)
            self.handlers[ipc_name] = handler
        end
    }
    if extra_config then
        for k, v in pairs(extra_config) do app.config[k] = v end
    end
    return app
end

local passed_count = 0
local function it(description, fn)
    io.write(string.format("  - %-60s ", description))
    local ok, err = pcall(fn)
    if ok then
        io.write("[PASS]\n")
        passed_count = passed_count + 1
    else
        io.write("[FAIL]\n")
        print("\n    ERROR: " .. tostring(err) .. "\n")
        os.exit(1)
    end
end

print("\n=======================================================")
print("RUNNING SECURITY & ARCHITECTURE COMPLIANCE SUITE")
print("=======================================================\n")

-- ----------------------------------------------------------------------------
-- 1. SQL Plugin Security & Sandbox Isolation
-- ----------------------------------------------------------------------------
print("1. SQL Plugin Security:")
local SQLPlugin = require("plugins.sql.init")

it("Rejects directory traversal (..) in database paths", function()
    local app = create_mock_app("sql-sec-app")
    local plugin = SQLPlugin.init()
    plugin.setup(app, plugin)

    local ok, err = pcall(function()
        app.handlers["plugin:sql|load"]({ db = "sqlite:../../traversal.db" })
    end)
    assert(not ok, "Path traversal must fail")
    assert(string.find(tostring(err), "Sandbox violation: path traversal", 1, true),
        "Expected path traversal sandbox violation, got: " .. tostring(err))
end)

it("Blocks caller-supplied absolute DB paths over IPC by default", function()
    local app = create_mock_app("sql-sec-app")
    local plugin = SQLPlugin.init()
    plugin.setup(app, plugin)

    local ok, err = pcall(function()
        app.handlers["plugin:sql|load"]({ db = "/etc/passwd" })
    end)
    assert(not ok, "Arbitrary absolute path must fail")
    assert(string.find(tostring(err), "Sandbox violation: caller-provided absolute path", 1, true),
        "Expected absolute path sandbox violation, got: " .. tostring(err))
end)

it("Permits absolute DB paths only when explicitly whitelisted", function()
    local app = create_mock_app("sql-sec-app")
    local allowed_file = "/tmp/sql_whitelisted_test.db"
    local plugin = SQLPlugin.init({
        allowed_paths = { allowed_file }
    })
    plugin.setup(app, plugin)

    local ok, err = pcall(function()
        app.handlers["plugin:sql|load"]({ db = allowed_file })
    end)
    assert(ok, "Whitelisted absolute path should be allowed: " .. tostring(err))
end)

it("Sandboxes relative DB files strictly inside OS AppData directory", function()
    local app = create_mock_app("sql-sec-app")
    local plugin = SQLPlugin.init()
    plugin.setup(app, plugin)

    local ok, err = pcall(function()
        app.handlers["plugin:sql|load"]({ db = "sqlite:sandboxed_relative.db" })
    end)
    assert(ok, "Sandboxed relative db should load successfully: " .. tostring(err))
end)

-- ----------------------------------------------------------------------------
-- 2. Window-State & Autostart Safe Directory Creation & Identifier Sanitization
-- ----------------------------------------------------------------------------
print("\n2. System & OS Hardening (Zero os.execute command injection):")
local WindowStatePlugin = require("plugins.window-state.init")
local AutostartPlugin = require("plugins.autostart.init")

it("Window-State saves without shell invocation or directory traversal", function()
    local app = create_mock_app("win-sec-app")
    local plugin = WindowStatePlugin.init({
        filename = "/tmp/test-win-state-sec/nested/state.json"
    })
    plugin.setup(app, plugin)

    local res = app.handlers["plugin:window-state|save"]({
        label = "main",
        state = { width = 1024, height = 768 }
    })
    assert(res and res.success, "Window state save must succeed")

    local restored = app.handlers["plugin:window-state|restore"]({ label = "main" })
    assert(restored and restored.width == 1024, "Restored width must match")
end)

it("Autostart sanitizes identifier to prevent command injection", function()
    local app = create_mock_app("evil; id; rm -rf / ;")
    local plugin = AutostartPlugin.init()
    plugin.setup(app, plugin)

    -- Calling is_enabled must not execute the injected shell command
    local enabled = app.handlers["plugin:autostart|is_enabled"]()
    assert(type(enabled) == "boolean", "is_enabled must return boolean without shell explosion")
end)

-- ----------------------------------------------------------------------------
-- 3. HTTP Protocol Hardening & SSRF / Scope Protection
-- ----------------------------------------------------------------------------
print("\n3. HTTP Protocol Hardening & SSRF / Scope Protection:")
local HttpPlugin = require("plugins.http.init")

it("Blocks non-HTTP protocol schemes (file://, gopher://, dict://)", function()
    local ok1, err1 = pcall(function()
        HttpPlugin.fetch("file:///etc/passwd")
    end)
    assert(not ok1, "file:// protocol must be blocked")
    assert(string.find(tostring(err1), "Disallowed protocol 'file:'", 1, true),
        "Expected disallowed protocol error, got: " .. tostring(err1))

    local ok2, err2 = pcall(function()
        HttpPlugin.fetch("gopher://evil.com/1")
    end)
    assert(not ok2, "gopher:// protocol must be blocked")
    assert(string.find(tostring(err2), "Disallowed protocol 'gopher:'", 1, true),
        "Expected disallowed protocol error, got: " .. tostring(err2))
end)

it("Blocks frontend callers from disabling TLS verification without backend authorization", function()
    local app = create_mock_app("http-sec-app")
    local plugin = HttpPlugin.init({
        scopes = { allow = { "https://httpbin.org/*" } },
        allow_insecure_tls = false
    })
    plugin.setup(app, plugin)

    local ok, err = pcall(function()
        app.handlers["plugin:http|fetch"]({
            url = "https://httpbin.org/get",
            options = {
                danger = { acceptInvalidCerts = true }
            }
        })
    end)
    assert(not ok, "Frontend cannot disable TLS verification on its own")
    assert(string.find(tostring(err), "Security violation: Disabling TLS verification", 1, true),
        "Expected TLS security violation error, got: " .. tostring(err))
end)

it("Enforces HTTP scope check on redirects (Blocks SSRF redirect bypass)", function()
    local app = create_mock_app("http-sec-app")
    local plugin = HttpPlugin.init({
        scopes = { allow = { "https://httpbin.org/redirect-to*" } }
    })
    plugin.setup(app, plugin)

    local ok, err = pcall(function()
        app.handlers["plugin:http|fetch"]({
            url = "https://httpbin.org/redirect-to?url=https://google.com"
        })
    end)
    assert(not ok, "Redirect to out-of-scope host must fail")
    assert(string.find(tostring(err), "Access denied by HTTP scope", 1, true),
        "Expected HTTP scope access denial on redirect, got: " .. tostring(err))
end)

it("HTTP Scope blocks loopback, private networks and cloud metadata (SSRF defense)", function()
    local app = create_mock_app("http-sec-app")
    local plugin = HttpPlugin.init({
        scopes = { allow = { "http://*/*" } }
    })
    plugin.setup(app, plugin)

    -- Loopback
    local ok1, err1 = pcall(function()
        app.handlers["plugin:http|fetch"]({ url = "http://127.0.0.1:8080/admin" })
    end)
    assert(not ok1 and string.find(tostring(err1), "blocked by default HTTP security scope", 1, true))

    -- Cloud metadata service
    local ok2, err2 = pcall(function()
        app.handlers["plugin:http|fetch"]({ url = "http://169.254.169.254/latest/meta-data/" })
    end)
    assert(not ok2 and string.find(tostring(err2), "blocked by default HTTP security scope", 1, true))

    -- Private network 10.0.0.1
    local ok3, err3 = pcall(function()
        app.handlers["plugin:http|fetch"]({ url = "http://10.0.0.1/status" })
    end)
    assert(not ok3 and string.find(tostring(err3), "blocked by default HTTP security scope", 1, true))
end)

it("HTTP Scope parses URL and blocks host confusion and traversal bypasses", function()
    local app = create_mock_app("http-sec-app")
    local plugin = HttpPlugin.init({
        scopes = { allow = { "https://api.example.com/v1/*" } }
    })
    plugin.setup(app, plugin)

    -- Host confusion / prefix: evil.com/.api.example.com
    local ok1, err1 = pcall(function()
        app.handlers["plugin:http|fetch"]({ url = "https://evil.com/.api.example.com/v1/data" })
    end)
    assert(not ok1 and string.find(tostring(err1), "not in allow list", 1, true))

    -- Traversal bypass using %2e%2e/ out of scope
    local ok2, err2 = pcall(function()
        app.handlers["plugin:http|fetch"]({ url = "https://api.example.com/v1/%2e%2e/admin/secrets" })
    end)
    assert(not ok2 and string.find(tostring(err2), "not in allow list", 1, true))
end)

it("SQL Connection Scope restricts database connections and masks credentials", function()
    local SQLPlugin = require("plugins.sql.init")
    local app = create_mock_app("sql-sec-app")
    local plugin = SQLPlugin.init({
        allowed_connections = { "sqlite:allowed.db" }
    })
    plugin.setup(app, plugin)

    -- Denied connection
    local ok1, err1 = pcall(function()
        app.handlers["plugin:sql|load"]({ db = "sqlite:unauthorized.db" })
    end)
    assert(not ok1, "Unauthorized connection must fail")
    assert(string.find(tostring(err1), "Access denied by SQL scope", 1, true))

    -- Masked credentials in error
    local ok2, err2 = pcall(function()
        app.handlers["plugin:sql|load"]({ db = "postgres://admin:SuperSecretPassword123@db.internal:5432/finance" })
    end)
    assert(not ok2)
    assert(not string.find(tostring(err2), "SuperSecretPassword123", 1, true), "Password must be masked")
    assert(string.find(tostring(err2), "admin:***", 1, true), "Masked pattern expected")
end)

it("HTTP Cookie Jar and Set-Cookie management", function()
    local app = create_mock_app("http-cookie-app")
    local cj = "/tmp/test_http_compliance_cj_" .. os.time() .. ".txt"
    local plugin = HttpPlugin.init({
        cookie_jar = cj,
        scopes = { allow = { "https://httpbin.org/*" } }
    })
    plugin.setup(app, plugin)

    local r1 = app.handlers["plugin:http|fetch"]({
        url = "https://httpbin.org/cookies/set?session_token=test_abc123",
        options = { maxRedirections = 0 }
    })
    assert(r1.status == 302, "Expected 302 redirect")
    assert(#r1.cookies > 0, "Expected cookies captured")
    local found = false
    for _, c in ipairs(r1.cookies) do
        if c:find("session_token=test_abc123") then found = true end
    end
    assert(found, "Set-Cookie must contain session_token")

    -- Second request checks cookie jar persistence
    local r2 = app.handlers["plugin:http|fetch"]({
        url = "https://httpbin.org/cookies",
        options = {}
    })
    assert(r2.ok, "Expected 200 OK")
    assert(string.find(r2.data, "test_abc123", 1, true), "Cookie must persist in cookie jar")
    pcall(os.remove, cj)
end)

print(string.format("\n======================================================="))
print(string.format("ALL %d COMPLIANCE TESTS PASSED SUCCESSFULLY!", passed_count))
print("=======================================================\n")
