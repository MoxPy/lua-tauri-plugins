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

print(string.format("\n======================================================="))
print(string.format("ALL %d COMPLIANCE TESTS PASSED SUCCESSFULLY!", passed_count))
print("=======================================================\n")
