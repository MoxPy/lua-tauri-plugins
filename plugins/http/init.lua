local ffi = require("ffi")

-- ============================================================================
-- libcurl C API Declarations via FFI
-- ============================================================================
pcall(ffi.cdef, [[
typedef void CURL;
typedef int CURLcode;

struct curl_slist {
    char *data;
    struct curl_slist *next;
};

CURL *curl_easy_init();
void curl_easy_cleanup(CURL *curl);
CURLcode curl_easy_setopt(CURL *curl, int option, ...);
CURLcode curl_easy_perform(CURL *curl);
const char *curl_easy_strerror(CURLcode errornum);
CURLcode curl_easy_getinfo(CURL *curl, int info, ...);
struct curl_slist *curl_slist_append(struct curl_slist *, const char *);
void curl_slist_free_all(struct curl_slist *);

typedef size_t (*curl_write_callback)(char *ptr, size_t size, size_t nmemb, void *userdata);
]])

local function load_curl_lib()
    local candidates = {
        "libcurl",
        "/usr/lib/libcurl.dylib",
        "/usr/lib/libcurl.4.dylib",
        "libcurl.so.4",
        "libcurl.so",
        "libcurl.dll"
    }
    for _, name in ipairs(candidates) do
        local ok, lib = pcall(ffi.load, name)
        if ok and lib then return lib end
    end
    error("Failed to load native libcurl library. Ensure curl is installed.")
end

local curl_lib = load_curl_lib()

-- CURLOPT constants
local CURLOPT_URL            = 10002
local CURLOPT_FOLLOWLOCATION = 52
local CURLOPT_MAXREDIRS      = 68
local CURLOPT_CONNECTTIMEOUT_MS = 156
local CURLOPT_TIMEOUT_MS     = 155
local CURLOPT_CUSTOMREQUEST  = 10036
local CURLOPT_POSTFIELDS     = 10015
local CURLOPT_POSTFIELDSIZE  = 60
local CURLOPT_HTTPHEADER     = 10023
local CURLOPT_WRITEFUNCTION  = 20011
local CURLOPT_HEADERFUNCTION = 20079
local CURLOPT_SSL_VERIFYPEER = 64
local CURLOPT_SSL_VERIFYHOST = 81
local CURLOPT_USERAGENT      = 10018
local CURLOPT_PROTOCOLS       = 181
local CURLOPT_REDIR_PROTOCOLS = 182

-- Protocol constants
local CURLPROTO_HTTP          = 1
local CURLPROTO_HTTPS         = 2
local ALLOWED_PROTOCOLS       = 3LL -- CURLPROTO_HTTP | CURLPROTO_HTTPS

-- CURLINFO constants
local CURLINFO_RESPONSE_CODE = 2097154
local CURLINFO_EFFECTIVE_URL = 1048577

-- ============================================================================
-- Protocol Hardening (Only HTTP and HTTPS Permitted)
-- ============================================================================
local function assert_url_protocol(url)
    if type(url) ~= "string" or url == "" then
        error("URL must be a non-empty string")
    end
    local scheme = url:match("^([%a][%w%+%-%*]*)://")
    if not scheme then
        error(string.format("Invalid URL (missing or malformed protocol scheme): %s", url))
    end
    scheme = scheme:lower()
    if scheme ~= "http" and scheme ~= "https" then
        error(string.format("Disallowed protocol '%s:' in URL '%s'. Only 'http://' and 'https://' are permitted.", scheme, url))
    end
    return scheme
end

-- ============================================================================
-- URL Scope Validation (Cybersecurity Glob Matching)
-- ============================================================================
local function url_matches_pattern(url, pattern)
    local escaped = pattern:gsub("%%", "%%%%"):gsub("([%^%$%(%)%.%[%]%+%-%?])", "%%%1")
    local lua_pat = "^" .. escaped:gsub("%*", ".*") .. "$"
    return url:match(lua_pat) ~= nil
end

local function assert_url_in_scope(url, scopes)
    if not scopes or (#(scopes.allow or {}) == 0 and #(scopes.deny or {}) == 0) then
        return true
    end

    -- 1. Check deny list first
    for _, item in ipairs(scopes.deny or {}) do
        local pattern = type(item) == "table" and item.url or item
        if url_matches_pattern(url, pattern) then
            error(string.format("Access denied by HTTP scope (deny list): %s", url))
        end
    end

    -- 2. Check allow list
    if scopes.allow and #scopes.allow > 0 then
        local allowed = false
        for _, item in ipairs(scopes.allow) do
            local pattern = type(item) == "table" and item.url or item
            if url_matches_pattern(url, pattern) then
                allowed = true
                break
            end
        end
        if not allowed then
            error(string.format("Access denied by HTTP scope (not in allow list): %s", url))
        end
    end

    return true
end

-- ============================================================================
-- Redirect URL Normalization
-- ============================================================================
local function resolve_redirect_url(base_url, location)
    if not location or location == "" then
        return base_url
    end
    if location:match("^https?://") then
        return location
    end
    if location:match("^//") then
        local scheme = base_url:match("^(https?:)") or "http:"
        return scheme .. location
    end
    if location:match("^/") then
        local origin = base_url:match("^(https?://[^/]+)")
        if origin then
            return origin .. location
        end
    end
    local base_prefix = base_url:match("^(https?://.*/)")
    if base_prefix then
        return base_prefix .. location
    end
    local origin = base_url:match("^(https?://[^?#]+)") or base_url
    return origin .. "/" .. location
end

-- ============================================================================
-- Single HTTP Hop Execution
-- ============================================================================
local function single_fetch(url, options, plugin_config)
    options = options or {}
    local method = (options.method or "GET"):upper()

    local handle = curl_lib.curl_easy_init()
    if handle == nil then
        error("Failed to allocate curl handle")
    end

    -- Restrict protocols strictly to HTTP and HTTPS at libcurl level
    pcall(function()
        curl_lib.curl_easy_setopt(handle, CURLOPT_PROTOCOLS, ALLOWED_PROTOCOLS)
        curl_lib.curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS, ALLOWED_PROTOCOLS)
    end)

    -- Disable automatic redirects in libcurl: Lua loop re-validates scope per hop
    curl_lib.curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0LL)

    -- Set URL
    curl_lib.curl_easy_setopt(handle, CURLOPT_URL, url)
    curl_lib.curl_easy_setopt(handle, CURLOPT_USERAGENT, options.userAgent or "Tauri-Lua-HTTP/1.0")

    -- Custom HTTP Method
    if method ~= "GET" then
        curl_lib.curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, method)
    end

    -- Timeouts (in milliseconds)
    local timeout_ms = tonumber(options.connectTimeout) or tonumber(options.timeout) or 30000
    curl_lib.curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, ffi.cast("long", timeout_ms))
    curl_lib.curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, ffi.cast("long", timeout_ms))

    -- TLS Hardening: caller cannot disable verification unless backend authorized
    local danger = options.danger or {}
    local wants_insecure = (danger.acceptInvalidCerts == true or danger.acceptInvalidHostnames == true)
    if wants_insecure then
        local backend_allowed = plugin_config and (plugin_config.allow_insecure_tls == true or (type(plugin_config.danger) == "table" and plugin_config.danger.acceptInvalidCerts == true))
        if not backend_allowed then
            curl_lib.curl_easy_cleanup(handle)
            error("Security violation: Disabling TLS verification (acceptInvalidCerts/acceptInvalidHostnames) is forbidden unless explicitly authorized in backend configuration (allow_insecure_tls = true).")
        end
        curl_lib.curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0LL)
        curl_lib.curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0LL)
    else
        curl_lib.curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1LL)
        curl_lib.curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2LL)
    end

    -- Headers
    local header_list = nil
    if type(options.headers) == "table" then
        for k, v in pairs(options.headers) do
            local header_str = string.format("%s: %s", tostring(k), tostring(v))
            header_list = curl_lib.curl_slist_append(header_list, header_str)
        end
        if header_list ~= nil then
            curl_lib.curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list)
        end
    end

    -- Request Body (POST/PUT/PATCH)
    local body_str = nil
    if options.body ~= nil then
        if type(options.body) == "string" then
            body_str = options.body
        elseif type(options.body) == "table" then
            local ok_json, json_encoded = pcall(function()
                return require("tauri").json.encode(options.body)
            end)
            body_str = ok_json and json_encoded or tostring(options.body)
        else
            body_str = tostring(options.body)
        end
        curl_lib.curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body_str)
        curl_lib.curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, ffi.cast("long", #body_str))
    end

    -- Body & Header Callbacks
    local body_chunks = {}
    local response_headers = {}

    local write_cb = ffi.cast("curl_write_callback", function(ptr, size, nmemb, userdata)
        local total = size * nmemb
        table.insert(body_chunks, ffi.string(ptr, total))
        return total
    end)

    local header_cb = ffi.cast("curl_write_callback", function(ptr, size, nmemb, userdata)
        local total = size * nmemb
        local raw_line = ffi.string(ptr, total)
        local k, v = raw_line:match("^([^:]+):%s*(.-)[\r\n]*$")
        if k and v then
            response_headers[k:lower()] = v
        end
        return total
    end)

    curl_lib.curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_cb)
    curl_lib.curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_cb)

    -- Perform Request
    local rc = curl_lib.curl_easy_perform(handle)

    -- Extract status and effective URL
    local status_buf = ffi.new("long[1]")
    curl_lib.curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, status_buf)
    local status_code = tonumber(status_buf[0])

    local url_buf = ffi.new("char*[1]")
    curl_lib.curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, url_buf)
    local final_url = (url_buf[0] ~= nil) and ffi.string(url_buf[0]) or url

    -- Cleanup
    if header_list ~= nil then
        curl_lib.curl_slist_free_all(header_list)
    end
    curl_lib.curl_easy_cleanup(handle)
    write_cb:free()
    header_cb:free()

    if rc ~= 0 then
        local err_msg = ffi.string(curl_lib.curl_easy_strerror(rc))
        error(string.format("HTTP request to '%s' failed: %s (code %d)", url, err_msg, rc))
    end

    local full_body = table.concat(body_chunks)
    local status_text = (status_code >= 200 and status_code < 300) and "OK" or "Error"

    return {
        status = status_code,
        statusText = status_text,
        ok = (status_code >= 200 and status_code < 300),
        headers = response_headers,
        url = final_url,
        data = full_body
    }
end

-- ============================================================================
-- HTTP Request Core Execution (With Per-Hop Scope & Protocol Verification)
-- ============================================================================
local function perform_fetch(url, options, scopes, plugin_config)
    options = options or {}
    local current_url = url
    local current_options = {}
    for k, v in pairs(options) do current_options[k] = v end

    local max_redirs = tonumber(options.maxRedirections)
    if max_redirs == nil then max_redirs = 5 end
    local redirect_count = 0

    while true do
        -- 1. Validate protocol scheme (http/https only)
        assert_url_protocol(current_url)

        -- 2. Validate scopes (both allow and deny lists) on EVERY hop
        assert_url_in_scope(current_url, scopes)

        -- 3. Execute single request hop
        local res = single_fetch(current_url, current_options, plugin_config)

        -- 4. Check for redirect response
        local is_redirect = (res.status == 301 or res.status == 302 or res.status == 303 or res.status == 307 or res.status == 308)
        local location = res.headers and res.headers["location"]

        if is_redirect and location and max_redirs > 0 then
            if redirect_count >= max_redirs then
                error(string.format("Maximum redirections (%d) exceeded for URL '%s'", max_redirs, url))
            end
            redirect_count = redirect_count + 1
            local next_url = resolve_redirect_url(current_url, location)

            -- Handle method rewrite for 303 or 301/302 POST -> GET
            local meth = (current_options.method or "GET"):upper()
            if res.status == 303 or ((res.status == 301 or res.status == 302) and meth == "POST") then
                current_options.method = "GET"
                current_options.body = nil
            end

            current_url = next_url
        else
            return res
        end
    end
end

-- ============================================================================
-- HTTP Plugin Declaration
-- ============================================================================
local HttpPlugin = {}
HttpPlugin.__index = HttpPlugin

-- Static module methods for direct usage
HttpPlugin.fetch = function(url, opts)
    return perform_fetch(url, opts, nil, nil)
end

HttpPlugin.get = function(url, opts)
    opts = opts or {}
    opts.method = "GET"
    return perform_fetch(url, opts, nil, nil)
end

HttpPlugin.post = function(url, body, opts)
    opts = opts or {}
    opts.method = "POST"
    opts.body = body
    return perform_fetch(url, opts, nil, nil)
end

function HttpPlugin.init(options)
    options = options or {}
    local plugin_inst = setmetatable({}, HttpPlugin)
    plugin_inst.name = "http"
    plugin_inst.scopes = options.scope or options.scopes or {}
    plugin_inst.allow_insecure_tls = options.allow_insecure_tls == true or (type(options.danger) == "table" and options.danger.acceptInvalidCerts == true)
    plugin_inst.app = nil

    return {
        name = "http",

        -- Direct instance Lua API
        fetch = function(url, opts)
            return perform_fetch(url, opts, plugin_inst.scopes, plugin_inst)
        end,

        get = function(url, opts)
            opts = opts or {}
            opts.method = "GET"
            return perform_fetch(url, opts, plugin_inst.scopes, plugin_inst)
        end,

        post = function(url, body, opts)
            opts = opts or {}
            opts.method = "POST"
            opts.body = body
            return perform_fetch(url, opts, plugin_inst.scopes, plugin_inst)
        end,

        setup = function(app, self_plugin)
            plugin_inst.app = app

            -- Load security scopes from config if present
            local tauri_sec = (app.config.tauri and app.config.tauri.security) or app.config.security or {}
            if tauri_sec.http_scope then
                plugin_inst.scopes = tauri_sec.http_scope
            end

            -- IPC: fetch
            app:register("plugin:http|fetch", function(args)
                local url = type(args) == "table" and (args.url or args[1]) or args
                local opts = type(args) == "table" and (args.options or args) or {}
                return perform_fetch(url, opts, plugin_inst.scopes, plugin_inst)
            end)
        end,

        -- Injected Guest JavaScript API
        js = [[
            (function() {
                class HttpResponse {
                    constructor(payload) {
                        this.status = payload.status;
                        this.statusText = payload.statusText;
                        this.ok = payload.ok;
                        this.headers = new Headers(payload.headers || {});
                        this.url = payload.url;
                        this._data = payload.data || "";
                    }
                    async text() {
                        return this._data;
                    }
                    async json() {
                        return JSON.parse(this._data);
                    }
                }

                async function fetch(url, options = {}) {
                    const payload = await window.__TAURI__.invoke('plugin:http|fetch', {
                        url: url,
                        options: options
                    });
                    return new HttpResponse(payload);
                }

                window.__TAURI_HTTP__ = { fetch };
                if (!window.__TAURI__) window.__TAURI__ = {};
                window.__TAURI__.http = { fetch };
            })();
        ]]
    }
end

return HttpPlugin
