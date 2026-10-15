local ffi = require("ffi")

-- ============================================================================
-- SQLite3 C API Declarations via FFI
-- ============================================================================
pcall(ffi.cdef, [[
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

int sqlite3_open(const char *filename, sqlite3 **ppDb);
int sqlite3_close(sqlite3 *db);
const char *sqlite3_errmsg(sqlite3 *db);

int sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
int sqlite3_step(sqlite3_stmt *stmt);
int sqlite3_finalize(sqlite3_stmt *stmt);
int sqlite3_reset(sqlite3_stmt *stmt);

int sqlite3_column_count(sqlite3_stmt *stmt);
const char *sqlite3_column_name(sqlite3_stmt *stmt, int N);
int sqlite3_column_type(sqlite3_stmt *stmt, int iCol);
long long sqlite3_column_int64(sqlite3_stmt *stmt, int iCol);
double sqlite3_column_double(sqlite3_stmt *stmt, int iCol);
const unsigned char *sqlite3_column_text(sqlite3_stmt *stmt, int iCol);

int sqlite3_bind_null(sqlite3_stmt *stmt, int index);
int sqlite3_bind_int64(sqlite3_stmt *stmt, int index, long long val);
int sqlite3_bind_double(sqlite3_stmt *stmt, int index, double val);
int sqlite3_bind_text(sqlite3_stmt *stmt, int index, const char *val, int n, void(*)(void*));
int sqlite3_bind_parameter_count(sqlite3_stmt *stmt);
int sqlite3_bind_parameter_index(sqlite3_stmt *stmt, const char *zName);

int sqlite3_changes(sqlite3 *db);
long long sqlite3_last_insert_rowid(sqlite3 *db);
int mkdir(const char *pathname, unsigned int mode);
int _mkdir(const char *pathname);
]])

local function load_sqlite_lib()
    local candidates = {
        "sqlite3",
        "/usr/lib/libsqlite3.dylib",
        "/usr/local/lib/libsqlite3.dylib",
        "/opt/homebrew/lib/libsqlite3.dylib",
        "libsqlite3.so.0",
        "libsqlite3.so",
        "sqlite3.dll"
    }
    for _, name in ipairs(candidates) do
        local ok, lib = pcall(ffi.load, name)
        if ok and lib then return lib end
    end
    error("Failed to load native SQLite3 shared library. Ensure sqlite3 is installed.")
end

local sql_lib = load_sqlite_lib()

-- ============================================================================
-- Path Resolution (App-Sandboxed Storage)
-- ============================================================================
local function get_app_data_dir(app)
    local app_id = (app.config.package and app.config.package.name) or app.config.productName or "tauri-app"
    local os_name = ffi.os
    if os_name == "OSX" then
        local home = os.getenv("HOME") or "."
        return home .. "/Library/Application Support/" .. app_id
    elseif os_name == "Windows" then
        local appdata = os.getenv("APPDATA") or "."
        return appdata .. "\\" .. app_id
    else
        local xdg = os.getenv("XDG_DATA_HOME")
        if xdg and xdg ~= "" then
            return xdg .. "/" .. app_id
        else
            local home = os.getenv("HOME") or "."
            return home .. "/.local/share/" .. app_id
        end
    end
end

local function safe_mkdir_p(target_path)
    if not target_path or target_path == "" or target_path == "." or target_path == "/" then
        return true
    end
    local normalized = target_path:gsub("\\", "/")
    local prefix = ""
    if normalized:match("^/") then
        prefix = "/"
        normalized = normalized:sub(2)
    elseif normalized:match("^[A-Za-z]:/") then
        prefix = normalized:sub(1, 3)
        normalized = normalized:sub(4)
    end

    local current = prefix
    for part in normalized:gmatch("[^/]+") do
        if part ~= "" and part ~= "." then
            current = (current == "" or current:match("/$")) and (current .. part) or (current .. "/" .. part)
            if ffi.os == "Windows" then
                pcall(function() ffi.C._mkdir(current) end)
            else
                pcall(function() ffi.C.mkdir(current, 493) end)
            end
        end
    end
    return true
end

local function resolve_db_path(app, raw_path, is_ipc, allowed_paths, allow_ipc_absolute)
    local path = (raw_path or ""):gsub("^sqlite:", "")
    if path == "" then path = "app.db" end
    if path == ":memory:" then return ":memory:" end

    if path:find("%z") then
        error("Null byte detected in database path: " .. tostring(raw_path))
    end

    -- Normalize slashes for traversal check
    local norm = path:gsub("\\", "/")
    -- Check for directory traversal
    if norm:match("(^|/)%.%.(/|$)") or norm:find("%.%.") then
        error(string.format("Sandbox violation: path traversal ('..') is forbidden in database path: '%s'", raw_path))
    end

    local is_abs = norm:match("^/") or norm:match("^[A-Za-z]:/")

    if is_abs then
        if is_ipc and not allow_ipc_absolute then
            local is_allowed = false
            for _, allowed in ipairs(allowed_paths or {}) do
                local norm_allowed = allowed:gsub("\\", "/")
                if norm == norm_allowed or norm:sub(1, #norm_allowed + 1) == (norm_allowed .. "/") then
                    is_allowed = true
                    break
                end
            end
            if not is_allowed then
                error(string.format("Sandbox violation: caller-provided absolute path '%s' is not in allowed_paths", raw_path))
            end
        end
        local parent = norm:match("^(.*)/[^/]+$")
        if parent and parent ~= "" then
            safe_mkdir_p(parent)
        end
        return norm
    end

    -- Sandbox relative path inside OS AppData directory
    local base_dir = get_app_data_dir(app)
    local full_path = base_dir:gsub("\\", "/") .. "/" .. norm
    local parent = full_path:match("^(.*)/[^/]+$")
    if parent and parent ~= "" then
        safe_mkdir_p(parent)
    end
    return full_path
end

-- ============================================================================
-- Parameter Binder (Supports ?, $1, ?1, and named :key / $key)
-- ============================================================================
local function bind_value(stmt, idx, val)
    local vtype = type(val)
    if vtype == "nil" then
        sql_lib.sqlite3_bind_null(stmt, idx)
    elseif vtype == "number" then
        if math.floor(val) == val then
            sql_lib.sqlite3_bind_int64(stmt, idx, val)
        else
            sql_lib.sqlite3_bind_double(stmt, idx, val)
        end
    elseif vtype == "boolean" then
        sql_lib.sqlite3_bind_int64(stmt, idx, val and 1 or 0)
    elseif vtype == "string" then
        sql_lib.sqlite3_bind_text(stmt, idx, val, #val, ffi.cast("void(*)(void*)", 0))
    else
        local s = tostring(val)
        sql_lib.sqlite3_bind_text(stmt, idx, s, #s, ffi.cast("void(*)(void*)", 0))
    end
end

local function bind_params(stmt, values)
    if type(values) ~= "table" then return end

    -- Check if array
    local is_array = true
    local count = 0
    for k, _ in pairs(values) do
        count = count + 1
        if type(k) ~= "number" then
            is_array = false
            break
        end
    end

    if is_array then
        for idx = 1, count do
            bind_value(stmt, idx, values[idx])
        end
    else
        -- Key-value dictionary: bind by parameter name ($name, :name)
        for k, val in pairs(values) do
            local prefixes = {"$", ":", "@"}
            for _, pfx in ipairs(prefixes) do
                local idx = sql_lib.sqlite3_bind_parameter_index(stmt, pfx .. tostring(k))
                if idx > 0 then
                    bind_value(stmt, idx, val)
                    break
                end
            end
        end
    end
end

-- ============================================================================
-- SQLite Driver Implementation
-- ============================================================================
local SQLiteDriver = {}
SQLiteDriver.__index = SQLiteDriver

function SQLiteDriver.new(db_ptr, path)
    local self = setmetatable({}, SQLiteDriver)
    self.handle = db_ptr
    self.path = path
    return self
end

function SQLiteDriver:execute(query, values)
    local stmt_ptr = ffi.new("sqlite3_stmt*[1]")
    local prep_rc = sql_lib.sqlite3_prepare_v2(self.handle, query, #query, stmt_ptr, nil)
    if prep_rc ~= 0 then
        error(string.format("SQLite prepare error: %s", ffi.string(sql_lib.sqlite3_errmsg(self.handle))))
    end
    local stmt = stmt_ptr[0]
    bind_params(stmt, values)

    local step_rc = sql_lib.sqlite3_step(stmt)
    sql_lib.sqlite3_finalize(stmt)

    if step_rc ~= 101 and step_rc ~= 100 then -- SQLITE_DONE (101), SQLITE_ROW (100)
        error(string.format("SQLite execute error (%d): %s", step_rc, ffi.string(sql_lib.sqlite3_errmsg(self.handle))))
    end

    return {
        rowsAffected = tonumber(sql_lib.sqlite3_changes(self.handle)),
        lastInsertId = tonumber(sql_lib.sqlite3_last_insert_rowid(self.handle))
    }
end

function SQLiteDriver:select(query, values)
    local stmt_ptr = ffi.new("sqlite3_stmt*[1]")
    local prep_rc = sql_lib.sqlite3_prepare_v2(self.handle, query, #query, stmt_ptr, nil)
    if prep_rc ~= 0 then
        error(string.format("SQLite prepare error: %s", ffi.string(sql_lib.sqlite3_errmsg(self.handle))))
    end
    local stmt = stmt_ptr[0]
    bind_params(stmt, values)

    local rows = {}
    local col_count = tonumber(sql_lib.sqlite3_column_count(stmt))
    local col_names = {}
    for c = 0, col_count - 1 do
        col_names[c] = ffi.string(sql_lib.sqlite3_column_name(stmt, c))
    end

    while sql_lib.sqlite3_step(stmt) == 100 do -- SQLITE_ROW
        local row = {}
        for c = 0, col_count - 1 do
            local ctype = sql_lib.sqlite3_column_type(stmt, c)
            local col_name = col_names[c]
            if ctype == 1 then -- INTEGER
                row[col_name] = tonumber(sql_lib.sqlite3_column_int64(stmt, c))
            elseif ctype == 2 then -- FLOAT
                row[col_name] = tonumber(sql_lib.sqlite3_column_double(stmt, c))
            elseif ctype == 3 then -- TEXT
                row[col_name] = ffi.string(sql_lib.sqlite3_column_text(stmt, c))
            elseif ctype == 5 then -- NULL
                row[col_name] = nil
            else
                row[col_name] = ffi.string(sql_lib.sqlite3_column_text(stmt, c))
            end
        end
        table.insert(rows, row)
    end
    sql_lib.sqlite3_finalize(stmt)
    return rows
end

function SQLiteDriver:close()
    if self.handle then
        sql_lib.sqlite3_close(self.handle)
        self.handle = nil
        return true
    end
    return false
end

-- ============================================================================
-- Migrations Engine (_sqlx_migrations Tauri Parity)
-- ============================================================================
local function apply_migrations(driver, migrations)
    if type(migrations) ~= "table" or #migrations == 0 then return end

    -- 1. Ensure migrations tracking table exists
    driver:execute([[
        CREATE TABLE IF NOT EXISTS _sqlx_migrations (
            version INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN NOT NULL,
            checksum TEXT NOT NULL,
            execution_time INTEGER NOT NULL
        );
    ]])

    -- 2. Query applied migrations
    local applied_rows = driver:select("SELECT version FROM _sqlx_migrations WHERE success = 1;")
    local applied_versions = {}
    for _, r in ipairs(applied_rows) do
        applied_versions[tonumber(r.version)] = true
    end

    -- 3. Sort migrations ascending by version
    local pending = {}
    for _, m in ipairs(migrations) do
        table.insert(pending, m)
    end
    table.sort(pending, function(a, b) return (a.version or 0) < (b.version or 0) end)

    -- 4. Execute pending migrations
    for _, m in ipairs(pending) do
        local ver = tonumber(m.version)
        if ver and not applied_versions[ver] then
            local desc = m.description or "migration_" .. tostring(ver)
            local sql = m.sql or ""

            driver:execute("BEGIN IMMEDIATE TRANSACTION;")
            local ok, err = pcall(function()
                driver:execute(sql)
                driver:execute(
                    "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (?, ?, 1, '', 0);",
                    { ver, desc }
                )
            end)

            if ok then
                driver:execute("COMMIT;")
                print(string.format("[SQL: Migration] Applied v%d (%s) successfully", ver, desc))
            else
                driver:execute("ROLLBACK;")
                error(string.format("Migration v%d (%s) failed: %s", ver, desc, tostring(err)))
            end
        end
    end
end

-- ============================================================================
-- SQL Plugin Manager
-- ============================================================================
local SQLPlugin = {}
SQLPlugin.__index = SQLPlugin

function SQLPlugin.init(options)
    options = options or {}
    local plugin_inst = setmetatable({}, SQLPlugin)
    plugin_inst.name = "sql"
    plugin_inst.db_pool = {}
    plugin_inst.migrations = options.migrations or {}
    plugin_inst.default_path = options.default_path or "sqlite:app.db"
    plugin_inst.allowed_paths = options.allowed_paths or {}
    plugin_inst.allow_ipc_absolute = options.allow_ipc_absolute == true
    plugin_inst.app = nil

    local function get_or_connect(db_key, load_options, is_ipc)
        load_options = load_options or {}
        local auto_create = load_options.autoCreate ~= false

        db_key = db_key or plugin_inst.default_path
        if plugin_inst.db_pool[db_key] then
            return plugin_inst.db_pool[db_key]
        end

        local scheme = db_key:match("^([%a%d]+):") or "sqlite"

        if scheme == "sqlite" then
            local resolved_path = resolve_db_path(plugin_inst.app, db_key, is_ipc, plugin_inst.allowed_paths, plugin_inst.allow_ipc_absolute)

            if not auto_create and resolved_path ~= ":memory:" then
                local f = io.open(resolved_path, "r")
                if not f then
                    error(string.format("Database file does not exist and autoCreate is false: %s", db_key))
                end
                f:close()
            end

            local db_ptr = ffi.new("sqlite3*[1]")
            local rc = sql_lib.sqlite3_open(resolved_path, db_ptr)
            if rc ~= 0 then
                local err = ffi.string(sql_lib.sqlite3_errmsg(db_ptr[0]))
                sql_lib.sqlite3_close(db_ptr[0])
                error(string.format("Failed to open SQLite database '%s': %s", resolved_path, err))
            end

            local driver = SQLiteDriver.new(db_ptr[0], resolved_path)
            plugin_inst.db_pool[db_key] = driver

            -- Run attached migrations if configured
            local db_migrations = plugin_inst.migrations[db_key] or plugin_inst.migrations
            if type(db_migrations) == "table" and #db_migrations > 0 then
                apply_migrations(driver, db_migrations)
            end

            return driver
        elseif scheme == "postgres" or scheme == "postgresql" then
            error("PostgreSQL driver connection planned. URL: " .. db_key)
        elseif scheme == "mysql" then
            error("MySQL driver connection planned. URL: " .. db_key)
        else
            error("Unsupported database driver scheme: " .. scheme)
        end
    end

    return {
        name = "sql",

        -- Backend Lua programmatic API
        execute = function(db_key, query, values)
            local driver = get_or_connect(db_key)
            return driver:execute(query, values)
        end,

        select = function(db_key, query, values)
            local driver = get_or_connect(db_key)
            return driver:select(query, values)
        end,

        close = function(db_key)
            local driver = plugin_inst.db_pool[db_key]
            if driver then
                driver:close()
                plugin_inst.db_pool[db_key] = nil
                return true
            end
            return false
        end,

        setup = function(app, self_plugin)
            plugin_inst.app = app

            -- 1. Preload databases configured in tauri.conf.json
            local tauri_plugins = app.config.plugins or (app.config.tauri and app.config.tauri.plugins) or {}
            local sql_conf = tauri_plugins.sql or {}
            if type(sql_conf.preload) == "table" then
                for _, db_url in ipairs(sql_conf.preload) do
                    get_or_connect(db_url, { autoCreate = true })
                end
            end

            -- 2. IPC: load
            app:register("plugin:sql|load", function(args)
                local db_path = type(args) == "table" and (args.db or args.path) or args
                local opts = type(args) == "table" and (args.options or args) or {}
                get_or_connect(db_path, opts, true)
                return db_path
            end)

            -- 3. IPC: execute
            app:register("plugin:sql|execute", function(args)
                local db_path = args.db or args.path or plugin_inst.default_path
                local query = args.query or args[1] or ""
                local values = args.values or args.params or args[2] or {}
                local driver = get_or_connect(db_path, nil, true)
                return driver:execute(query, values)
            end)

            -- 4. IPC: select
            app:register("plugin:sql|select", function(args)
                local db_path = args.db or args.path or plugin_inst.default_path
                local query = args.query or args[1] or ""
                local values = args.values or args.params or args[2] or {}
                local driver = get_or_connect(db_path, nil, true)
                return driver:select(query, values)
            end)

            -- 5. IPC: close
            app:register("plugin:sql|close", function(args)
                local db_path = type(args) == "table" and (args.db or args.path) or args
                local driver = plugin_inst.db_pool[db_path]
                if driver then
                    driver:close()
                    plugin_inst.db_pool[db_path] = nil
                    return true
                end
                return false
            end)
        end,

        -- Injected client JavaScript (@tauri-apps/plugin-sql full parity)
        js = [[
            (function() {
                class Database {
                    constructor(path) {
                        this.path = path;
                    }
                    static async load(path, options = {}) {
                        const dbPath = await window.__TAURI__.invoke('plugin:sql|load', { db: path, options: options });
                        return new Database(dbPath);
                    }
                    static async get(path) {
                        return new Database(path);
                    }
                    async execute(query, values = []) {
                        return window.__TAURI__.invoke('plugin:sql|execute', {
                            db: this.path,
                            query: query,
                            values: values
                        });
                    }
                    async select(query, values = []) {
                        return window.__TAURI__.invoke('plugin:sql|select', {
                            db: this.path,
                            query: query,
                            values: values
                        });
                    }
                    async close() {
                        return window.__TAURI__.invoke('plugin:sql|close', { db: this.path });
                    }
                }
                window.Database = Database;
                if (!window.__TAURI__) window.__TAURI__ = {};
                window.__TAURI__.sql = { Database };
            })();
        ]],

        on_window_close = function(app, event)
            for _, driver in pairs(plugin_inst.db_pool) do
                pcall(function() driver:close() end)
            end
            plugin_inst.db_pool = {}
        end
    }
end

return SQLPlugin
