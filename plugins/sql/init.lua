local ffi = require("ffi")

-- ============================================================================
-- SQLite3 C API Declarations via FFI
-- ============================================================================
local ok_cdef = pcall(ffi.cdef, [[
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

int sqlite3_changes(sqlite3 *db);
long long sqlite3_last_insert_rowid(sqlite3 *db);
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
-- Plugin Implementation
-- ============================================================================
local SQLPlugin = {}
SQLPlugin.__index = SQLPlugin

local function normalize_db_path(path)
    if type(path) ~= "string" or path == "" then
        return "default.db"
    end
    return (path:gsub("^sqlite:", ""))
end

local function bind_params(db, stmt, values)
    if type(values) ~= "table" then return end
    for idx, val in ipairs(values) do
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
end

function SQLPlugin.init(options)
    options = options or {}
    local plugin_inst = setmetatable({}, SQLPlugin)
    plugin_inst.name = "sql"
    plugin_inst.db_pool = {}
    plugin_inst.default_path = options.default_path or "app.db"

    local function get_or_open_db(db_key)
        local key = normalize_db_path(db_key or plugin_inst.default_path)
        if plugin_inst.db_pool[key] then
            return plugin_inst.db_pool[key]
        end

        local db_ptr = ffi.new("sqlite3*[1]")
        local rc = sql_lib.sqlite3_open(key, db_ptr)
        if rc ~= 0 then
            local err = ffi.string(sql_lib.sqlite3_errmsg(db_ptr[0]))
            sql_lib.sqlite3_close(db_ptr[0])
            error(string.format("Failed to open SQLite database '%s': %s", key, err))
        end
        plugin_inst.db_pool[key] = db_ptr[0]
        return db_ptr[0]
    end

    local function execute_query(db_key, query, values)
        local db = get_or_open_db(db_key)
        local stmt_ptr = ffi.new("sqlite3_stmt*[1]")
        local prep_rc = sql_lib.sqlite3_prepare_v2(db, query, #query, stmt_ptr, nil)
        if prep_rc ~= 0 then
            error(string.format("SQLite prepare error: %s", ffi.string(sql_lib.sqlite3_errmsg(db))))
        end
        local stmt = stmt_ptr[0]
        bind_params(db, stmt, values)

        local step_rc = sql_lib.sqlite3_step(stmt)
        sql_lib.sqlite3_finalize(stmt)

        if step_rc ~= 101 and step_rc ~= 100 then -- SQLITE_DONE (101), SQLITE_ROW (100)
            error(string.format("SQLite execute error (%d): %s", step_rc, ffi.string(sql_lib.sqlite3_errmsg(db))))
        end

        local changes = tonumber(sql_lib.sqlite3_changes(db))
        local last_id = tonumber(sql_lib.sqlite3_last_insert_rowid(db))
        return {
            rowsAffected = changes,
            lastInsertId = last_id
        }
    end

    local function select_query(db_key, query, values)
        local db = get_or_open_db(db_key)
        local stmt_ptr = ffi.new("sqlite3_stmt*[1]")
        local prep_rc = sql_lib.sqlite3_prepare_v2(db, query, #query, stmt_ptr, nil)
        if prep_rc ~= 0 then
            error(string.format("SQLite prepare error: %s", ffi.string(sql_lib.sqlite3_errmsg(db))))
        end
        local stmt = stmt_ptr[0]
        bind_params(db, stmt, values)

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

    local function close_db(db_key)
        local key = normalize_db_path(db_key)
        local db = plugin_inst.db_pool[key]
        if db then
            sql_lib.sqlite3_close(db)
            plugin_inst.db_pool[key] = nil
            return true
        end
        return false
    end

    -- Plugin Definition returned to Tauri
    return {
        name = "sql",

        -- Expose direct Lua API for backend scripts:
        execute = execute_query,
        select = select_query,
        close = close_db,

        -- Setup hook called by app:plugin()
        setup = function(app, self_plugin)
            -- 1. Load DB
            app:register("plugin:sql|load", function(args)
                local path = type(args) == "table" and (args.db or args.path) or args
                get_or_open_db(path)
                return "sqlite:" .. normalize_db_path(path)
            end)

            -- 2. Execute Query (INSERT, UPDATE, DELETE, CREATE)
            app:register("plugin:sql|execute", function(args)
                local db_path = args.db or args.path or plugin_inst.default_path
                local query = args.query or args[1] or ""
                local values = args.values or args.params or args[2] or {}
                return execute_query(db_path, query, values)
            end)

            -- 3. Select Query (SELECT)
            app:register("plugin:sql|select", function(args)
                local db_path = args.db or args.path or plugin_inst.default_path
                local query = args.query or args[1] or ""
                local values = args.values or args.params or args[2] or {}
                return select_query(db_path, query, values)
            end)

            -- 4. Close DB
            app:register("plugin:sql|close", function(args)
                local db_path = type(args) == "table" and (args.db or args.path) or args
                return close_db(db_path)
            end)
        end,

        -- Client-side JavaScript Injected into Webview (@tauri-apps/plugin-sql parity)
        js = [[
            (function() {
                class Database {
                    constructor(path) {
                        this.path = path;
                    }
                    static async load(path) {
                        const dbPath = await window.__TAURI__.invoke('plugin:sql|load', { db: path });
                        return new Database(dbPath);
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

        -- Lifecycle hook: close all opened databases on window exit
        on_window_close = function(app, event)
            for key, db in pairs(plugin_inst.db_pool) do
                pcall(sql_lib.sqlite3_close, db)
            end
            plugin_inst.db_pool = {}
        end
    }
end

return SQLPlugin
