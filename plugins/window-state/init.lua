local ffi = require("ffi")

pcall(ffi.cdef, [[
    int mkdir(const char *pathname, unsigned int mode);
    int _mkdir(const char *pathname);
]])

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

local WindowStatePlugin = {}
WindowStatePlugin.__index = WindowStatePlugin

local function get_json_codec(app, plugin_inst)
    if plugin_inst and plugin_inst.json then return plugin_inst.json end
    if app and app.json then return app.json end
    local ok, tauri = pcall(require, "tauri")
    if ok and tauri and tauri.json then return tauri.json end
    local ok_cjson, cjson = pcall(require, "cjson")
    if ok_cjson and cjson then return cjson end
    error("JSON codec not found on app instance or tauri module")
end

local function sanitize_label(label)
    if type(label) == "string" and label:match("^[%w%-_%.]+$") and label ~= "__proto__" then
        return label
    end
    return "main"
end

local function get_default_storage_path(app)
    local app_name = (app.config.package and app.config.package.name) or app.config.productName or "tauri-app"
    local home = os.getenv("HOME") or os.getenv("USERPROFILE") or "."
    return home .. "/.local/share/" .. app_name .. "/window-state.json"
end

function WindowStatePlugin.init(options)
    options = options or {}
    local plugin_inst = setmetatable({}, WindowStatePlugin)
    plugin_inst.name = "window-state"
    plugin_inst.filename = options.filename
    plugin_inst.json = options.json
    plugin_inst.state = {}

    local function resolve_path(app)
        return plugin_inst.filename or get_default_storage_path(app)
    end

    local function load_state(app)
        local json = get_json_codec(app, plugin_inst)
        local path = resolve_path(app)
        local f = io.open(path, "r")
        if f then
            local content = f:read("*a")
            f:close()
            local decoded = json.decode(content)
            plugin_inst.state = decoded or {}
        end
        return plugin_inst.state
    end

    local function save_state(app, label, window_data)
        local json = get_json_codec(app, plugin_inst)
        local path = resolve_path(app)
        local parent = path:match("^(.*)/[^/]+$")
        if parent and parent ~= "" then
            safe_mkdir_p(parent)
        end

        local safe_lbl = sanitize_label(label)
        plugin_inst.state[safe_lbl] = window_data

        local f = io.open(path, "w")
        if f then
            local json_str = json.encode(plugin_inst.state)
            f:write(json_str)
            f:close()
            return true
        end
        return false
    end

    return {
        name = "window-state",

        setup = function(app, self_plugin)
            load_state(app)

            -- 1. Save Window State
            app:register("plugin:window-state|save", function(args)
                local label = (type(args) == "table" and args.label) or "main"
                local state_data = type(args) == "table" and (args.state or args) or {}
                local ok = save_state(app, label, state_data)
                return { success = ok }
            end)

            -- 2. Restore Window State
            app:register("plugin:window-state|restore", function(args)
                local raw_label = (type(args) == "table" and args.label) or (type(args) == "string" and args) or "main"
                local label = sanitize_label(raw_label)
                load_state(app)
                return plugin_inst.state[label] or {
                    width = 960,
                    height = 640,
                    x = 100,
                    y = 100,
                    maximized = false,
                    fullscreen = false
                }
            end)
        end,

        js = [[
            (function() {
                const helper = {
                    save: function(label = "main") {
                        return window.__TAURI__.invoke('plugin:window-state|save', {
                            label: label,
                            state: {
                                width: window.outerWidth || window.innerWidth,
                                height: window.outerHeight || window.innerHeight,
                                screenX: window.screenX,
                                screenY: window.screenY,
                                maximized: false,
                                fullscreen: !!document.fullscreenElement
                            }
                        });
                    },
                    restore: function(label = "main") {
                        return window.__TAURI__.invoke('plugin:window-state|restore', { label: label });
                    }
                };
                window.__TAURI_WINDOW_STATE__ = helper;
                if (!window.__TAURI__) window.__TAURI__ = {};
                window.__TAURI__.windowState = helper;
                window.__TAURI__.window_state = helper;
            })();
        ]],

        on_window_close = function(app, event)
            -- Auto-persist on close
            save_state(app, event.label or "main", {
                width = 960,
                height = 640,
                closedAt = os.time()
            })
        end
    }
end


pcall(function() package.loaded["tauri.plugin.window_state"] = WindowStatePlugin end)
return WindowStatePlugin
