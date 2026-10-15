local ffi = require("ffi")

-- ============================================================================
-- Platform C Declarations
-- ============================================================================
pcall(ffi.cdef, [[
int _NSGetExecutablePath(char* buf, uint32_t* bufsize);
long readlink(const char *path, char *buf, size_t bufsiz);
unsigned long GetModuleFileNameA(void* hModule, char* lpFilename, unsigned long nSize);
]])

local function get_current_executable()
    local os_name = ffi.os
    if os_name == "OSX" then
        local buf = ffi.new("char[1024]")
        local size = ffi.new("uint32_t[1]", 1024)
        if ffi.C._NSGetExecutablePath(buf, size) == 0 then
            return ffi.string(buf)
        end
    elseif os_name == "Linux" then
        local buf = ffi.new("char[1024]")
        local len = ffi.C.readlink("/proc/self/exe", buf, 1024)
        if len > 0 then
            return ffi.string(buf, len)
        end
    elseif os_name == "Windows" then
        local buf = ffi.new("char[1024]")
        local len = ffi.C.GetModuleFileNameA(nil, buf, 1024)
        if len > 0 then
            return ffi.string(buf, len)
        end
    end
    return arg and arg[0] or ""
end

-- If running inside a macOS .app bundle, return the .app directory for cleaner launch
local function get_launch_target()
    local exe = get_current_executable()
    local app_bundle = exe:match("^(.*%.app)/Contents/MacOS/.*$")
    if app_bundle then
        return app_bundle, true -- is_app_bundle
    end
    return exe, false
end

local function escape_xml(s)
    local map = {
        ["&"] = "&amp;",
        ["<"] = "&lt;",
        [">"] = "&gt;",
        ['"'] = "&quot;",
        ["'"] = "&apos;"
    }
    return (s:gsub('[&<>"\\\']', map))
end

-- ============================================================================
-- Autostart Plugin
-- ============================================================================
local AutostartPlugin = {}
AutostartPlugin.__index = AutostartPlugin

function AutostartPlugin.init(options)
    options = options or {}
    local plugin_inst = setmetatable({}, AutostartPlugin)
    plugin_inst.name = "autostart"
    plugin_inst.mac_launcher = options.mac_launcher or "LaunchAgent" -- LaunchAgent or AppleScript
    plugin_inst.app = nil

    local function get_app_meta()
        local app = plugin_inst.app
        local id = "com.tauri.lua"
        local name = "tauri-app"
        if app and app.config then
            id = app.config.identifier or (app.config.package and app.config.package.name) or id
            name = (app.config.package and app.config.package.name) or app.config.productName or name
        end
        return id, name
    end

    local function is_enabled()
        local os_name = ffi.os
        local id, name = get_app_meta()
        local home = os.getenv("HOME") or os.getenv("USERPROFILE") or "."

        if os_name == "OSX" then
            local plist_path = home .. "/Library/LaunchAgents/" .. id .. ".plist"
            local f = io.open(plist_path, "r")
            if f then
                f:close()
                return true
            end
            return false
        elseif os_name == "Linux" then
            local desktop_path = home .. "/.config/autostart/" .. id .. ".desktop"
            local f = io.open(desktop_path, "r")
            if f then
                f:close()
                return true
            end
            return false
        elseif os_name == "Windows" then
            local cmd = string.format('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "%s" >nul 2>&1', id)
            return os.execute(cmd) == 0
        end
        return false
    end

    local function enable()
        local os_name = ffi.os
        local id, name = get_app_meta()
        local target, is_bundle = get_launch_target()
        local home = os.getenv("HOME") or os.getenv("USERPROFILE") or "."

        if os_name == "OSX" then
            local launch_agents_dir = home .. "/Library/LaunchAgents"
            os.execute("mkdir -p \"" .. launch_agents_dir .. "\" 2>/dev/null")
            local plist_path = launch_agents_dir .. "/" .. id .. ".plist"

            local exec_args = ""
            if is_bundle then
                exec_args = string.format("        <string>/usr/bin/open</string>\n        <string>-a</string>\n        <string>%s</string>", escape_xml(target))
            else
                exec_args = string.format("        <string>%s</string>", escape_xml(target))
            end

            local plist_content = string.format([[<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
%s
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>]], escape_xml(id), exec_args)

            local f = io.open(plist_path, "w")
            if not f then
                error(string.format("Failed to write LaunchAgent plist at %s", plist_path))
            end
            f:write(plist_content)
            f:close()
            return true

        elseif os_name == "Linux" then
            local autostart_dir = home .. "/.config/autostart"
            os.execute("mkdir -p \"" .. autostart_dir .. "\" 2>/dev/null")
            local desktop_path = autostart_dir .. "/" .. id .. ".desktop"

            local desktop_content = string.format([[
[Desktop Entry]
Type=Application
Version=1.0
Name=%s
Exec=%s
Terminal=false
StartupNotify=false
]], name, target)

            local f = io.open(desktop_path, "w")
            if not f then
                error(string.format("Failed to write XDG autostart file at %s", desktop_path))
            end
            f:write(desktop_content)
            f:close()
            return true

        elseif os_name == "Windows" then
            local cmd = string.format('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "%s" /t REG_SZ /d "\"%s\"" /f >nul 2>&1', id, target)
            local ok = os.execute(cmd)
            return ok == 0 or ok == true
        end

        return false
    end

    local function disable()
        local os_name = ffi.os
        local id = get_app_meta()
        local home = os.getenv("HOME") or os.getenv("USERPROFILE") or "."

        if os_name == "OSX" then
            local plist_path = home .. "/Library/LaunchAgents/" .. id .. ".plist"
            os.remove(plist_path)
            return true
        elseif os_name == "Linux" then
            local desktop_path = home .. "/.config/autostart/" .. id .. ".desktop"
            os.remove(desktop_path)
            return true
        elseif os_name == "Windows" then
            local cmd = string.format('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "%s" /f >nul 2>&1', id)
            local ok = os.execute(cmd)
            return ok == 0 or ok == true
        end

        return false
    end

    return {
        name = "autostart",

        -- Direct Lua Backend API
        is_enabled = is_enabled,
        enable = enable,
        disable = disable,

        setup = function(app, self_plugin)
            plugin_inst.app = app

            app:register("plugin:autostart|is_enabled", function()
                return is_enabled()
            end)

            app:register("plugin:autostart|enable", function()
                return enable()
            end)

            app:register("plugin:autostart|disable", function()
                return disable()
            end)
        end,

        -- Injected Guest JavaScript API
        js = [[
            (function() {
                window.__TAURI_AUTOSTART__ = {
                    isEnabled: () => window.__TAURI__.invoke('plugin:autostart|is_enabled'),
                    enable: () => window.__TAURI__.invoke('plugin:autostart|enable'),
                    disable: () => window.__TAURI__.invoke('plugin:autostart|disable')
                };
                if (!window.__TAURI__) window.__TAURI__ = {};
                window.__TAURI__.autostart = window.__TAURI_AUTOSTART__;
            })();
        ]]
    }
end

return AutostartPlugin
